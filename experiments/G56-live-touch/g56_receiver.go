// SPDX-License-Identifier: MIT
// An owned, finite Win32 receiver for consumer-visible G56 pointer evidence.
// Coordinates one finite owned-window test and the fixed guarded live helper.
// No arbitrary input, controller access or detached process lifetime is exposed.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var u = syscall.NewLazyDLL("user32.dll")
var k = syscall.NewLazyDLL("kernel32.dll")

const className = "OpenG56PointerReceiver"

type Point struct{ X, Y int32 }
type PointerInfo struct {
	Type, ID, Frame, Flags                 uint32
	Source, Target                         uintptr
	Pixel, Himetric, RawPixel, RawHimetric Point
	Time, History                          uint32
	Input                                  int32
	Keys                                   uint32
	Performance                            uint64
	Button, Padding                        uint32
}
type WndClass struct {
	Size, Style                        uint32
	Proc                               uintptr
	ClassExtra, WindowExtra            int32
	Instance, Icon, Cursor, Background uintptr
	Menu, Name                         *uint16
	SmallIcon                          uintptr
}
type Message struct {
	Window         uintptr
	ID             uint32
	WParam, LParam uintptr
	Time           uint32
	Position       Point
	Private        uint32
}

// These are Windows ARM64 layouts from the documented Win32 declarations.
var _ [96 - int(unsafe.Sizeof(PointerInfo{}))]byte
var _ [int(unsafe.Sizeof(PointerInfo{})) - 96]byte
var _ [80 - int(unsafe.Sizeof(WndClass{}))]byte
var _ [int(unsafe.Sizeof(WndClass{})) - 80]byte
var _ [48 - int(unsafe.Sizeof(Message{}))]byte
var _ [int(unsafe.Sizeof(Message{})) - 48]byte
var _ [48 - int(unsafe.Offsetof(PointerInfo{}.RawPixel))]byte
var _ [int(unsafe.Offsetof(PointerInfo{}.RawPixel)) - 48]byte

type Ready struct {
	Token                string
	PID                  uint32
	Window               uintptr
	Tick                 uint64
	Class, Title         string
	Width, Height        int32
	Foreground, DPIAware bool
}

var tokenPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

func wide(s string) *uint16 {
	p, e := syscall.UTF16PtrFromString(s)
	if e != nil {
		panic(e)
	}
	return p
}
func tick() uint64 { r, _, _ := k.NewProc("GetTickCount64").Call(); return uint64(r) }
func windowText(proc string, h uintptr) string {
	var b [256]uint16
	n, _, _ := u.NewProc(proc).Call(h, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	if n >= uintptr(len(b)) {
		return ""
	}
	return syscall.UTF16ToString(b[:n])
}
func createJSON(path string, v any) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = json.NewEncoder(f).Encode(v); e != nil {
		return e
	}
	return f.Sync()
}
func paths(dir, token string) (string, error) {
	if !tokenPattern.MatchString(token) || !filepath.IsAbs(dir) {
		return "", errors.New("absolute project directory and 32 hex token required")
	}
	return filepath.Join(dir, "G56-receiver-"+token), nil
}
func check(path string) (Ready, error) {
	var r Ready
	b, e := os.ReadFile(path)
	if e != nil {
		return r, e
	}
	if e = json.Unmarshal(b, &r); e != nil {
		return r, e
	}
	if !tokenPattern.MatchString(r.Token) || r.Class != className || r.Title != "G56 pointer receiver "+r.Token || r.Window == 0 || r.PID == 0 {
		return r, errors.New("invalid receiver identity")
	}
	now := tick()
	if now < r.Tick || now-r.Tick > 30000 {
		return r, errors.New("receiver readiness expired")
	}
	valid, _, _ := u.NewProc("IsWindow").Call(r.Window)
	var pid uint32
	u.NewProc("GetWindowThreadProcessId").Call(r.Window, uintptr(unsafe.Pointer(&pid)))
	fg, _, _ := u.NewProc("GetForegroundWindow").Call()
	if valid == 0 || pid != r.PID || fg != r.Window || windowText("GetClassNameW", r.Window) != r.Class || windowText("GetWindowTextW", r.Window) != r.Title {
		return r, errors.New("owned receiver is not the foreground window")
	}
	var rectangle struct{ Left, Top, Right, Bottom int32 }
	ok, _, _ := u.NewProc("GetWindowRect").Call(r.Window, uintptr(unsafe.Pointer(&rectangle)))
	if ok == 0 || rectangle.Left != 0 || rectangle.Top != 0 || rectangle.Right != r.Width || rectangle.Bottom != r.Height {
		return r, errors.New("owned receiver must cover the full display")
	}
	r.Foreground = true
	return r, nil
}
func worker(dir, token, mode, adminPath, adminSHA string) error {
	if mode != "selftest" && mode != "live" {
		return errors.New("unknown bounded receiver mode")
	}
	if mode == "live" {
		if !strings.EqualFold(filepath.Clean(adminPath), filepath.Join(dir, "G56-admin.exe")) {
			return errors.New("only the owned project admin helper is permitted")
		}
		b, e := os.ReadFile(adminPath)
		if e != nil {
			return e
		}
		h := sha256.Sum256(b)
		if hex.EncodeToString(h[:]) != adminSHA {
			return errors.New("admin helper hash mismatch")
		}
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	base, e := paths(dir, token)
	if e != nil {
		return e
	}
	log, e := os.OpenFile(base+"-events.jsonl", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer log.Close()
	enc := json.NewEncoder(log)
	events, dropped := 0, 0
	write := func(v any) {
		if events < 1024 {
			enc.Encode(v)
			log.Sync()
			events++
		} else {
			dropped++
		}
	}
	aware := false
	if p := u.NewProc("SetProcessDpiAwarenessContext"); p.Find() == nil {
		r, _, _ := p.Call(^uintptr(3))
		aware = r != 0
	}
	if !aware {
		r, _, _ := u.NewProc("SetProcessDPIAware").Call()
		aware = r != 0
	}
	if e = u.NewProc("GetPointerInfoHistory").Find(); e != nil {
		return e
	}
	if e = u.NewProc("GetPointerInfo").Find(); e != nil {
		return e
	}
	var hwnd uintptr
	callback := syscall.NewCallback(func(h uintptr, msg uint32, wp, lp uintptr) uintptr {
		switch msg {
		case 0x245, 0x246, 0x247, 0x249, 0x24a, 0x24c: // update/down/up/enter/leave/capture changed
			var p PointerInfo
			ok, _, pe := u.NewProc("GetPointerInfo").Call(wp&65535, uintptr(unsafe.Pointer(&p)))
			row := map[string]any{"message": fmt.Sprintf("0x%x", msg), "pointer_id_wparam": uint32(wp & 65535), "lparam_xy": Point{int32(int16(lp & 65535)), int32(int16((lp >> 16) & 65535))}, "tick": tick(), "GetPointerInfo_ok": ok != 0, "window": h}
			if ok != 0 {
				row["pointer"] = p
				if p.History > 1 {
					count := p.History
					if count > 256 {
						count = 256
					}
					history := make([]PointerInfo, count)
					available := count
					ok, _, err := u.NewProc("GetPointerInfoHistory").Call(wp&65535, uintptr(unsafe.Pointer(&available)), uintptr(unsafe.Pointer(&history[0])))
					if ok != 0 {
						copied := available
						if copied > count {
							copied = count
						}
						row["history"] = history[:copied]
						row["history_available"] = available
						row["history_truncated"] = available > count
					} else {
						row["history_error"] = err.Error()
					}
				}
				if p.Source != 0 {
					var n uint32
					result, _, err := u.NewProc("GetRawInputDeviceInfoW").Call(p.Source, 0x20000007, 0, uintptr(unsafe.Pointer(&n)))
					if uint32(result) != 0xffffffff && n > 0 && n < 32768 {
						b := make([]uint16, n+1)
						capacity := n + 1
						result, _, err = u.NewProc("GetRawInputDeviceInfoW").Call(p.Source, 0x20000007, uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&capacity)))
						if uint32(result) != 0xffffffff {
							row["source_device_name"] = syscall.UTF16ToString(b)
						} else {
							row["source_device_name_error"] = err.Error()
						}
					} else {
						row["source_device_name_error"] = err.Error()
					}
				}
			} else {
				row["error"] = pe.Error()
			}
			write(row)
			return 0
		case 0x201, 0x202, 0x203, 0x204, 0x205, 0x206: // consume promoted button input
			write(map[string]any{"message": fmt.Sprintf("0x%x", msg), "tick": tick(), "promoted_button": true})
			return 0
		case 0x10:
			u.NewProc("DestroyWindow").Call(h)
			return 0
		case 2:
			u.NewProc("PostQuitMessage").Call(0)
			return 0
		}
		r, _, _ := u.NewProc("DefWindowProcW").Call(h, uintptr(msg), wp, lp)
		return r
	})
	instance, _, _ := k.NewProc("GetModuleHandleW").Call(0)
	name := wide(className)
	wc := WndClass{Size: uint32(unsafe.Sizeof(WndClass{})), Proc: callback, Instance: instance, Background: 6, Name: name}
	atom, _, we := u.NewProc("RegisterClassExW").Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		return fmt.Errorf("RegisterClassExW: %v", we)
	}
	width, _, _ := u.NewProc("GetSystemMetrics").Call(0)
	height, _, _ := u.NewProc("GetSystemMetrics").Call(1)
	if width < 100 || height < 100 || width > 10000 || height > 10000 {
		return errors.New("unexpected display dimensions")
	}
	title := "G56 pointer receiver " + token
	caption := wide(title)
	hwnd, _, we = u.NewProc("CreateWindowExW").Call(8, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(caption)), 0x90000000, 0, 0, width, height, 0, 0, instance, 0)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowExW: %v", we)
	}
	u.NewProc("ShowWindow").Call(hwnd, 5)
	u.NewProc("SetForegroundWindow").Call(hwnd)
	u.NewProc("UpdateWindow").Call(hwnd)
	fg, _, _ := u.NewProc("GetForegroundWindow").Call()
	r := Ready{Token: token, PID: uint32(os.Getpid()), Window: hwnd, Tick: tick(), Class: className, Title: title, Width: int32(width), Height: int32(height), Foreground: fg == hwnd, DPIAware: aware}
	if e = createJSON(base+"-ready.json", r); e != nil {
		u.NewProc("DestroyWindow").Call(hwnd)
		return e
	}
	// The entire receiver remains within the controller's finite command Job.
	// No detached child is expected to survive a completed G17 command.
	lifetime := 5 * time.Second
	if mode == "live" {
		lifetime = 12 * time.Second
	}
	go func(h uintptr) { time.Sleep(lifetime); u.NewProc("PostMessageW").Call(h, 0x10, 0, 0) }(hwnd)
	positive, guardError := check(base + "-ready.json")
	if guardError != nil || !positive.DPIAware {
		u.NewProc("DestroyWindow").Call(hwnd)
		return fmt.Errorf("receiver foreground/DPI guard: %v", guardError)
	}
	qualification := map[string]any{"owned_foreground_verified": true, "DPI_aware": positive.DPIAware, "mode": mode}
	if mode == "selftest" {
		fake := r
		fake.PID++
		fakePath := base + "-wrong-pid.json"
		if e = createJSON(fakePath, fake); e != nil {
			return e
		}
		_, bad := check(fakePath)
		if bad == nil {
			return errors.New("wrong PID unexpectedly passed ownership guard")
		}
		qualification["wrong_PID_refused"] = bad.Error()
	}
	if e = createJSON(base+"-qualification.json", qualification); e != nil {
		return e
	}
	type childResult struct {
		Started       bool
		Output, Error string
		ExitCode      int
	}
	result := make(chan childResult, 1)
	if mode == "live" {
		go func() {
			time.Sleep(100 * time.Millisecond)
			if _, e := check(base + "-ready.json"); e != nil {
				result <- childResult{Error: e.Error(), ExitCode: -1}
				return
			}
			cmd := exec.Command(adminPath, "live", base+"-ready.json", base+"-power.bin")
			cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
			b, e := cmd.CombinedOutput()
			v := childResult{Started: cmd.Process != nil, Output: string(b), ExitCode: -1}
			if cmd.ProcessState != nil {
				v.ExitCode = cmd.ProcessState.ExitCode()
			}
			if e != nil {
				v.Error = e.Error()
			}
			result <- v
		}()
	}

	for {
		var m Message
		n, _, ge := u.NewProc("GetMessageW").Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(n) == -1 {
			return fmt.Errorf("GetMessageW: %v", ge)
		}
		if n == 0 {
			break
		}
		u.NewProc("TranslateMessage").Call(uintptr(unsafe.Pointer(&m)))
		u.NewProc("DispatchMessageW").Call(uintptr(unsafe.Pointer(&m)))
	}
	runtime.KeepAlive(name)
	runtime.KeepAlive(caption)
	runtime.KeepAlive(callback)
	summary := map[string]any{"token": token, "mode": mode, "events": events, "dropped": dropped, "tick": tick(), "window_closed": true}
	if mode == "selftest" {
		summary["driver_requests_submitted"] = 0
	} else {
		select {
		case child := <-result:
			summary["admin"] = child
		case <-time.After(2 * time.Second):
			summary["admin"] = childResult{Error: "admin job did not finish; observe existing native lifetime state before further input", ExitCode: -1}
		}
	}
	if e = createJSON(base+"-done.json", summary); e != nil {
		return e
	}
	if mode == "live" {
		child := summary["admin"].(childResult)
		if child.Error != "" || child.ExitCode != 0 {
			return fmt.Errorf("owned admin result: exit%d error%s", child.ExitCode, child.Error)
		}
	}
	return nil
}
func run() (any, error) {
	if runtime.GOOS != "windows" || runtime.GOARCH != "arm64" {
		return nil, errors.New("Windows ARM64 required")
	}
	if len(os.Args) == 3 && os.Args[1] == "check" {
		return check(os.Args[2])
	}
	if len(os.Args) == 4 && os.Args[1] == "selftest" {
		e := worker(os.Args[2], os.Args[3], "selftest", "", "")
		return map[string]any{"finished": e == nil, "mode": "selftest"}, e
	}
	if len(os.Args) == 6 && os.Args[1] == "live" {
		e := worker(os.Args[2], os.Args[3], "live", os.Args[4], os.Args[5])
		return map[string]any{"finished": e == nil, "mode": "live"}, e
	}
	return nil, errors.New("usage: selftest <project directory> <32 hex token>; live <directory> <token> <owned admin path> <sha256>; check <ready file>")
}
func main() {
	v, e := run()
	out := map[string]any{"ok": e == nil, "result": v}
	if e != nil {
		out["error"] = e.Error()
	}
	json.NewEncoder(os.Stdout).Encode(out)
	if e != nil {
		os.Exit(1)
	}
}
