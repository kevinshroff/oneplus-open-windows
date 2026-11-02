package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

const root = `C:\OpenG81\payloads\`

var user = syscall.NewLazyDLL("user32.dll")

type point struct{ X, Y int32 }

// Win64 INPUT: DWORD plus aligned 32-byte union; KEYBDINPUT/MOUSEINPUT
// offsets match the retained SDK WinUser.h. Every request pairs DOWN with UP.
type input struct {
	Kind uint32
	Pad  uint32
	Data [32]byte
}
type request struct {
	Action     string `json:"action"`
	ExpectHWND uint64 `json:"expect_hwnd"`
	X, Y       int32
	Keys       []string `json:"keys"`
	Text       string   `json:"text"`
	Capture    bool     `json:"capture"`
}
type state struct {
	Session       uint32 `json:"session"`
	InputDesktop  string `json:"input_desktop"`
	InputError    string `json:"input_error,omitempty"`
	Width, Height int32
	Cursor        point  `json:"cursor"`
	HWND          uint64 `json:"hwnd"`
	PID           uint32 `json:"pid"`
	Class         string `json:"class"`
	Title         string `json:"title"`
	IdleMS        uint32 `json:"idle_ms"`
}

func current() state {
	var s state
	mustBool(kernel.NewProc("ProcessIdToSessionId"), uintptr(os.Getpid()), uintptr(unsafe.Pointer(&s.Session)))
	active, _, _ := kernel.NewProc("WTSGetActiveConsoleSessionId").Call()
	if s.Session == 0 || uint32(active) != s.Session {
		panic("active console user required")
	}
	h, _, e := user.NewProc("OpenInputDesktop").Call(0, 0, 1) // DESKTOP_READOBJECTS
	if h == 0 {
		s.InputError = e.Error()
	} else {
		s.InputDesktop = objectName(user, h)
		user.NewProc("CloseDesktop").Call(h)
	}
	w, _, _ := user.NewProc("GetSystemMetrics").Call(0)
	hh, _, _ := user.NewProc("GetSystemMetrics").Call(1)
	s.Width, s.Height = int32(w), int32(hh)
	if w == 0 || hh == 0 || w > 16384 || hh > 16384 {
		panic("screen geometry")
	}
	user.NewProc("GetCursorPos").Call(uintptr(unsafe.Pointer(&s.Cursor)))
	f, _, _ := user.NewProc("GetForegroundWindow").Call()
	s.HWND = uint64(f)
	if f != 0 {
		user.NewProc("GetWindowThreadProcessId").Call(f, uintptr(unsafe.Pointer(&s.PID)))
		var b [512]uint16
		user.NewProc("GetClassNameW").Call(f, uintptr(unsafe.Pointer(&b[0])), 512)
		s.Class = syscall.UTF16ToString(b[:])
		b = [512]uint16{}
		user.NewProc("GetWindowTextW").Call(f, uintptr(unsafe.Pointer(&b[0])), 512)
		s.Title = syscall.UTF16ToString(b[:])
	}
	last := struct{ Size, Time uint32 }{Size: 8}
	if ok, _, _ := user.NewProc("GetLastInputInfo").Call(uintptr(unsafe.Pointer(&last))); ok != 0 {
		now, _, _ := kernel.NewProc("GetTickCount").Call()
		s.IdleMS = uint32(now) - last.Time
	}
	return s
}
func mustBool(p *syscall.LazyProc, a ...uintptr) {
	r, _, e := p.Call(a...)
	if r == 0 {
		panic(fmt.Sprintf("%s: %v", p.Name, e))
	}
}
func key(vk, scan uint16, flags uint32) input {
	i := input{Kind: 1}
	binary.LittleEndian.PutUint16(i.Data[0:], vk)
	binary.LittleEndian.PutUint16(i.Data[2:], scan)
	binary.LittleEndian.PutUint32(i.Data[4:], flags)
	return i
}
func mouse(x, y int32, flags uint32) input {
	i := input{}
	binary.LittleEndian.PutUint32(i.Data[0:], uint32(x))
	binary.LittleEndian.PutUint32(i.Data[4:], uint32(y))
	binary.LittleEndian.PutUint32(i.Data[12:], flags)
	return i
}
func send(events []input) int {
	if len(events) == 0 {
		return 0
	}
	n, _, e := user.NewProc("SendInput").Call(uintptr(len(events)), uintptr(unsafe.Pointer(&events[0])), unsafe.Sizeof(input{}))
	if n != uintptr(len(events)) {
		// Best-effort release only keys/buttons in this submitted transaction.
		var ups []input
		for _, i := range events {
			if i.Kind == 1 {
				flags := binary.LittleEndian.Uint32(i.Data[4:])
				if flags&2 == 0 {
					binary.LittleEndian.PutUint32(i.Data[4:], flags|2)
					ups = append(ups, i)
				}
			}
		}
		for _, i := range events {
			if i.Kind == 0 {
				f := binary.LittleEndian.Uint32(i.Data[12:])
				if f&2 != 0 {
					ups = append(ups, mouse(0, 0, 4))
				}
				if f&8 != 0 {
					ups = append(ups, mouse(0, 0, 16))
				}
			}
		}
		if len(ups) > 0 {
			user.NewProc("SendInput").Call(uintptr(len(ups)), uintptr(unsafe.Pointer(&ups[0])), unsafe.Sizeof(input{}))
		}
		panic(fmt.Sprintf("SendInput accepted %d/%d: %v", n, len(events), e))
	}
	return int(n)
}
func vk(name string) (uint16, uint32) {
	n := strings.ToUpper(name)
	if len(n) == 1 && ((n[0] >= 'A' && n[0] <= 'Z') || (n[0] >= '0' && n[0] <= '9')) {
		return uint16(n[0]), 0
	}
	m := map[string]uint16{"WIN": 0x5b, "CTRL": 0x11, "SHIFT": 0x10, "ALT": 0x12, "ENTER": 13, "ESC": 27, "TAB": 9, "SPACE": 32, "BACKSPACE": 8, "DELETE": 0x2e, "HOME": 0x24, "END": 0x23, "LEFT": 0x25, "UP": 0x26, "RIGHT": 0x27, "DOWN": 0x28, "F4": 0x73}
	k, ok := m[n]
	if !ok {
		panic("unsupported key: " + name)
	}
	var f uint32
	if k == 0x5b || k >= 0x23 && k <= 0x2e {
		f = 1
	}
	return k, f
}
func run() (result map[string]any) {
	result = map[string]any{"version": "G88-interactive-input"}
	defer func() {
		if e := recover(); e != nil {
			result["error"] = fmt.Sprint(e)
		}
	}()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	guard()
	if unsafe.Sizeof(input{}) != 40 || unsafe.Offsetof(input{}.Data) != 8 {
		panic("INPUT ABI")
	}
	if len(os.Args) != 2 {
		panic("one request basename required")
	}
	name := os.Args[1]
	result["request"] = name
	if !strings.HasPrefix(name, "G88-") || strings.ContainsAny(name, `\/:`) || !strings.HasSuffix(name, ".json") {
		panic("request filename")
	}
	data, e := os.ReadFile(root + name)
	must(e)
	if len(data) > 8192 {
		panic("request limit")
	}
	var q request
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	must(d.Decode(&q))
	if d.Decode(new(any)) != io.EOF {
		panic("one JSON request required")
	}
	user.NewProc("SetProcessDPIAware").Call()
	station, _, _ := user.NewProc("GetProcessWindowStation").Call()
	tid, _, _ := kernel.NewProc("GetCurrentThreadId").Call()
	desktop, _, _ := user.NewProc("GetThreadDesktop").Call(tid)
	if objectName(user, station) != "WinSta0" || objectName(user, desktop) != "Default" {
		panic("default user desktop required")
	}
	before := current()
	result["before"] = before
	// Never switch desktops, unlock the workstation or change authentication.
	if q.Action != "status" {
		if before.InputDesktop != "Default" {
			panic("input desktop is unavailable or secure")
		}
		if q.Action != "wake" && (q.ExpectHWND == 0 || before.HWND != q.ExpectHWND) {
			panic("foreground changed; inspect status first")
		}
		for _, v := range []uintptr{1, 2, 4, 0x10, 0x11, 0x12, 0x5b, 0x5c} {
			a, _, _ := user.NewProc("GetAsyncKeyState").Call(v)
			if a&0x8000 != 0 {
				panic("physical modifier/button is held")
			}
		}
	}
	var ev []input
	switch q.Action {
	case "status":
	case "wake":
		// A powered-off display may have no foreground window. A zero-distance
		// mouse move wakes it without clicking, typing, or changing focus.
		p, _, e := kernel.NewProc("SetThreadExecutionState").Call(0x80000003)
		if p == 0 {
			panic(fmt.Sprint("display wake request: ", e))
		}
		defer kernel.NewProc("SetThreadExecutionState").Call(0x80000000)
		ev = append(ev, mouse(0, 0, 1))
	case "move", "click", "rightclick":
		if q.X < 0 || q.Y < 0 || q.X >= before.Width || q.Y >= before.Height {
			panic("pointer outside primary screen")
		}
		x := int32((int64(q.X)*65536 + 32768) / int64(before.Width))
		y := int32((int64(q.Y)*65536 + 32768) / int64(before.Height))
		ev = append(ev, mouse(x, y, 0x8001))
		if q.Action == "click" {
			ev = append(ev, mouse(0, 0, 2), mouse(0, 0, 4))
		}
		if q.Action == "rightclick" {
			ev = append(ev, mouse(0, 0, 8), mouse(0, 0, 16))
		}
	case "keys":
		if len(q.Keys) < 1 || len(q.Keys) > 5 {
			panic("key chord size")
		}
		seen := map[uint16]bool{}
		var ups []input
		for _, name := range q.Keys {
			k, f := vk(name)
			if seen[k] {
				panic("duplicate key")
			}
			seen[k] = true
			ev = append(ev, key(k, 0, f))
			ups = append(ups, key(k, 0, f|2))
		}
		if seen[0x5b] && seen['L'] || seen[0x11] && seen[0x12] && seen[0x2e] {
			panic("lock/security chords excluded")
		}
		for i := len(ups) - 1; i >= 0; i-- {
			ev = append(ev, ups[i])
		}
	case "text":
		u := utf16.Encode([]rune(q.Text))
		if len(u) < 1 || len(u) > 1024 {
			panic("text length")
		}
		for _, c := range u {
			if c < 32 || c == 127 {
				panic("text control characters")
			}
			ev = append(ev, key(0, c, 4), key(0, c, 6))
		}
	default:
		panic("unknown action")
	}
	if q.Action != "status" {
		s := current()
		if s.InputDesktop != "Default" || (q.Action != "wake" && s.HWND != q.ExpectHWND) {
			panic("desktop/foreground changed before input")
		}
	}
	if len(ev) > 0 {
		result["events_accepted"] = send(ev)
		time.Sleep(500 * time.Millisecond)
		if q.Action == "wake" {
			time.Sleep(time.Second)
		}
	}
	result["after"] = current()
	if q.Capture {
		data, e := screenshot()
		must(e)
		must(os.WriteFile(root+"G88-current-screen.png", data, 0600))
		result["image"] = root + "G88-current-screen.png"
	}
	return
}
func main() {
	result := run()
	data, e := json.MarshalIndent(result, "", "  ")
	must(e)
	must(os.WriteFile(root+"G88-result.json", append(data, '\n'), 0600))
	if result["error"] != nil {
		os.Exit(1)
	}
}
