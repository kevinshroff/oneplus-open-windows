// SPDX-License-Identifier: MIT
// Only a RAM-trial OPEN0063/OpenG63 devnode can be disabled or enabled.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")
var cfg = syscall.NewLazyDLL("cfgmgr32.dll")

//go:uintptrescapes
func call(p *syscall.LazyProc, args ...uintptr) (uintptr, error) {
	r, _, e := p.Call(args...)
	return r, e
}
func wide(s string) *uint16 {
	p, e := syscall.UTF16PtrFromString(s)
	if e != nil {
		panic(e)
	}
	return p
}
func winerr(label string, e error) error {
	if e == nil || e == syscall.Errno(0) {
		return errors.New(label + ": Windows call returned failure")
	}
	return fmt.Errorf("%s: %w", label, e)
}
func environment() (Environment, error) {
	e := Environment{OS: runtime.GOOS, Arch: runtime.GOARCH, CPUs: runtime.NumCPU(), SystemRoot: os.Getenv("SystemRoot")}
	version := make([]byte, 276)
	binary.LittleEndian.PutUint32(version, 276)
	r, _ := call(syscall.NewLazyDLL("ntdll.dll").NewProc("RtlGetVersion"), uintptr(unsafe.Pointer(&version[0])))
	if uint32(r) != 0 {
		return e, fmt.Errorf("RtlGetVersion status0x%x", r)
	}
	e.Build = binary.LittleEndian.Uint32(version[12:])
	n, _ := call(kernel.NewProc("GetSystemFirmwareTable"), 0x41435049, 0x54445344, 0, 0)
	e.DSDTBytes = int(n)
	if n == 0 || n > 65536 {
		return e, errors.New("firmware table size invalid")
	}
	b := make([]byte, n)
	got, _ := call(kernel.NewProc("GetSystemFirmwareTable"), 0x41435049, 0x54445344, uintptr(unsafe.Pointer(&b[0])), n)
	if got != n {
		return e, errors.New("firmware table short read")
	}
	h := sha256.Sum256(b)
	e.DSDTSHA = hex.EncodeToString(h[:])
	var key syscall.Handle
	if er := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, wide(`SYSTEM\CurrentControlSet\Control`), 0, syscall.KEY_QUERY_VALUE, &key); er != nil {
		return e, er
	}
	defer syscall.RegCloseKey(key)
	buf := make([]uint16, 2048)
	sz := uint32(len(buf) * 2)
	var typ uint32
	r, er := call(syscall.NewLazyDLL("advapi32.dll").NewProc("RegQueryValueExW"), uintptr(key), uintptr(unsafe.Pointer(wide("SystemBootDevice"))), 0, uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&sz)))
	if r != 0 || typ != 1 || sz < 2 || sz > uint32(len(buf)*2) || sz%2 != 0 {
		return e, winerr("SystemBootDevice query", er)
	}
	e.BootDevice = syscall.UTF16ToString(buf[:sz/2])
	names := make([]uint16, 2048)
	r, er = call(kernel.NewProc("QueryDosDeviceW"), uintptr(unsafe.Pointer(wide("X:"))), uintptr(unsafe.Pointer(&names[0])), uintptr(len(names)))
	if r == 0 || r > uintptr(len(names)) {
		return e, winerr("X device query", er)
	}
	e.XDevice = syscall.UTF16ToString(names[:r])
	return e, nil
}

func oneNode() (map[string]any, error) {
	var n uint32
	r, _ := call(cfg.NewProc("CM_Get_Device_ID_List_SizeW"), uintptr(unsafe.Pointer(&n)), 0, 0x100)
	if r != 0 || n < 2 || n > 65536 {
		return nil, fmt.Errorf("present device list size CR0x%x len%d", r, n)
	}
	buf := make([]uint16, n)
	r, _ = call(cfg.NewProc("CM_Get_Device_ID_ListW"), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(n), 0x100)
	if r != 0 {
		return nil, fmt.Errorf("present device list CR0x%x", r)
	}
	ids := []string{}
	at := 0
	ended := false
	for i, c := range buf {
		if c == 0 {
			if i == at {
				ended = true
				break
			}
			id := syscall.UTF16ToString(buf[at:i])
			if strings.HasPrefix(strings.ToUpper(id), hardwareID+`\`) {
				ids = append(ids, id)
			}
			at = i + 1
		}
	}
	if !ended || len(ids) != 1 {
		return nil, errors.New("need exactly one present ACPI OPEN0063 device")
	}
	var dn uint32
	r, _ = call(cfg.NewProc("CM_Locate_DevNodeW"), uintptr(unsafe.Pointer(&dn)), uintptr(unsafe.Pointer(wide(ids[0]))), 0)
	if r != 0 {
		return nil, fmt.Errorf("owned node locate CR0x%x", r)
	}
	var status, problem uint32
	r, _ = call(cfg.NewProc("CM_Get_DevNode_Status"), uintptr(unsafe.Pointer(&status)), uintptr(unsafe.Pointer(&problem)), uintptr(dn), 0)
	if r != 0 {
		return nil, fmt.Errorf("owned node status CR0x%x", r)
	}
	var typ uint32
	name := make([]uint16, 256)
	size := uint32(len(name) * 2)
	r, _ = call(cfg.NewProc("CM_Get_DevNode_Registry_PropertyW"), uintptr(dn), 5, uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&size)), 0)
	service := ""
	if r != 0 && r != 0x25 { // CR_NO_SUCH_VALUE means the unbound service property is absent.
		return nil, fmt.Errorf("owned node service query CR0x%x", r)
	}
	if r == 0 {
		if typ != 1 || size < 2 || size > uint32(len(name)*2) || size%2 != 0 {
			return nil, errors.New("owned node service property malformed")
		}
		service = syscall.UTF16ToString(name[:size/2])
	}
	return map[string]any{"devinst": dn, "instance": ids[0], "status": status, "problem": problem, "service": service, "service_query_CR": r}, nil
}

const stateDir = `X:\OpenG17\payloads`

func currentNode() (Node, uint32, error) {
	v, e := oneNode()
	if e != nil {
		return Node{}, 0, e
	}
	n := Node{v["instance"].(string), v["status"].(uint32), v["problem"].(uint32), v["service"].(string)}
	if !owner(n) {
		return n, 0, errors.New("exact OPEN0063/OpenG63 owner required")
	}
	return n, v["devinst"].(uint32), nil
}
func record(path string, v any) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	e = json.NewEncoder(f).Encode(v)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}
func path(nonce, mode, suffix string) string {
	return filepath.Join(stateDir, "G66-"+nonce+"-"+mode+suffix+".json")
}
func run(mode, nonce string) (any, error) {
	env, e := environment()
	if e != nil {
		return env, e
	}
	if e = allowedRAM(env); e != nil {
		return env, e
	}
	node, dn, e := currentNode()
	if e != nil {
		return node, e
	}
	if mode == "describe" {
		return map[string]any{"environment": env, "node": node, "raw_writes": 0}, nil
	}
	var prior *Result
	if mode == "enable" && goodToken(nonce) {
		b, er := os.ReadFile(path(nonce, "disable", "-result"))
		if er != nil {
			return nil, er
		}
		prior = &Result{}
		if er = json.Unmarshal(b, prior); er != nil {
			return nil, er
		}
	}
	if e = authorize(mode, nonce, env, node, prior); e != nil {
		return nil, e
	}
	resultPath := path(nonce, mode, "-result")
	if _, e = os.Stat(resultPath); !os.IsNotExist(e) {
		return nil, errors.New("preserve prior PnP outcome")
	}
	api, flags := "CM_Disable_DevNode", uint32(4) // Pinned cfgmgr32.h: CM_DISABLE_UI_NOT_OK, never PERSIST8.
	if mode == "enable" {
		api, flags = "CM_Enable_DevNode", 0
	}
	if e = record(path(nonce, mode, "-intent"), map[string]any{"mode": mode, "nonce": nonce, "environment": env, "before": node, "api": api, "flags": flags, "PID": os.Getpid(), "UTC": time.Now().UTC().Format(time.RFC3339Nano)}); e != nil {
		return nil, e
	}
	r, _ := call(cfg.NewProc(api), uintptr(dn), uintptr(flags))
	after, _, ae := currentNode()
	out := Result{mode, nonce, env, node, after, api, flags, uint32(r), r == 0, false}
	out.Verified = r == 0 && ae == nil && ((mode == "disable" && disabled(after)) || (mode == "enable" && started(after)))
	if e = record(resultPath, out); e != nil {
		return out, fmt.Errorf("API ran; result persistence failed, never replay: %w", e)
	}
	if !out.Verified {
		return out, fmt.Errorf("PnP outcome requires inspection: CR0x%x query%v", r, ae)
	}
	return out, nil
}
func main() {
	var v any
	var e error
	if len(os.Args) == 2 && os.Args[1] == "describe" {
		v, e = run("describe", "")
	} else if len(os.Args) == 3 {
		v, e = run(os.Args[1], os.Args[2])
	} else {
		e = errors.New("usage: describe | disable NONCE | enable NONCE")
	}
	out := map[string]any{"ok": e == nil, "result": v}
	if e != nil {
		out["error"] = e.Error()
	}
	json.NewEncoder(os.Stdout).Encode(out)
	if e != nil {
		os.Exit(1)
	}
}
