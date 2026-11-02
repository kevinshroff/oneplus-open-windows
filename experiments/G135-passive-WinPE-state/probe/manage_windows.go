// Fixed demand-driver management for this captured G134 WinPE boot only.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

type serviceStatus struct {
	Type, State, Accepted, Win32Exit, SpecificExit, CheckPoint, WaitHint uint32
}

func main() {
	r := map[string]any{"ok": false, "service_created": false, "start_submitted": false, "stop_submitted": false, "physical_access_by_manager": 0}
	defer func() {
		if e := recover(); e != nil {
			r["error"] = fmt.Sprint(e)
		}
		json.NewEncoder(os.Stdout).Encode(r)
		if r["ok"] != true {
			os.Exit(1)
		}
	}()
	must := func(e error) { if e != nil { panic(e) } }
	must(winPEGuard())
	if len(os.Args) != 2 || (os.Args[1] != "load" && os.Args[1] != "status" && os.Args[1] != "unload") {
		panic("load | status | unload")
	}
	mode := os.Args[1]
	r["action"] = mode
	base := `X:\OpenG17\payloads`
	self, e := os.Executable()
	must(e)
	if !strings.EqualFold(filepath.Dir(self), base) { panic("fixed payload directory required") }
	checkFile := func(path, digest string) {
		b, e := os.ReadFile(path); must(e)
		s := sha256.Sum256(b)
		if hex.EncodeToString(s[:]) != digest { panic("file identity: " + filepath.Base(path)) }
	}
	reader := base + `\G134-read-DSP.exe`
	checkFile(reader, "c852aa05d0485faebdb3c8635161b1cc1c0b3f7ad50bb302260e776daae92159")
	b, e := exec.Command(reader).Output(); must(e)
	var proof struct { OK bool `json:"ok"`; Report struct { Valid bool `json:"report_valid"`; Stable bool `json:"stable_double_read"`; SHA string `json:"table_sha256"` } `json:"report"` }
	must(json.Unmarshal(b, &proof))
	if !proof.OK || !proof.Report.Valid || !proof.Report.Stable || proof.Report.SHA != "ba93adddfbaf952010dcfd838630d7e99f8641b21840237d38295ce5b9a5b194" {
		panic("exact captured G134 report required")
	}
	r["G134_report_sha256"] = proof.Report.SHA
	driver := base + `\G135-signed.sys`
	checkFile(driver, "a357a234505ec3a8d3c2c55bed4de02f2847485206a874668c9a1d2f84e85ee6")
	dll := syscall.NewLazyDLL("advapi32.dll")
	openManager := dll.NewProc("OpenSCManagerW")
	openService := dll.NewProc("OpenServiceW")
	createService := dll.NewProc("CreateServiceW")
	queryService := dll.NewProc("QueryServiceStatus")
	startService := dll.NewProc("StartServiceW")
	controlService := dll.NewProc("ControlService")
	deleteService := dll.NewProc("DeleteService")
	closeHandle := dll.NewProc("CloseServiceHandle")
	access := uintptr(1)
	if mode == "load" { access |= 2 }
	manager, _, e := openManager.Call(0, 0, access)
	if manager == 0 { panic(fmt.Sprintf("OpenSCManager: %v", e)) }
	defer closeHandle.Call(manager)
	name, e := syscall.UTF16PtrFromString("OpenG135"); must(e)
	want := uintptr(4)
	if mode == "unload" { want |= 0x20 | 0x10000 }
	h, _, e := openService.Call(manager, uintptr(unsafe.Pointer(name)), want)
	if mode == "load" {
		if h != 0 { closeHandle.Call(h); panic("existing G135 service; inspect status") }
		if e != syscall.Errno(1060) { panic(fmt.Sprintf("OpenService before create: %v", e)) }
		path, e := syscall.UTF16PtrFromString(driver); must(e)
		h, _, e = createService.Call(manager, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(name)), 0x10034, 1, 3, 1, uintptr(unsafe.Pointer(path)), 0, 0, 0, 0, 0)
		if h == 0 { panic(fmt.Sprintf("CreateService: %v", e)) }
		r["service_created"] = true
		defer closeHandle.Call(h)
		r["start_submitted"] = true
		v, _, e := startService.Call(h, 0, 0)
		if v == 0 { panic(fmt.Sprintf("StartService: %v; preserve service and inspect", e)) }
	} else {
		if h == 0 {
			if mode == "status" && e == syscall.Errno(1060) { r["service_absent"] = true; r["ok"] = true; return }
			panic(fmt.Sprintf("OpenService: %v", e))
		}
		defer closeHandle.Call(h)
	}
	var status serviceStatus
	v, _, e := queryService.Call(h, uintptr(unsafe.Pointer(&status)))
	if v == 0 { panic(fmt.Sprintf("QueryServiceStatus: %v", e)) }
	r["service_status"] = status
	if mode == "unload" {
		if status.State == 4 {
			r["stop_submitted"] = true
			v, _, e = controlService.Call(h, 1, uintptr(unsafe.Pointer(&status)))
			if v == 0 { panic(fmt.Sprintf("ControlService stop: %v; inspect same instance", e)) }
		}
		if status.State != 1 { panic(fmt.Sprintf("service state %d; inspect before deletion", status.State)) }
		v, _, e = deleteService.Call(h)
		if v == 0 { panic(fmt.Sprintf("DeleteService: %v", e)) }
		r["service_deleted"] = true
	}
	if mode == "load" && status.State != 4 { panic(fmt.Sprintf("load returned state %d; inspect", status.State)) }
	r["ok"] = true
}
