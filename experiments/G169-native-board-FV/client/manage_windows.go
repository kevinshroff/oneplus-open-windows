// Fixed demand-driver management; loads only after validated per-boot G155 evidence.
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

var expectedDriver string

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
	must := func(e error) {
		if e != nil {
			panic(e)
		}
	}
	must(winPEGuard())
	if len(os.Args) != 2 || (os.Args[1] != "load" && os.Args[1] != "status" && os.Args[1] != "unload") {
		panic("load | status | unload")
	}
	mode := os.Args[1]
	r["action"] = mode
	base := `X:\OpenG17\payloads`
	self, e := os.Executable()
	must(e)
	if !strings.EqualFold(filepath.Dir(self), base) {
		panic("fixed payload directory required")
	}
	checkFile := func(path, digest string) {
		b, e := os.ReadFile(path)
		must(e)
		s := sha256.Sum256(b)
		if hex.EncodeToString(s[:]) != digest {
			panic("file identity: " + filepath.Base(path))
		}
	}
	driver := base + `\G169-signed.sys`
	if len(expectedDriver) != 64 {
		panic("driver identity not built in")
	}
	checkFile(driver, expectedDriver)
	if mode == "load" {
		reader := base + `\G155-read-DSP.exe`
		checkFile(reader, "c85e5c2d32b0d4dcdaed3d6423eed1177ca67653223e9c3698e42d6ca98236aa")
		b, e := exec.Command(reader).Output()
		must(e)
		digest, e := bootProof(b)
		must(e)
		r["G155_report_sha256"] = digest
	}
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
	if mode == "load" {
		access |= 2
	}
	manager, _, e := openManager.Call(0, 0, access)
	if manager == 0 {
		panic(fmt.Sprintf("OpenSCManager: %v", e))
	}
	defer closeHandle.Call(manager)
	name, e := syscall.UTF16PtrFromString("OpenG169")
	must(e)
	want := uintptr(4)
	if mode == "unload" {
		want |= 0x20 | 0x10000
	}
	h, _, e := openService.Call(manager, uintptr(unsafe.Pointer(name)), want)
	if mode == "load" {
		if h != 0 {
			closeHandle.Call(h)
			panic("existing G169 service; inspect status")
		}
		if e != syscall.Errno(1060) {
			panic(fmt.Sprintf("OpenService before create: %v", e))
		}
		path, e := syscall.UTF16PtrFromString(driver)
		must(e)
		h, _, e = createService.Call(manager, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(name)), 0x10034, 1, 3, 1, uintptr(unsafe.Pointer(path)), 0, 0, 0, 0, 0)
		if h == 0 {
			panic(fmt.Sprintf("CreateService: %v", e))
		}
		r["service_created"] = true
		defer closeHandle.Call(h)
		r["start_submitted"] = true
		v, _, e := startService.Call(h, 0, 0)
		if v == 0 {
			panic(fmt.Sprintf("StartService: %v; preserve service and inspect", e))
		}
	} else {
		if h == 0 {
			if mode == "status" && e == syscall.Errno(1060) {
				r["service_absent"] = true
				r["ok"] = true
				return
			}
			panic(fmt.Sprintf("OpenService: %v", e))
		}
		defer closeHandle.Call(h)
	}
	var status serviceStatus
	v, _, e := queryService.Call(h, uintptr(unsafe.Pointer(&status)))
	if v == 0 {
		panic(fmt.Sprintf("QueryServiceStatus: %v", e))
	}
	r["service_status"] = status
	if mode == "unload" {
		if status.State == 4 {
			name, e := syscall.UTF16PtrFromString(`\\.\OpenG169`)
			must(e)
			device, e := syscall.CreateFile(name, syscall.GENERIC_READ, 0, nil, syscall.OPEN_EXISTING, 0, 0)
			must(e)
			in, code, e := request("status", 0, 0)
			must(e)
			b := make([]byte, abi.Size)
			var got uint32
			e = syscall.DeviceIoControl(device, code, &in[0], uint32(len(in)), &b[0], uint32(len(b)), &got, nil)
			closeError := syscall.CloseHandle(device)
			must(e)
			must(closeError)
			if got != uint32(len(b)) {
				panic("safe unload snapshot length")
			}
			snapshot, e := decode(b)
			must(e)
			if snapshot["SafeToUnload"] != uint32(1) || snapshot["MapsLive"] != uint32(0) || snapshot["Running"] != uint32(0) {
				panic("owner not safely closed; retain current instance")
			}
			r["safe_unload_snapshot"] = snapshot
			r["stop_submitted"] = true
			v, _, e = controlService.Call(h, 1, uintptr(unsafe.Pointer(&status)))
			if v == 0 {
				panic(fmt.Sprintf("ControlService stop: %v; inspect same instance", e))
			}
		}
		if status.State != 1 {
			panic(fmt.Sprintf("service state %d; inspect before deletion", status.State))
		}
		v, _, e = deleteService.Call(h)
		if v == 0 {
			panic(fmt.Sprintf("DeleteService: %v", e))
		}
		r["service_deleted"] = true
	}
	if mode == "load" && status.State != 4 {
		panic(fmt.Sprintf("load returned state %d; inspect", status.State))
	}
	r["ok"] = true
}
