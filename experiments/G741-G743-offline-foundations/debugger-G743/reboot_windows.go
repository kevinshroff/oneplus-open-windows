// G743: fixed debugger restart, root-selected actual held target only.
// No interrupt, arbitrary commands, automatic retry or session termination.
package main

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

type guid struct {
	A    uint32
	B, C uint16
	D    [8]byte
}

var iidClient = guid{0x27fe5639, 0x8407, 0x4f47, [8]byte{0x83, 0x64, 0xee, 0x11, 0x8f, 0xb0, 0x8a, 0xc8}}
var iidControl = guid{0x5182e668, 0x105e, 0x416e, [8]byte{0xad, 0x92, 0x24, 0xef, 0x80, 0x04, 0x24, 0xba}}

//go:uintptrescapes
func call(obj uintptr, slot int, args ...uintptr) uint32 {
	vt := *(*uintptr)(unsafe.Pointer(obj))
	fn := *(*uintptr)(unsafe.Pointer(vt + uintptr(slot)*unsafe.Sizeof(uintptr(0))))
	r, _, _ := syscall.SyscallN(fn, append([]uintptr{obj}, args...)...)
	return uint32(r)
}
func check(where string, hr uint32) {
	fmt.Printf("%s HRESULT=0x%08x\n", where, hr)
	if int32(hr) < 0 {
		panic(where)
	}
}
func execute(ctl uintptr, text string) uint32 {
	p, e := syscall.BytePtrFromString(text)
	if e != nil {
		panic(e)
	}
	hr := call(ctl, 66, 1, uintptr(unsafe.Pointer(p)), 0) // ALL_CLIENTS, DEFAULT
	runtime.KeepAlive(p)
	return hr
}
func main() {
	if runtime.GOARCH != "amd64" || len(os.Args) != 2 {
		panic("G743 AMD64: status | reboot-held")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	dll, e := syscall.LoadDLL(`C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbgeng.dll`)
	if e != nil {
		panic(e)
	}
	defer dll.Release()
	proc, e := dll.FindProc("DebugConnect")
	if e != nil {
		panic(e)
	}
	transport, _ := syscall.BytePtrFromString("npipe:server=localhost,pipe=OpenG80")
	var client uintptr
	hr, _, _ := proc.Call(uintptr(unsafe.Pointer(transport)), uintptr(unsafe.Pointer(&iidClient)), uintptr(unsafe.Pointer(&client)))
	check("DebugConnect", uint32(hr))
	runtime.KeepAlive(transport)
	defer call(client, 2)
	var ctl uintptr
	check("QueryControl", call(client, 0, uintptr(unsafe.Pointer(&iidControl)), uintptr(unsafe.Pointer(&ctl))))
	defer call(ctl, 2)
	check("ConnectSession", call(client, 21, 1, 0)) // NO_VERSION, no history replay.

	var state uint32
	check("ExecutionStatus", call(ctl, 49, uintptr(unsafe.Pointer(&state))))
	fmt.Printf("EXECUTION_STATUS=0x%08x\n", state)
	if os.Args[1] == "status" {
		return
	}
	if os.Args[1] != "reboot-held" {
		panic("G743 fixed actions only")
	}
	if state != 6 {
		panic("G743 requires exact observed BREAK6; no interrupt selected")
	}
	// Root must first bind the pipe to the current target/boot and complete file sync.
	// Success means command dispatch only; only fresh fastboot/boot evidence proves reset.
	check("Execute G743 reboot", execute(ctl, ".echo G743_ROOT_REBOOT_DISPATCH; .reboot"))
}
