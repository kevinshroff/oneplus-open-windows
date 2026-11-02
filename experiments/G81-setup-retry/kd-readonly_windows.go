// A bounded read-only client of the existing local G80 debug server.
// COM vtable slots are verified against the host's SDK 10.0.19041 DbgEng.h.
// It never ends the shared debugger session and resumes a target it interrupts.
package main

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

type guid struct {
	A    uint32
	B, C uint16
	D    [8]byte
}

var iidClient = guid{0x27fe5639, 0x8407, 0x4f47, [8]byte{0x83, 0x64, 0xee, 0x11, 0x8f, 0xb0, 0x8a, 0xc8}}
var iidControl = guid{0x5182e668, 0x105e, 0x416e, [8]byte{0xad, 0x92, 0x24, 0xef, 0x80, 0x04, 0x24, 0xba}}

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
	hr := call(ctl, 63, 1, uintptr(unsafe.Pointer(p)), 0) // ALL_CLIENTS, DEFAULT
	runtime.KeepAlive(p)
	return hr
}
func main() {
	if runtime.GOARCH != "amd64" || len(os.Args) != 1 {
		panic("fixed AMD64 read-only diagnostic only")
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
	// The legacy server blocks GetExecutionStatus while its event wait is
	// active. SetInterrupt is the documented asynchronous entry point.
	requested := true
	defer func() {
		if requested {
			fmt.Printf("RESUME_HRESULT=0x%08x\n", call(ctl, 47, 1))
		}
	}()
	if state != 6 { // DEBUG_STATUS_BREAK
		check("Interrupt", call(ctl, 4, 0)) // DEBUG_INTERRUPT_ACTIVE
		deadline := time.Now().Add(12 * time.Second)
		for time.Now().Before(deadline) {
			call(client, 28, 200)
			check("Status", call(ctl, 46, uintptr(unsafe.Pointer(&state))))
			if state == 6 {
				break
			}
		}
	}
	if state != 6 {
		panic("target did not break within diagnostic window")
	}
	for _, cmd := range []string{".echo G81_API_READ_ONLY_BEGIN", "vertarget", "du fffff78000000030 L40", ".echo G81_API_READ_ONLY_END"} {
		check("Execute "+cmd, execute(ctl, cmd))
	}
}
