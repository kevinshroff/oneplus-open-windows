// Disabled-only DbgEng processor-breakpoint parameter probe.
// Never enables a breakpoint, interrupts, resumes, executes debugger commands,
// reads/writes target memory, opens a device, or changes the debuggee.
package main

import (
	"encoding/json"
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
func need(where string, hr uint32) {
	if hr != 0 {
		panic(fmt.Sprintf("%s HRESULT=%08x", where, hr))
	}
}
func count(ctl uintptr) uint32 {
	var n uint32
	need("GetNumberBreakpoints", call(ctl, 68, uintptr(unsafe.Pointer(&n))))
	return n
}
func state(ctl uintptr) {
	var s uint32
	need("GetExecutionStatus", call(ctl, 49, uintptr(unsafe.Pointer(&s))))
	if s != 6 {
		panic("Requires already stopped live kernel; no interrupt/resume provided")
	}
}

type attempt struct {
	Size      uint32 `json:"size"`
	Result    string `json:"set_hresult"`
	Accepted  bool   `json:"metadata_accepted"`
	Matched   bool   `json:"parameters_match"`
	Reason    string `json:"reason"`
	Type      uint32 `json:"breakpoint_type"`
	Processor uint32 `json:"processor_type"`
	ReadSize  uint32 `json:"read_size"`
	Access    uint32 `json:"access"`
	Flags     uint32 `json:"flags"`
	Removed   bool   `json:"removed"`
}

func probe(ctl uintptr, size uint32) (a attempt) {
	a.Size = size
	before := count(ctl)
	var bp uintptr
	need("AddBreakpoint(DATA,ANY_ID)", call(ctl, 72, 1, 0xffffffff, uintptr(unsafe.Pointer(&bp))))
	if bp == 0 {
		panic("Null breakpoint returned")
	}
	// Remove this exact newly-created, never-enabled object on every path.
	defer func() {
		need("RemoveBreakpoint(owned disabled object)", call(ctl, 73, bp))
		a.Removed = true
		if count(ctl) != before {
			panic("Breakpoint count changed; investigate, do not arm")
		}
	}()
	need("GetFlags", call(bp, 6, uintptr(unsafe.Pointer(&a.Flags))))
	if a.Flags&4 != 0 {
		panic("Unexpected enabled breakpoint")
	}
	hr := call(bp, 13, uintptr(size), 4)
	a.Result = fmt.Sprintf("0x%08x", hr)
	need("GetType", call(bp, 4, uintptr(unsafe.Pointer(&a.Type)), uintptr(unsafe.Pointer(&a.Processor))))
	if a.Type != 1 || a.Processor != 0xaa64 {
		panic("Requires ARM64 processor breakpoint; no fallback")
	}
	if hr == 0 {
		need("GetDataParameters", call(bp, 12, uintptr(unsafe.Pointer(&a.ReadSize)), uintptr(unsafe.Pointer(&a.Access))))
		need("GetFlags after parameters", call(bp, 6, uintptr(unsafe.Pointer(&a.Flags))))
		if a.Flags&4 != 0 {
			panic("Unexpected enabled breakpoint after parameters")
		}
		a.Matched = a.ReadSize == size && a.Access == 4
		a.Accepted = a.Matched
		if a.Matched {
			a.Reason = "exact_disabled_parameter_match"
		} else {
			a.Reason = "parameter_readback_mismatch_observed"
		}
	} else {
		a.Reason = "set_parameters_rejected"
	}
	return a
}
func main() {
	if len(os.Args) == 1 {
		fmt.Println("INERT: use probe-disabled only after root qualifies current stopped ARM64 KD engine")
		return
	}
	if len(os.Args) != 2 || os.Args[1] != "probe-disabled" || runtime.GOARCH != "amd64" {
		panic("Only AMD64 host probe-disabled supported")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	dll, e := syscall.LoadDLL(`C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbgeng.dll`)
	if e != nil {
		panic(e)
	}
	defer dll.Release()
	connect, e := dll.FindProc("DebugConnect")
	if e != nil {
		panic(e)
	}
	pipe, _ := syscall.BytePtrFromString("npipe:server=localhost,pipe=OpenG80")
	var client uintptr
	hr, _, _ := connect.Call(uintptr(unsafe.Pointer(pipe)), uintptr(unsafe.Pointer(&iidClient)), uintptr(unsafe.Pointer(&client)))
	runtime.KeepAlive(pipe)
	need("DebugConnect", uint32(hr))
	defer call(client, 2)
	var ctl uintptr
	need("QueryControl", call(client, 0, uintptr(unsafe.Pointer(&iidControl)), uintptr(unsafe.Pointer(&ctl))))
	defer call(ctl, 2)
	need("ConnectSession", call(client, 21, 1, 0))
	state(ctl)
	var kind, qual, actual, effective uint32
	need("GetDebuggeeType", call(ctl, 34, uintptr(unsafe.Pointer(&kind)), uintptr(unsafe.Pointer(&qual))))
	need("GetActualProcessorType", call(ctl, 35, uintptr(unsafe.Pointer(&actual))))
	need("GetEffectiveProcessorType", call(ctl, 47, uintptr(unsafe.Pointer(&effective))))
	if kind != 1 || qual != 0 || actual != 0xaa64 || effective != 0xaa64 {
		panic("Requires live kernel ARM64 actual/effective architecture")
	}
	before := count(ctl)
	if before != 0 {
		panic("Capability probe requires empty breakpoint inventory; does not remove others")
	}
	out := []attempt{probe(ctl, 1), probe(ctl, 4)}
	state(ctl)
	if count(ctl) != before {
		panic("Unexpected breakpoint inventory after probe")
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": "g1313-disabled-hwexec-probe/2", "attempts": out, "target_memory_accesses": 0, "breakpoints_enabled": 0, "interrupts": 0, "resumes": 0, "live_execution_support_proven": false})
}
