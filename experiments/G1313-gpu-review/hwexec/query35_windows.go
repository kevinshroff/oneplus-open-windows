// Fixed benign EL1 breakpoint trigger. No privileges, devices or driver loads.
// Build this file explicitly; probe_windows.go is a separate host executable.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

func main() {
	if len(os.Args) == 1 {
		fmt.Println("INERT: query35 explicitly requests one 2-byte SystemKernelDebuggerInformation query")
		return
	}
	if len(os.Args) != 2 || os.Args[1] != "query35" || runtime.GOARCH != "arm64" {
		fmt.Fprintln(os.Stderr, "Only native Windows ARM64 query35 is supported")
		os.Exit(2)
	}
	dll, err := syscall.LoadDLL("ntdll.dll")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer dll.Release()
	proc, err := dll.FindProc("NtQuerySystemInformation")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var info [2]byte
	var returned uint32
	// Exactly one invocation: class35, 2-byte SYSTEM_KERNEL_DEBUGGER_INFORMATION.
	status, _, _ := proc.Call(35, uintptr(unsafe.Pointer(&info[0])), 2, uintptr(unsafe.Pointer(&returned)))
	runtime.KeepAlive(&info)
	runtime.KeepAlive(&returned)
	raw := uint32(status)
	result := map[string]any{"schema": "g1313-query35/1", "pid": os.Getpid(), "native_calls": 1, "class": 35, "buffer_bytes": 2, "ntstatus": fmt.Sprintf("0x%08x", raw), "returned_bytes": returned, "sample_valid": raw == 0 && returned == 2}
	if raw == 0 && returned == 2 {
		result["debugger_enabled"] = info[0]
		result["debugger_not_present"] = info[1]
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
	// No retry or inferred zero-valued sample after a failing/short query.
	if raw != 0 || returned != 2 {
		os.Exit(1)
	}
}
