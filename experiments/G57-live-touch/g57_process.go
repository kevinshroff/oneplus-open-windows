// SPDX-License-Identifier: MIT
// Read-only observation of one recorded process; no terminate/write access.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

func main() {
	if len(os.Args) != 2 {
		panic("recorded numeric PID required")
	}
	pid, e := strconv.ParseUint(os.Args[1], 10, 32)
	if e != nil || pid < 8 {
		panic("invalid recorded PID")
	}
	k := syscall.NewLazyDLL("kernel32.dll")
	r := map[string]any{"pid": pid, "terminate_or_write_access": false}
	h, _, err := k.NewProc("OpenProcess").Call(0x101000, 0, uintptr(pid))
	if h == 0 {
		r["open_error"] = fmt.Sprint(err)
		r["process_absent"] = err == syscall.Errno(87)
	} else {
		defer k.NewProc("CloseHandle").Call(h)
		var code uint32
		ok, _, err := k.NewProc("GetExitCodeProcess").Call(h, uintptr(unsafe.Pointer(&code)))
		r["query_ok"] = ok != 0
		r["exit_code"] = code
		if ok == 0 {
			r["query_error"] = fmt.Sprint(err)
		}
		state, _, err := k.NewProc("WaitForSingleObject").Call(h, 0)
		r["wait_state"] = state
		r["process_terminal"] = state == 0
		if state != 0 && state != 258 {
			r["wait_error"] = fmt.Sprint(err)
		}
	}
	json.NewEncoder(os.Stdout).Encode(r)
}
