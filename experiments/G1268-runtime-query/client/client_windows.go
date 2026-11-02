//go:build windows && arm64

// Default is status-only. No driver installation/start/stop or implicit query/retry.
//
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func main() {
	query := flag.Bool("query-once", false, "explicit fixed FAST INFO64 once request; may not return promptly")
	flag.Parse()
	if flag.NArg() != 0 {
		panic("no positional arguments")
	}
	access := uint32(syscall.GENERIC_READ)
	code := uint32(0x226880)
	var input []byte
	if *query {
		access |= syscall.GENERIC_WRITE
		code = 0x22e884
		input = make([]byte, 8)
		binary.LittleEndian.PutUint32(input, 1)
		binary.LittleEndian.PutUint32(input[4:], 0x38363231)
	}
	p, e := syscall.UTF16PtrFromString(`\\.\OpenGpuScmQueryG1268`)
	if e != nil {
		panic(e)
	}
	h, e := syscall.CreateFile(p, access, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0)
	if e != nil {
		panic(e)
	}
	defer syscall.CloseHandle(h)
	out := make([]byte, 184)
	var got uint32
	var in *byte
	if len(input) > 0 {
		in = &input[0]
	}
	e = syscall.DeviceIoControl(h, code, in, uint32(len(input)), &out[0], uint32(len(out)), &got, nil)
	if e != nil {
		fmt.Fprintln(os.Stderr, "IOCTL failed; no replay or cancellation claim:", e)
		os.Exit(1)
	}
	if got != 184 {
		panic("wrong report size")
	}
	u := func(o int) uint32 { return binary.LittleEndian.Uint32(out[o:]) }
	q := func(o int) uint64 { return binary.LittleEndian.Uint64(out[o:]) }
	if u(0) != 0x38365147 || u(4) != 1 || u(8) != 184 || u(24) > 1 {
		panic("report identity")
	}
	flags, state, capability := u(16), u(12), u(20)
	avail := "unknown"
	if state == 3 && flags&8 != 0 {
		if capability == 1 {
			avail = "unavailable"
		} else if capability == 2 {
			avail = "available"
		} else {
			panic("invalid completion capability")
		}
	} else if capability != 0 {
		panic("capability without completion")
	}
	inputs, raw := make([]string, 8), make([]string, 8)
	for i := 0; i < 8; i++ {
		inputs[i] = fmt.Sprintf("0x%016x", q(32+8*i))
		raw[i] = fmt.Sprintf("0x%016x", q(96+8*i))
	}
	if q(32) != 0xc2000601 || q(40) != 1 || q(48) != 0x02000c1b {
		panic("different query profile")
	}
	result := map[string]any{"schema": "g1268-runtime-info-report/1", "query_ioctl_requested": *query, "state": state, "flags": flags, "availability": avail, "queries_accepted": u(24), "input_registers": inputs, "last_returned_raw_x0_x7": raw, "smc_entries": q(160), "smc_returns": q(168), "interrupted_continuations": q(176), "monitor_returned": flags&4 != 0, "retained_incomplete": flags&64 != 0, "runtime_hardware_qualified": false, "setter_qualified": false, "automatic_retry": false, "host_client_pointer_bytes": unsafe.Sizeof(uintptr(0))}
	b, e := json.Marshal(result)
	if e != nil {
		panic(e)
	}
	fmt.Println(string(b))
}
