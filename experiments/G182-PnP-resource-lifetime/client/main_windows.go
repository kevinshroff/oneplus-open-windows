// Read-only interface query for the actual firmware-enumerated G182 PnP device.
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

type guid struct {
	A    uint32
	B, C uint16
	D    [8]byte
}

func main() {
	r := map[string]any{"ok": false, "register_accesses": 0}
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
	if len(os.Args) != 1 {
		panic("no arguments accepted")
	}
	g := guid{0x8fa58182, 0xfd04, 0x4f21, [8]byte{0x9f, 0x08, 0xa3, 0x04, 0xc1, 0xbd, 0x01, 0x82}}
	dll := syscall.NewLazyDLL("cfgmgr32.dll")
	size := dll.NewProc("CM_Get_Device_Interface_List_SizeW")
	list := dll.NewProc("CM_Get_Device_Interface_ListW")
	var n uint32
	v, _, _ := size.Call(uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&g)), 0, 0)
	if v != 0 || n < 3 || n > 4096 {
		panic(fmt.Sprintf("interface size %d/%d", v, n))
	}
	buf := make([]uint16, n)
	v, _, _ = list.Call(uintptr(unsafe.Pointer(&g)), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(n), 0)
	if v != 0 {
		panic(fmt.Sprintf("interface enumeration %d", v))
	}
	end := 0
	for end < len(buf) && buf[end] != 0 {
		end++
	}
	if end < 1 || end+1 >= len(buf) || buf[end+1] != 0 {
		panic("exactly one interface required")
	}
	path := syscall.UTF16ToString(buf[:end])
	r["interface"] = path
	p, e := syscall.UTF16PtrFromString(path)
	must(e)
	h, e := syscall.CreateFile(p, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0)
	must(e)
	in := make([]byte, 32)
	out := make([]byte, 112)
	binary.LittleEndian.PutUint32(in, 32)
	binary.LittleEndian.PutUint32(in[4:], 1)
	binary.LittleEndian.PutUint64(in[8:], 0x315352323831474f)
	var got uint32
	e = syscall.DeviceIoControl(h, 0x226c40, &in[0], 32, &out[0], 112, &got, nil)
	ce := syscall.CloseHandle(h)
	must(e)
	must(ce)
	if got != 112 {
		panic("status byte count")
	}
	u := func(o int) uint32 { return binary.LittleEndian.Uint32(out[o:]) }
	q := func(o int) uint64 { return binary.LittleEndian.Uint64(out[o:]) }
	if u(0) != 112 || u(4) != 1 || q(8) != 0x315352323831474f || u(104) != 0 || u(108) != 0 {
		panic("status framing")
	}
	r["status"] = map[string]any{"Now100ns": q(16), "D0Epoch": q(24), "PrepareEpoch": q(32), "ReleaseCalls": q(40), "MapCalls": q(48), "UnmapCalls": q(56), "KernelBuild": u(64), "Cpus": u(68), "Irql": u(72), "Prepared": u(76), "D0Active": u(80), "MapCount": u(84), "ValidationCode": u(88), "LastStatus": u(92), "FirmwareMatch": u(96), "ProducerQualified": u(100)}
	if u(64) != 26100 || u(68) != 8 || u(72) != 0 || u(76) != 1 || u(80) != 1 || u(84) != 20 || u(88) != 0 || u(92) != 0 || u(96) != 1 || u(100) != 0 || q(24) == 0 || q(32) == 0 || q(48)-q(56) != 20 {
		panic("resource-only D0 qualification failed")
	}
	r["ok"] = true
}
