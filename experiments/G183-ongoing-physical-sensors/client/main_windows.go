// Read-only interface query for the actual firmware-enumerated G183 PnP device.
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
	if len(os.Args) != 2 {
		panic("one exclusive capture path required")
	}
	g := guid{0x8fa58183, 0xfd04, 0x4f21, [8]byte{0x9f, 0x08, 0xa3, 0x04, 0xc1, 0xbd, 0x01, 0x83}}
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
	out := make([]byte, 281104)
	binary.LittleEndian.PutUint32(in, 32)
	binary.LittleEndian.PutUint32(in[4:], 1)
	binary.LittleEndian.PutUint64(in[8:], 0x31534e333831474f)
	var got uint32
	e = syscall.DeviceIoControl(h, 0x226c80, &in[0], 32, &out[0], 281104, &got, nil)
	ce := syscall.CloseHandle(h)
	must(e)
	must(ce)
	if got != 281104 {
		panic("status byte count")
	}
	u := func(o int) uint32 { return binary.LittleEndian.Uint32(out[o:]) }
	q := func(o int) uint64 { return binary.LittleEndian.Uint64(out[o:]) }
	if u(0) != 281104 || u(4) != 1 || q(8) != 0x31534e333831474f || u(172) != 0 {
		panic("snapshot framing")
	}
	f, e := os.OpenFile(os.Args[1], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	must(e)
	written, e := f.Write(out)
	ce = f.Close()
	must(e)
	must(ce)
	if written != len(out) {
		panic("capture length")
	}
	r["capture"] = os.Args[1]
	r["bytes"] = len(out)
	status := map[string]any{}
	for i, n := range []string{"Now100ns", "Instance", "D0Epoch", "PrepareEpoch", "ReleaseCalls", "MapCalls", "UnmapCalls", "Attempts", "Completed", "ValidCount", "Ticks", "LastSequence"} {
		status[n] = q(16 + 8*i)
	}
	for i, n := range []string{"KernelBuild", "Cpus", "Irql", "FirmwareMatch", "Prepared", "D0Active", "MapCount", "Queued", "Busy", "Valid", "Fault", "Uncertain", "ValidationCode", "LastStatus", "ProducerQualified", "Reserved"} {
		status[n] = u(112 + 4*i)
	}
	r["status"] = status
	r["sample_valid"] = u(148) == 1
	r["result"] = map[string]any{"Code": u(264 + 8), "Uncertain": u(264 + 12), "Epoch": q(264 + 16), "Sequence": q(264 + 24), "Begin100ns": q(264 + 32), "End100ns": q(264 + 56), "ConfigWrites": u(264 + 68), "GaugeWrites": u(264 + 80), "PolicyCommands": u(264 + 88), "PolicyCompleted": u(264 + 92), "PolicyFault": u(264 + 96), "CancelledClean": u(264 + 100)}
	if u(148) == 1 {
		if u(152) != 0 || u(156) != 0 || u(128) != 1 || u(132) != 1 || u(136) != 20 || q(264+16) != q(32) || q(264+24) != q(104) || q(16) < q(320) || q(16)-q(320) > 300000000 {
			panic("sample lifetime")
		}
		readings := map[string]any{}
		for i, n := range []string{"VoltageMv", "TemperatureDeciK", "CurrentRaw", "Flags", "RemainingMah", "FullMah", "Percent"} {
			readings[n] = []uint32{u(176 + 8*i), u(180 + 8*i)}
		}
		for i, n := range []string{"ChargerStateFirst", "ChargerStateLast", "Enable", "FloatMv", "FastMa", "UsbType", "Mode"} {
			readings[n] = u(232 + 4*i)
		}
		r["reading"] = readings
	}
	if u(112) != 26100 || u(116) != 8 || u(120) != 0 || u(124) != 1 || u(168) != 0 {
		panic("platform/production flag")
	}
	r["ok"] = true
}
