package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func main() {
	v := Environment{OS: "windows", Arch: "arm64", CPUs: 8, Build: 26100, SystemRoot: `X:\Windows`, XDevice: `\Device\Ramdisk{d9b257fc-684e-4dcb-ab79-03cfa2f6b750}`, BootDevice: "ramdisk(0)", DSDTBytes: 730, DSDTSHA: trialDSDT}
	cases := 0
	check := func(b bool) {
		cases++
		if !b {
			panic(fmt.Sprintf("G64 policy case%d", cases))
		}
	}
	check(allowedRAM(v) == nil)
	for i := 0; i < 13; i++ {
		e := v
		switch i {
		case 0:
			e.OS = "linux"
		case 1:
			e.Arch = "amd64"
		case 2:
			e.CPUs = 4
		case 3:
			e.Build = 26000
		case 4:
			e.SystemRoot = `C:\Windows`
		case 5:
			e.XDevice = `\Device\HarddiskVolume6`
		case 6:
			e.XDevice += `\PhysicalDrive0`
		case 7:
			e.XDevice = `\Device\Ramdisk{bad}`
		case 8:
			e.BootDevice = "multi(0)disk(0)rdisk(0)partition(6)"
		case 9:
			e.DSDTBytes = 576
		case 10:
			e.DSDTSHA = "c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01"
		case 11:
			e.BootDevice = "ramdisk(0) extra"
		case 12:
			e.SystemRoot = `X:\Windows\..\Windows`
		}
		check(allowedRAM(e) != nil)
	}
	e := v
	e.XDevice = strings.ToUpper(e.XDevice)
	e.SystemRoot = `x:\windows`
	e.BootDevice = " RAMDISK(0)\r\n"
	check(allowedRAM(e) == nil)
	for i := 0; i < 256; i++ {
		e = v
		e.XDevice = `\Device\HarddiskVolume6`
		if i&1 != 0 {
			e.DSDTSHA = "bad"
		}
		if i&2 != 0 {
			e.BootDevice = "ramdisk(0)"
		}
		if i&4 != 0 {
			e.SystemRoot = `X:\Windows`
		}
		if i&8 != 0 {
			e.OS = "windows"
		}
		if i&16 != 0 {
			e.Arch = "arm64"
		}
		if i&32 != 0 {
			e.CPUs = 8
		}
		if i&64 != 0 {
			e.Build = 26100
		}
		if i&128 != 0 {
			e.DSDTBytes = 730
		}
		check(allowedRAM(e) != nil)
	}
	for _, s := range []string{"0123456789abcdef0123456789abcdef", "00000000000000000000000000000000"} {
		check(goodToken(s))
	}
	for _, s := range []string{"", "0123456789abcdef0123456789abcde", "0123456789abcdef0123456789abcdef0", "0123456789abcdef0123456789abcdeF", "0123456789abcdef0123456789abcde/"} {
		check(!goodToken(s))
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"passed": true, "cases": cases, "native_operations": 0, "persistent_root_always_rejected": true})
}
