package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var captured []byte

var kernel = syscall.NewLazyDLL("kernel32.dll")

func table(id uint32, limit uintptr) ([]byte, error) {
	f := kernel.NewProc("GetSystemFirmwareTable")
	n, _, last := f.Call(0x41435049, uintptr(id), 0, 0)
	if n == 0 || n > limit {
		return nil, fmt.Errorf("firmware table unavailable/size: %v", last)
	}
	b := make([]byte, n)
	got, _, last := f.Call(0x41435049, uintptr(id), uintptr(unsafe.Pointer(&b[0])), n)
	if got != n {
		return nil, fmt.Errorf("firmware table changed/failed: %v", last)
	}
	return b, nil
}

func run() (Report, error) {
	var empty Report
	if len(os.Args) != 1 {
		return empty, fmt.Errorf("fixed read-only report query takes no arguments")
	}
	dsdt, e := table(0x54445344, 4096)
	if e != nil {
		return empty, e
	}
	h := sha256.Sum256(dsdt)
	if len(dsdt) != 576 || hex.EncodeToString(h[:]) != "c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01" {
		return empty, fmt.Errorf("OnePlus Open firmware identity")
	}
	enum := kernel.NewProc("EnumSystemFirmwareTables")
	n, _, last := enum.Call(0x41435049, 0, 0)
	if n == 0 || n > 4096 || n%4 != 0 {
		return empty, fmt.Errorf("ACPI enumeration size: %v", last)
	}
	ids := make([]byte, n)
	got, _, last := enum.Call(0x41435049, uintptr(unsafe.Pointer(&ids[0])), n)
	if got != n {
		return empty, fmt.Errorf("ACPI enumeration changed/failed: %v", last)
	}
	matches := 0
	for i := 0; i < len(ids); i += 4 {
		if binary.LittleEndian.Uint32(ids[i:i+4]) == 0x5044414f {
			matches++
		}
	}
	if matches != 1 {
		return empty, fmt.Errorf("G134 report table count %d; no native preflight result established", matches)
	}
	b, e := table(0x5044414f, 8192)
	if e != nil {
		return empty, e
	}
	b2, e := table(0x5044414f, 8192)
	if e != nil || !bytes.Equal(b, b2) {
		return empty, fmt.Errorf("G134 unstable firmware report")
	}
	captured = append([]byte(nil), b...)
	r, e := decodeReport(b)
	if e == nil {
		r.StableDoubleRead = true
	}
	return r, e
}

func main() {
	r, e := run()
	if e != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": false, "error": e.Error(), "raw_table_base64": base64.StdEncoding.EncodeToString(captured)})
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "report": r})
}
