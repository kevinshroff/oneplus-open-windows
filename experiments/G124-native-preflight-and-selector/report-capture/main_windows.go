package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")

func readTable(id uint32, limit uintptr) ([]byte, error) {
	f := kernel.NewProc("GetSystemFirmwareTable")
	n, _, e := f.Call(0x41435049, uintptr(id), 0, 0)
	if n == 0 || n > limit {
		return nil, fmt.Errorf("table size %d: %v", n, e)
	}
	b := make([]byte, n)
	got, _, e := f.Call(0x41435049, uintptr(id), uintptr(unsafe.Pointer(&b[0])), n)
	if got != n {
		return nil, fmt.Errorf("table length changed %d/%d: %v", got, n, e)
	}
	return b, nil
}

func capture() (map[string]any, error) {
	if len(os.Args) != 1 || runtime.GOARCH != "arm64" || runtime.NumCPU() != 8 {
		return nil, fmt.Errorf("fixed no-argument 8-CPU ARM64 phone query")
	}
	dsdt, err := readTable(0x54445344, 4096)
	if err != nil {
		return nil, err
	}
	dh := sha256.Sum256(dsdt)
	if len(dsdt) != 576 || hex.EncodeToString(dh[:]) != "c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01" {
		return nil, fmt.Errorf("project DSDT identity")
	}
	f := kernel.NewProc("EnumSystemFirmwareTables")
	n, _, e := f.Call(0x41435049, 0, 0)
	if n == 0 || n > 65536 || n%4 != 0 {
		return nil, fmt.Errorf("ACPI inventory size: %v", e)
	}
	ids := make([]byte, n)
	got, _, e := f.Call(0x41435049, uintptr(unsafe.Pointer(&ids[0])), n)
	if got != n {
		return nil, fmt.Errorf("ACPI inventory changed: %v", e)
	}
	count := 0
	for i := 0; i < len(ids); i += 4 {
		if binary.LittleEndian.Uint32(ids[i:i+4]) == 0x4650414f {
			count++
		}
	}
	if count != 1 {
		return nil, fmt.Errorf("OAPF count %d", count)
	}
	b, err := readTable(0x4650414f, 24*1024+36)
	if err != nil {
		return nil, err
	}
	again, err := readTable(0x4650414f, 24*1024+36)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(b, again) || len(b) < 36 || string(b[:4]) != "OAPF" || int(binary.LittleEndian.Uint32(b[4:8])) != len(b) || b[8] != 1 || string(b[10:16]) != "OPEN  " || string(b[16:24]) != "G119PFLT" || binary.LittleEndian.Uint32(b[24:28]) != 119 || string(b[28:32]) != "OPEN" || binary.LittleEndian.Uint32(b[32:36]) != 1 {
		return nil, fmt.Errorf("unstable table or G119 header identity")
	}
	var sum byte
	for _, v := range b {
		sum += v
	}
	if sum != 0 {
		return nil, fmt.Errorf("OAPF checksum")
	}
	h := sha256.Sum256(b)
	return map[string]any{"ok": true, "system_root": os.Getenv("SystemRoot"), "bytes": len(b), "sha256": hex.EncodeToString(h[:]), "raw_base64": b, "stable_double_read": true, "header_and_checksum_valid": true, "MMIO_accesses": 0, "drivers_loaded": 0, "files_written": 0}, nil
}

func main() {
	r, err := capture()
	if err != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": false, "error": err.Error()})
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(r)
}
