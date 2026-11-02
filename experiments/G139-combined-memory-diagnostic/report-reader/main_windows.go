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
	"runtime"
	"syscall"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")

func query(proc *syscall.LazyProc, args []uintptr, limit uintptr) ([]byte, error) {
	n, _, e := proc.Call(args...)
	if n == 0 || n > limit {
		return nil, fmt.Errorf("firmware query size: %v", e)
	}
	b := make([]byte, n)
	args = append(args[:len(args)-2], uintptr(unsafe.Pointer(&b[0])), n)
	got, _, e := proc.Call(args...)
	if got != n {
		return nil, fmt.Errorf("firmware query changed: %v", e)
	}
	return b, nil
}
func table(id uint32, limit uintptr) ([]byte, error) {
	return query(kernel.NewProc("GetSystemFirmwareTable"), []uintptr{0x41435049, uintptr(id), 0, 0}, limit)
}
func stableTable(id uint32, limit uintptr) ([]byte, error) {
	b, e := table(id, limit)
	if e != nil {
		return nil, e
	}
	again, e := table(id, limit)
	if e != nil || !bytes.Equal(b, again) {
		return nil, fmt.Errorf("unstable ACPI table")
	}
	return b, nil
}
func run() (map[string]any, error) {
	out := map[string]any{"raw_writes": 0, "MMIO_accesses": 0, "drivers_loaded": 0}
	if len(os.Args) != 1 || runtime.NumCPU() != 8 || runtime.GOARCH != "arm64" {
		return out, fmt.Errorf("fixed OnePlus ARM64 query only")
	}
	d, e := stableTable(0x54445344, 4096)
	if e != nil {
		return out, e
	}
	h := sha256.Sum256(d)
	if len(d) != 576 || hex.EncodeToString(h[:]) != "c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01" {
		return out, fmt.Errorf("OnePlus firmware DSDT")
	}
	f := kernel.NewProc("EnumSystemFirmwareTables")
	ids, e := query(f, []uintptr{0x41435049, 0, 0}, 4096)
	if e != nil {
		return out, e
	}
	again, e := query(f, []uintptr{0x41435049, 0, 0}, 4096)
	if e != nil || !bytes.Equal(ids, again) || len(ids)%4 != 0 {
		return out, fmt.Errorf("ACPI enumeration unstable")
	}
	count := 0
	for i := 0; i < len(ids); i += 4 {
		if binary.LittleEndian.Uint32(ids[i:i+4]) == 0x4c49504f {
			count++
		}
	}
	if count != 1 {
		return out, fmt.Errorf("expected one G139 OPIL table; found %d", count)
	}
	b, e := stableTable(0x4c49504f, maxTable)
	if e != nil {
		return out, e
	}
	out["raw_table_base64"] = base64.StdEncoding.EncodeToString(b)
	digest := sha256.Sum256(b)
	out["raw_sha256"] = hex.EncodeToString(digest[:])
	report, e := decodeReport(b)
	if e != nil {
		return out, e
	}
	out["report"] = report
	return out, nil
}
func main() {
	out, e := run()
	out["ok"] = e == nil
	if e != nil {
		out["error"] = e.Error()
	}
	json.NewEncoder(os.Stdout).Encode(out)
	if e != nil {
		os.Exit(1)
	}
}
