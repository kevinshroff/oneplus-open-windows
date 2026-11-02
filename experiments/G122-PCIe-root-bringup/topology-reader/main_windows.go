// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")
var get = kernel.NewProc("GetSystemFirmwareTable")
var enumerate = kernel.NewProc("EnumSystemFirmwareTables")

const provider = 0x41435049

func query(fn *syscall.LazyProc, id uint32, limit uint32) ([]byte, error) {
	var n uintptr
	var e error
	if fn == enumerate {
		n, _, e = fn.Call(provider, 0, 0)
	} else {
		n, _, e = fn.Call(provider, uintptr(id), 0, 0)
	}
	if n == 0 || n > uintptr(limit) {
		return nil, fmt.Errorf("firmware API length %d: %v", n, e)
	}
	b := make([]byte, n)
	var got uintptr
	if fn == enumerate {
		got, _, e = fn.Call(provider, uintptr(unsafe.Pointer(&b[0])), n)
	} else {
		got, _, e = fn.Call(provider, uintptr(id), uintptr(unsafe.Pointer(&b[0])), n)
	}
	if got != n {
		return nil, fmt.Errorf("firmware API changed length %d/%d: %v", got, n, e)
	}
	return b, nil
}
func main() {
	r := map[string]any{"ok": false, "native_MMIO_accesses": 0, "files_written": 0, "drivers_loaded": 0, "scope": "Windows firmware API bytes; duplicate signatures prevent complete AML namespace capture"}
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
	if len(os.Args) != 1 || runtime.GOARCH != "arm64" || runtime.NumCPU() != 8 {
		panic("8-CPU ARM64 phone; no arguments")
	}
	r["system_root"] = os.Getenv("SystemRoot")
	r["processors"] = runtime.NumCPU()
	enum, e := query(enumerate, 0, 65536)
	must(e)
	names, counts, e := inventory(enum)
	must(e)
	r["table_ids"] = names
	r["signature_counts"] = counts
	if counts["DSDT"] > 1 {
		panic("ambiguous DSDT inventory")
	}
	dsdt, e := query(get, le.Uint32([]byte("DSDT")), 1<<20)
	must(e)
	if len(dsdt) != 576 || digest(dsdt) != dsdtSHA {
		panic("project DSDT identity differs")
	}
	var tables []map[string]any
	r["tables"] = &tables
	for _, sig := range []string{"DSDT", "SSDT", "MCFG", "IORT"} {
		if counts[sig] == 0 {
			continue
		}
		b, e := query(get, le.Uint32([]byte(sig)), 1<<20)
		must(e)
		again, e := query(get, le.Uint32([]byte(sig)), 1<<20)
		must(e)
		if !bytes.Equal(b, again) {
			panic("table changed: " + sig)
		}
		row, e := tableSummary(sig, b)
		must(e)
		row["same_signature_count"] = counts[sig]
		row["stable_double_read"] = true
		row["API_returns_only_first_same_ID"] = counts[sig] > 1
		tables = append(tables, row)
	}
	again, e := query(enumerate, 0, 65536)
	must(e)
	if !bytes.Equal(enum, again) {
		panic("enumeration changed")
	}
	unique := true
	for _, sig := range []string{"DSDT", "SSDT", "MCFG", "IORT"} {
		if counts[sig] > 1 {
			unique = false
		}
	}
	r["all_same_ID_target_tables_retrieved"] = unique
	r["complete_ACPI_namespace_verified"] = false
	r["ok"] = true
}
