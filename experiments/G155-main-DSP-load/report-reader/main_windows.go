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
	"strings"
	"syscall"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")
var captured = map[string][]byte{}

func table(id uint32, limit uintptr) ([]byte, error) {
	f := kernel.NewProc("GetSystemFirmwareTable")
	n, _, e := f.Call(0x41435049, uintptr(id), 0, 0)
	if n == 0 || n > limit {
		return nil, fmt.Errorf("firmware table unavailable/size: %v", e)
	}
	b := make([]byte, n)
	got, _, e := f.Call(0x41435049, uintptr(id), uintptr(unsafe.Pointer(&b[0])), n)
	if got != n {
		return nil, fmt.Errorf("firmware table changed/read failed: %v", e)
	}
	return b, nil
}
func run() (Report, error) {
	var empty Report
	if len(os.Args) != 1 {
		return empty, fmt.Errorf("fixed read-only query takes no arguments")
	}
	dsdt, e := table(0x54445344, 4096)
	if e != nil {
		return empty, e
	}
	h := sha256.Sum256(dsdt)
	if len(dsdt) != 576 || hex.EncodeToString(h[:]) != "c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01" {
		return empty, fmt.Errorf("OnePlus Open firmware identity")
	}
	f := kernel.NewProc("EnumSystemFirmwareTables")
	n, _, e := f.Call(0x41435049, 0, 0)
	if n == 0 || n > 4096 || n%4 != 0 {
		return empty, fmt.Errorf("ACPI enumeration size: %v", e)
	}
	ids := make([]byte, n)
	got, _, e := f.Call(0x41435049, uintptr(unsafe.Pointer(&ids[0])), n)
	if got != n {
		return empty, fmt.Errorf("ACPI enumeration changed: %v", e)
	}
	errors := []string{}
	for _, item := range []struct {
		name string
		id   uint32
	}{{"OADP", 0x5044414f}, {"OSER", 0x5245534f}} {
		count := 0
		for i := 0; i < len(ids); i += 4 {
			if binary.LittleEndian.Uint32(ids[i:]) == item.id {
				count++
			}
		}
		if count != 1 {
			errors = append(errors, fmt.Sprintf("G155 %s table count %d", item.name, count))
			continue
		}
		b, e := table(item.id, 16384)
		if e != nil {
			errors = append(errors, e.Error())
			continue
		}
		again, e := table(item.id, 16384)
		if e != nil || !bytes.Equal(b, again) {
			errors = append(errors, item.name+" unstable double read")
			continue
		}
		captured[item.name] = append([]byte(nil), b...)
	}
	if len(errors) != 0 {
		return empty, fmt.Errorf("%s", strings.Join(errors, "; "))
	}
	d, e := decodeReport(captured["OADP"])
	if e != nil {
		return empty, e
	}
	s, e := decodeScmLog(captured["OSER"])
	if e != nil {
		return empty, e
	}
	d.StableDoubleRead = true
	s.StableDoubleRead = true
	return bindScmLog(d, s)
}
func main() {
	r, e := run()
	if e == nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "report": r})
		return
	}
	raw := map[string]string{}
	for name, b := range captured {
		raw[name] = base64.StdEncoding.EncodeToString(b)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": false, "error": e.Error(), "raw_tables_base64": raw})
	os.Exit(1)
}
