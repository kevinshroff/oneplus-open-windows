// Fixed-target file installer. Writes ordinary files only on the qualified ESP.
// There is no partition writer, firmware-variable writer, reboot, or fastboot API.
package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

//go:embed private/G154-FastbootOnce.efi
var helper []byte

const vol = `\\?\Volume{5982c0bf-b83f-025d-4354-68009ba0a5d1}`
const folder = vol + `\EFI\BOOT\`
const origSHA = "fae47d78487e781aa06466775cb461adeb7ff7f887fe2c15295bb2eb4f4954e1"
const origBytes = 3120648

func sum(b []byte) string        { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func u32(b []byte, o int) uint32 { return binary.LittleEndian.Uint32(b[o:]) }
func u64(b []byte, o int) uint64 { return binary.LittleEndian.Uint64(b[o:]) }
func guid(b []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", u32(b, 0), binary.LittleEndian.Uint16(b[4:]), binary.LittleEndian.Uint16(b[6:]), b[8:10], b[10:16])
}
func wide(s string) *uint16 {
	p, e := syscall.UTF16PtrFromString(s)
	if e != nil {
		panic(e)
	}
	return p
}
func check(e error) {
	if e != nil {
		panic(e)
	}
}
func read(p string, max int) []byte {
	f, e := os.Open(p)
	check(e)
	defer f.Close()
	i, e := f.Stat()
	check(e)
	if i.Size() < 0 || i.Size() > int64(max) {
		panic("bounded file size")
	}
	b := make([]byte, i.Size())
	n, e := f.ReadAt(b, 0)
	check(e)
	if n != len(b) {
		panic("short file")
	}
	return b
}
func original(p string) []byte {
	b := read(p, origBytes)
	if len(b) != origBytes || sum(b) != origSHA {
		panic("exact Windows loader identity")
	}
	return b
}
func create(p string, b []byte) {
	f, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	check(e)
	n, e := f.Write(b)
	check(e)
	if n != len(b) {
		panic("short write")
	}
	check(f.Sync())
	check(f.Close())
	if !bytes.Equal(read(p, len(b)), b) {
		panic("file readback")
	}
}
func replace(p string, b []byte) {
	tmp := folder + "G154.NEW"
	if _, e := os.Stat(tmp); !os.IsNotExist(e) {
		panic("preserve preexisting temporary file")
	}
	create(tmp, b)
	a, c := wide(tmp), wide(p)
	r, _, e := syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW").Call(uintptr(unsafe.Pointer(a)), uintptr(unsafe.Pointer(c)), 0x9)
	runtime.KeepAlive(a)
	runtime.KeepAlive(c)
	if r == 0 {
		panic(e)
	}
	if !bytes.Equal(read(p, len(b)), b) {
		panic("replacement readback")
	}
}
func guard() {
	if runtime.GOARCH != "arm64" || !strings.EqualFold(os.Getenv("SystemRoot"), `X:\Windows`) {
		panic("ARM64 WinPE only")
	}
	check(exec.Command(`X:\Windows\System32\reg.exe`, "query", `HKLM\SYSTEM\CurrentControlSet\Control\MiniNT`).Run())
	k := syscall.NewLazyDLL("kernel32.dll")
	name := wide("X:")
	d := make([]uint16, 512)
	n, _, e := k.NewProc("QueryDosDeviceW").Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&d[0])), uintptr(len(d)))
	runtime.KeepAlive(name)
	if n == 0 || !strings.HasPrefix(strings.ToLower(syscall.UTF16ToString(d)), `\device\ramdisk{`) {
		panic(fmt.Sprintf("RAM system device: %v", e))
	}
	h, e := syscall.CreateFile(wide(vol), syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0)
	check(e)
	defer syscall.CloseHandle(h)
	q := func(c uint32) []byte {
		b := make([]byte, 4096)
		var n uint32
		check(syscall.DeviceIoControl(h, c, nil, 0, &b[0], uint32(len(b)), &n, nil))
		if n > uint32(len(b)) {
			panic("IOCTL bounds")
		}
		return b[:n]
	}
	i, x := q(0x70048), q(0x560000)
	if len(i) < 144 || u32(i, 0) != 1 || u64(i, 8) != 0x4582ec000 || u64(i, 16) != 0x71bb90f000 || u32(i, 24) != 14 || guid(i[32:48]) != "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" || guid(i[48:64]) != "5982c0bf-b83f-025d-4354-68009ba0a5d1" {
		panic("ESP identity")
	}
	if len(x) < 32 || u32(x, 0) != 1 || u32(x, 8) != 0 || u64(x, 16) != 0x4582ec000 || u64(x, 24) != 0x71bb90f000 {
		panic("ESP physical extent")
	}
	root := wide(vol + `\`)
	label, fs := make([]uint16, 64), make([]uint16, 64)
	r, _, e := k.NewProc("GetVolumeInformationW").Call(uintptr(unsafe.Pointer(root)), uintptr(unsafe.Pointer(&label[0])), 64, 0, 0, 0, uintptr(unsafe.Pointer(&fs[0])), 64)
	runtime.KeepAlive(root)
	if r == 0 {
		panic(e)
	}
	if syscall.UTF16ToString(fs) != "FAT32" || syscall.UTF16ToString(label) != "OPENESP" {
		panic("OPENESP FAT32 required")
	}
}
func main() {
	if len(os.Args) != 2 || !(os.Args[1] == "inspect" || os.Args[1] == "arm" || os.Args[1] == "restore" || os.Args[1] == "receipt") {
		panic("inspect | arm | restore | receipt")
	}
	guard()
	mode := os.Args[1]
	out := map[string]any{"phase": "G154_" + mode, "helper_sha256": sum(helper), "raw_disk_writes": 0, "GPT_changes": 0, "BCD_changes": 0, "reboots": 0}
	if mode == "receipt" {
		b := read(folder+"G154.STATUS", 64)
		if len(b) != 64 || string(b[:8]) != "G154RST1" {
			panic("receipt identity")
		}
		out["receipt_phase"] = u64(b, 8)
		out["receipt_status"] = fmt.Sprintf("0x%016x", u64(b, 16))
		out["reset_image"] = fmt.Sprintf("0x%x", u64(b, 24))
		out["runtime_reset"] = fmt.Sprintf("0x%x", u64(b, 32))
		original(folder + "BOOTAA64.EFI")
		out["windows_loader_restored"] = true
	} else if mode == "inspect" {
		original(folder + "BOOTAA64.EFI")
		out["windows_loader_sha256"] = origSHA
		out["ordinary_file_writes"] = 0
	} else if mode == "arm" {
		b := original(folder + "BOOTAA64.EFI")
		backup := folder + "G154.ORIG"
		if _, e := os.Stat(backup); os.IsNotExist(e) {
			create(backup, b)
		} else {
			original(backup)
		}
		status := folder + "G154.STATUS"
		if _, e := os.Stat(status); os.IsNotExist(e) {
			create(status, make([]byte, 64))
		} else {
			v := read(status, 64)
			if len(v) != 64 || !(bytes.Equal(v, make([]byte, 64)) || string(v[:8]) == "G154RST1") {
				panic("preserve unrelated status")
			}
		}
		replace(folder+"BOOTAA64.EFI", helper)
		out["phase"] = "G154_armed_once"
		out["backup_verified"] = true
		out["windows_loader_sha256"] = origSHA
		out["next_boot"] = "Restore exact Windows loader, then one firmware bootloader-reset request; fallback to Windows on a failed guard"
	} else {
		b := original(folder + "G154.ORIG")
		cur := read(folder+"BOOTAA64.EFI", origBytes)
		if sum(cur) != sum(helper) && sum(cur) != origSHA {
			panic("preserve unexpected current loader")
		}
		if sum(cur) != origSHA {
			replace(folder+"BOOTAA64.EFI", b)
		}
		original(folder + "BOOTAA64.EFI")
		out["windows_loader_restored"] = true
	}
	check(json.NewEncoder(os.Stdout).Encode(out))
}
