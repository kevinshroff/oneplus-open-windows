// Fixed native restart of the verified phone after the Winlogon route stalls.
// ABI reference: System Informer PHNT ntexapi.h, SHUTDOWN_ACTION/NtShutdownSystem.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")
var advapi = syscall.NewLazyDLL("advapi32.dll")

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func ptr(s string) *uint16 { p, e := syscall.UTF16PtrFromString(s); must(e); return p }
func guid(b []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint16(b[4:]), binary.LittleEndian.Uint16(b[6:]), b[8:10], b[10:16])
}
func guard() {
	if runtime.GOARCH != "arm64" || !strings.EqualFold(os.Getenv("SystemRoot"), `C:\Windows`) {
		panic("installed ARM64 Windows required")
	}
	var mini syscall.Handle
	e0 := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, ptr(`SYSTEM\CurrentControlSet\Control\MiniNT`), 0, syscall.KEY_READ, &mini)
	if e0 == nil {
		syscall.RegCloseKey(mini)
		panic("refuse PE")
	}
	if e0 != syscall.ERROR_FILE_NOT_FOUND && e0 != syscall.ERROR_PATH_NOT_FOUND {
		panic(e0)
	}
	b := make([]uint16, 32768)
	n, _, e := kernel.NewProc("QueryDosDeviceW").Call(uintptr(unsafe.Pointer(ptr("C:"))), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	if n == 0 || n > uintptr(len(b)) || !strings.HasPrefix(strings.ToLower(syscall.UTF16ToString(b[:n])), `\device\harddiskvolume`) {
		panic(fmt.Sprint("RAM identity: ", e))
	}
	h, err := syscall.CreateFile(ptr(`\\.\C:`), syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0)
	must(err)
	defer syscall.CloseHandle(h)
	raw := make([]byte, 4096)
	var got uint32
	must(syscall.DeviceIoControl(h, 0x70048, nil, 0, &raw[0], uint32(len(raw)), &got, nil))
	if got < 144 || binary.LittleEndian.Uint32(raw) != 1 || binary.LittleEndian.Uint64(raw[8:]) != 0x2208000 || binary.LittleEndian.Uint64(raw[16:]) != 0x440000000 || guid(raw[32:48]) != "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7" || guid(raw[48:64]) != "1c68511e-28af-a8c9-dd6f-e3303d568c04" {
		panic("C: target identity")
	}
}

func digest(p string) (string, int64, error) {
	f, e := os.Open(p)
	if e != nil {
		return "", 0, e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, (128<<20)+1))
	if n > 128<<20 {
		return "", n, fmt.Errorf("file size guard")
	}
	return hex.EncodeToString(h.Sum(nil)), n, e
}

type luid struct {
	Low  uint32
	High int32
}
type privileges struct {
	Count      uint32
	Luid       luid
	Attributes uint32
}

func main() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	guard()
	if len(os.Args) != 2 || (os.Args[1] != "probe" && os.Args[1] != "restart-verified-phone") {
		panic("fixed mode only")
	}
	sha, _, e := digest(`C:\OpenG81\payloads\G86-before-SMI-retry.zip`)
	must(e)
	if sha != "adc6820e44edbefa770ea7e2435282e38c3d25b8d97b1b04214f2ae791ec2124" {
		panic("fresh independent backup must exist")
	}
	var token syscall.Handle
	r, _, e := advapi.NewProc("OpenProcessToken").Call(^uintptr(0), 0x28, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		panic(e)
	}
	defer syscall.CloseHandle(token)
	wanted := privileges{Count: 1, Attributes: 2}
	var previous privileges
	var returned uint32
	r, _, e = advapi.NewProc("LookupPrivilegeValueW").Call(0, uintptr(unsafe.Pointer(ptr("SeShutdownPrivilege"))), uintptr(unsafe.Pointer(&wanted.Luid)))
	if r == 0 {
		panic(e)
	}
	kernel.NewProc("SetLastError").Call(0)
	r, _, e = advapi.NewProc("AdjustTokenPrivileges").Call(uintptr(token), 0, uintptr(unsafe.Pointer(&wanted)), unsafe.Sizeof(previous), uintptr(unsafe.Pointer(&previous)), uintptr(unsafe.Pointer(&returned)))
	last, _, _ := kernel.NewProc("GetLastError").Call()
	if r == 0 || last != 0 {
		panic(fmt.Sprintf("shutdown privilege: return=%d error=%d api=%v", r, last, e))
	}
	defer advapi.NewProc("AdjustTokenPrivileges").Call(uintptr(token), 0, uintptr(unsafe.Pointer(&previous)), 0, 0, 0)
	if os.Args[1] == "probe" {
		must(json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": "verified_phone_restart_preflight", "shutdown_privilege_enabled_for_helper_only": true, "backup_verified": true, "restart_requested": false}))
		return
	}
	f, e := os.OpenFile(`C:\OpenG81\payloads\G86-native-restart-request.json`, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(e)
	must(json.NewEncoder(f).Encode(map[string]any{"phase": "native_restart_about_to_be_requested", "api": "NtShutdownSystem", "action": "ShutdownReboot=1", "independent_backup_sha256": sha, "GPT_firmware_or_setup_edits": 0}))
	must(f.Sync())
	must(f.Close())
	status, _, e := syscall.NewLazyDLL("ntdll.dll").NewProc("NtShutdownSystem").Call(1)
	fmt.Printf("NtShutdownSystem returned NTSTATUS=0x%08x native_error=%v\n", uint32(status), e)
	if int32(status) < 0 {
		os.Exit(1)
	}
}
