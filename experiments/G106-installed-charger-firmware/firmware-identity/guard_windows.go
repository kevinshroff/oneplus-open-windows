package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

func fullOSGuard() error {
	if runtime.GOARCH != "arm64" || runtime.NumCPU() != 8 || !strings.EqualFold(os.Getenv("SystemRoot"), `C:\Windows`) {
		return fmt.Errorf("installed eight-CPU ARM64 Windows required")
	}
	ptr := func(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }
	var mini syscall.Handle
	e := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, ptr(`SYSTEM\CurrentControlSet\Control\MiniNT`), 0, syscall.KEY_READ, &mini)
	if e == nil {
		syscall.RegCloseKey(mini)
		return fmt.Errorf("refuse WinPE")
	}
	if e != syscall.ERROR_FILE_NOT_FOUND && e != syscall.ERROR_PATH_NOT_FOUND {
		return e
	}
	var target [32768]uint16
	n, _, e := syscall.NewLazyDLL("kernel32.dll").NewProc("QueryDosDeviceW").Call(uintptr(unsafe.Pointer(ptr("C:"))), uintptr(unsafe.Pointer(&target[0])), uintptr(len(target)))
	if n == 0 || n > uintptr(len(target)) || !strings.HasPrefix(strings.ToLower(syscall.UTF16ToString(target[:n])), `\device\harddiskvolume`) {
		return fmt.Errorf("physical C: identity: %v", e)
	}
	h, e := syscall.CreateFile(ptr(`\\.\C:`), syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0)
	if e != nil {
		return e
	}
	defer syscall.CloseHandle(h)
	b := make([]byte, 4096)
	var got uint32
	if e = syscall.DeviceIoControl(h, 0x70048, nil, 0, &b[0], uint32(len(b)), &got, nil); e != nil {
		return e
	}
	guid := func(b []byte) string {
		return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint16(b[4:]), binary.LittleEndian.Uint16(b[6:]), b[8:10], b[10:16])
	}
	if got < 144 || binary.LittleEndian.Uint32(b) != 1 || binary.LittleEndian.Uint64(b[8:]) != 0x2208000 || binary.LittleEndian.Uint64(b[16:]) != 0x440000000 || guid(b[32:48]) != "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7" || guid(b[48:64]) != "1c68511e-28af-a8c9-dd6f-e3303d568c04" {
		return fmt.Errorf("C: partition identity differs")
	}
	return nil
}
