package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
)

// Physical reads are available only on the exact WinPE target. The kernel
// independently checks MiniNT, SystemRoot, build, CPU count and DSDT bytes.
func winPEGuard() error {
	if runtime.GOARCH != "arm64" || runtime.NumCPU() != 8 || !strings.EqualFold(os.Getenv("SystemRoot"), `X:\Windows`) {
		return fmt.Errorf("eight-CPU ARM64 WinPE at X:\\Windows required")
	}
	p, e := syscall.UTF16PtrFromString(`SYSTEM\CurrentControlSet\Control\MiniNT`)
	if e != nil {
		return e
	}
	var mini syscall.Handle
	if e = syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, p, 0, syscall.KEY_READ, &mini); e != nil {
		return fmt.Errorf("MiniNT identity: %v", e)
	}
	return syscall.RegCloseKey(mini)
}
