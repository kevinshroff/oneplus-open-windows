package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
)

// The driver independently validates exact OS build, root, MiniNT and DSDT.
func targetGuard() (uint32, error) {
	if runtime.GOARCH != "arm64" || runtime.NumCPU() != 8 {
		return 0, fmt.Errorf("eight-CPU ARM64 target required")
	}
	root := os.Getenv("SystemRoot")
	if !strings.EqualFold(root, `X:\Windows`) && !strings.EqualFold(root, `C:\Windows`) {
		return 0, fmt.Errorf("unexpected system root")
	}
	p, e := syscall.UTF16PtrFromString(`SYSTEM\CurrentControlSet\Control\MiniNT`)
	if e != nil {
		return 0, e
	}
	var h syscall.Handle
	e = syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, p, 0, syscall.KEY_READ, &h)
	if e == nil {
		if e = syscall.RegCloseKey(h); e != nil {
			return 0, e
		}
		if strings.EqualFold(root, `X:\Windows`) {
			return 26100, nil
		}
		return 0, fmt.Errorf("MiniNT/root mismatch")
	}
	if e != syscall.ERROR_FILE_NOT_FOUND && e != syscall.ERROR_PATH_NOT_FOUND {
		return 0, fmt.Errorf("MiniNT query: %v", e)
	}
	if strings.EqualFold(root, `C:\Windows`) {
		return 26300, nil
	}
	return 0, fmt.Errorf("normal root mismatch")
}
