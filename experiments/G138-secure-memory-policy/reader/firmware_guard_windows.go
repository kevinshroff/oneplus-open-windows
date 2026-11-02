package main

import (
	"bytes"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

func firmwareTable(id uint32, limit uintptr) ([]byte, error) {
	f := syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemFirmwareTable")
	n, _, e := f.Call(0x41435049, uintptr(id), 0, 0)
	if n == 0 || n > limit {
		return nil, fmt.Errorf("firmware table size: %v", e)
	}
	b := make([]byte, n)
	got, _, e := f.Call(0x41435049, uintptr(id), uintptr(unsafe.Pointer(&b[0])), n)
	if got != n {
		return nil, fmt.Errorf("firmware table changed/read: %v", e)
	}
	return b, nil
}
func bindCurrentFirmware() error {
	if runtime.NumCPU() != 8 {
		return fmt.Errorf("OnePlus CPU admission")
	}
	for _, t := range []struct {
		id    uint32
		bytes int
		sha   string
	}{
		{0x54445344, 576, "c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01"},
		{0x5044414f, 1780, "ba93adddfbaf952010dcfd838630d7e99f8641b21840237d38295ce5b9a5b194"},
	} {
		b, e := firmwareTable(t.id, 8192)
		if e != nil {
			return e
		}
		again, e := firmwareTable(t.id, 8192)
		if e != nil || len(b) != t.bytes || !bytes.Equal(b, again) || sum(b) != t.sha {
			return fmt.Errorf("fixed current G134 firmware admission")
		}
	}
	return nil
}
