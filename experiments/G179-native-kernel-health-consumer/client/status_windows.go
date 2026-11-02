package main

import (
	"fmt"
	"syscall"
)

func driverStatus() (map[string]any, error) {
	name, e := syscall.UTF16PtrFromString(`\\.\OpenG179`)
	if e != nil {
		return nil, e
	}
	h, e := syscall.CreateFile(name, syscall.GENERIC_READ, 0, nil, syscall.OPEN_EXISTING, 0, 0)
	if e != nil {
		return nil, e
	}
	defer syscall.CloseHandle(h)
	in := encodeRequest(0)
	b := make([]byte, abi.StatusSize)
	var got uint32
	e = syscall.DeviceIoControl(h, abi.Codes["status"], &in[0], uint32(len(in)), &b[0], uint32(len(b)), &got, nil)
	if e != nil {
		return nil, e
	}
	if got != uint32(len(b)) {
		return nil, fmt.Errorf("status length")
	}
	return decodeStatus(b)
}
