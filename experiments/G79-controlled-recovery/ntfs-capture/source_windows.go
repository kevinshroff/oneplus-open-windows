package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var k32 = syscall.NewLazyDLL("kernel32.dll")

func ioctl(f *os.File, code uint32, in, out []byte) error {
	var ptr uintptr
	if len(in) > 0 {
		ptr = uintptr(unsafe.Pointer(&in[0]))
	}
	var n uint32
	r, _, e := k32.NewProc("DeviceIoControl").Call(f.Fd(), uintptr(code), ptr, uintptr(len(in)), uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)), uintptr(unsafe.Pointer(&n)), 0)
	if r == 0 {
		return fmt.Errorf("DeviceIoControl(%#x): %w", code, e)
	}
	if code == 0x7405c && n != 8 {
		return fmt.Errorf("length IOCTL size %d", n)
	}
	if code == 0x2d1400 && n < 36 {
		return fmt.Errorf("short storage descriptor: %d", n)
	}
	return nil
}
func sourceInfo(f *os.File, name string) (int64, any, error) {
	raw := rawPhysicalName(name)
	if !raw {
		s, e := f.Stat()
		if e == nil && s.Mode().IsRegular() && !strings.HasPrefix(name, string([]byte{92, 92, 46, 92})) {
			return s.Size(), map[string]any{"kind": "regular image", "length": s.Size()}, nil
		}
		return 0, nil, fmt.Errorf("only regular images or canonical PhysicalDrive paths allowed")
	}
	var e error
	stage("raw source: length IOCTL")
	b := make([]byte, 8)
	if e = ioctl(f, 0x7405c, nil, b); e != nil {
		return 0, nil, e
	}
	length := int64(binary.LittleEndian.Uint64(b))
	stage("raw source: storage descriptor IOCTL")
	d := make([]byte, 4096)
	if e = ioctl(f, 0x2d1400, make([]byte, 12), d); e != nil {
		return 0, nil, e
	}
	stage("raw source: descriptor received")
	if binary.LittleEndian.Uint32(d[28:32]) != 7 {
		return 0, nil, fmt.Errorf("raw disk must use USB bus")
	}
	field := func(off uint32) string {
		if off == 0 || int(off) >= len(d) {
			return ""
		}
		b := d[off:]
		for i, c := range b {
			if c == 0 {
				return strings.TrimSpace(string(b[:i]))
			}
		}
		return ""
	}
	vendor := field(binary.LittleEndian.Uint32(d[12:16]))
	product := field(binary.LittleEndian.Uint32(d[16:20]))
	serial := field(binary.LittleEndian.Uint32(d[24:28]))
	if !strings.EqualFold(vendor, "Qualcomm") || !strings.Contains(strings.ToLower(product), "mmc") {
		return 0, nil, fmt.Errorf("raw USB device must be Qualcomm MMC storage, got %q %q", vendor, product)
	}
	return length, map[string]any{"kind": "USB raw device", "vendor": vendor, "product": product, "serial": serial, "length": length}, nil
}
