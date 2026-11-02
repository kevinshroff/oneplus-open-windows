package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/png"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const maxTransfer = 32 << 20

var kernel = syscall.NewLazyDLL("kernel32.dll")

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

func screenshot() ([]byte, error) {
	u := syscall.NewLazyDLL("user32.dll")
	g := syscall.NewLazyDLL("gdi32.dll")
	w, _, _ := u.NewProc("GetSystemMetrics").Call(0)
	h, _, _ := u.NewProc("GetSystemMetrics").Call(1)
	if w == 0 || h == 0 || w > 16384 || h > 16384 || w*h > 32<<20 {
		return nil, errors.New("invalid screen dimensions")
	}
	dc, _, e := u.NewProc("GetDC").Call(0)
	if dc == 0 {
		return nil, fmt.Errorf("GetDC: %v", e)
	}
	defer u.NewProc("ReleaseDC").Call(0, dc)
	mem, _, e := g.NewProc("CreateCompatibleDC").Call(dc)
	if mem == 0 {
		return nil, fmt.Errorf("CreateCompatibleDC: %v", e)
	}
	defer g.NewProc("DeleteDC").Call(mem)
	var info [40]byte
	*(*uint32)(unsafe.Pointer(&info[0])) = 40
	*(*int32)(unsafe.Pointer(&info[4])) = int32(w)
	*(*int32)(unsafe.Pointer(&info[8])) = -int32(h)
	*(*uint16)(unsafe.Pointer(&info[12])) = 1
	*(*uint16)(unsafe.Pointer(&info[14])) = 32
	var bits uintptr
	bmp, _, e := g.NewProc("CreateDIBSection").Call(dc, uintptr(unsafe.Pointer(&info[0])), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if bmp == 0 || bits == 0 {
		return nil, fmt.Errorf("CreateDIBSection: %v", e)
	}
	defer g.NewProc("DeleteObject").Call(bmp)
	old, _, _ := g.NewProc("SelectObject").Call(mem, bmp)
	defer g.NewProc("SelectObject").Call(mem, old)
	ok, _, e := g.NewProc("BitBlt").Call(mem, 0, 0, w, h, dc, 0, 0, 0x40cc0020)
	if ok == 0 {
		return nil, fmt.Errorf("BitBlt: %v", e)
	}
	source := unsafe.Slice((*byte)(unsafe.Pointer(bits)), int(w*h*4))
	im := image.NewRGBA(image.Rect(0, 0, int(w), int(h)))
	for i := 0; i < len(source); i += 4 {
		im.Pix[i] = source[i+2]
		im.Pix[i+1] = source[i+1]
		im.Pix[i+2] = source[i]
		im.Pix[i+3] = 255
	}
	var b bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestSpeed}
	err := enc.Encode(&b, im)
	if b.Len() > maxTransfer {
		return nil, errors.New("screenshot exceeds transfer limit")
	}
	return b.Bytes(), err
}

func objectName(u *syscall.LazyDLL, handle uintptr) string {
	var needed uint32
	var data [512]uint16
	ok, _, e := u.NewProc("GetUserObjectInformationW").Call(handle, 2, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)*2), uintptr(unsafe.Pointer(&needed)))
	if ok == 0 || needed > uint32(len(data)*2) {
		panic(fmt.Sprint("desktop object name: ", e))
	}
	return syscall.UTF16ToString(data[:])
}
