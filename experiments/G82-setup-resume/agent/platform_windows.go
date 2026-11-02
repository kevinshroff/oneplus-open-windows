package main

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/png"
	"log"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")
var currentJob uintptr

func startProcessLifetime(node string, ownerPID int) error {
	if node != "host" {
		return nil
	}
	if ownerPID <= 0 || ownerPID == os.Getpid() {
		return errors.New("host requires its owning wrapper PID")
	}
	name, _ := syscall.UTF16PtrFromString(`Local\OnePlusOpenG17HostWorker`)
	mutex, _, e := kernel.NewProc("CreateMutexW").Call(0, 0, uintptr(unsafe.Pointer(name)))
	if mutex == 0 {
		return fmt.Errorf("host instance mutex: %v", e)
	}
	if e == syscall.ERROR_ALREADY_EXISTS {
		kernel.NewProc("CloseHandle").Call(mutex)
		return errors.New("another G17 host worker already owns this instance")
	}
	owner, _, e := kernel.NewProc("OpenProcess").Call(0x100000, 0, uintptr(ownerPID)) // SYNCHRONIZE only.
	if owner == 0 {
		kernel.NewProc("CloseHandle").Call(mutex)
		return fmt.Errorf("host wrapper handle: %v", e)
	}
	r, _, e := kernel.NewProc("WaitForSingleObject").Call(owner, 0)
	if r != 258 { // WAIT_TIMEOUT means the owner is still alive.
		kernel.NewProc("CloseHandle").Call(owner)
		kernel.NewProc("CloseHandle").Call(mutex)
		return fmt.Errorf("host wrapper is not alive: wait=%x error=%v", r, e)
	}
	// Holding the mutex HANDLE makes worker ownership exclusive. Watching a real
	// process HANDLE prevents PID reuse from keeping an orphan alive. Task stop
	// may terminate PowerShell without running its finally block; exit then closes
	// our command Job Object handles, and leaves durable pending/inflight records.
	go func() {
		r, _, e := kernel.NewProc("WaitForSingleObject").Call(owner, 0xffffffff)
		log.Printf("host wrapper ended: pid=%d wait=%x error=%v; worker exiting", ownerPID, r, e)
		os.Exit(0)
	}()
	return nil
}

func prepareCommand(cmd *exec.Cmd) (func(), error) {
	h, _, e := kernel.NewProc("CreateJobObjectW").Call(0, 0)
	if h == 0 {
		return nil, fmt.Errorf("CreateJobObject: %v", e)
	}
	// JOBOBJECT_EXTENDED_LIMIT_INFORMATION, 64-bit layout. Kill child processes
	// as well as the direct child on timeout, completion, or worker termination.
	var limits [144]byte
	*(*uint32)(unsafe.Pointer(&limits[16])) = 0x2000
	r, _, e := kernel.NewProc("SetInformationJobObject").Call(h, 9, uintptr(unsafe.Pointer(&limits[0])), uintptr(len(limits)))
	if r == 0 {
		kernel.NewProc("CloseHandle").Call(h)
		return nil, fmt.Errorf("SetInformationJobObject: %v", e)
	}
	currentJob = h
	return func() { kernel.NewProc("CloseHandle").Call(h); currentJob = 0 }, nil
}
func assignCommand(cmd *exec.Cmd) error {
	h, _, e := kernel.NewProc("OpenProcess").Call(0x101, 0, uintptr(cmd.Process.Pid))
	if h == 0 {
		return fmt.Errorf("OpenProcess: %v", e)
	}
	defer kernel.NewProc("CloseHandle").Call(h)
	r, _, e := kernel.NewProc("AssignProcessToJobObject").Call(currentJob, h)
	if r == 0 {
		return fmt.Errorf("AssignProcessToJobObject: %v", e)
	}
	return nil
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
