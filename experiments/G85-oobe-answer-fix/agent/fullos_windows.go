package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func fullGUID(b []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint16(b[4:]), binary.LittleEndian.Uint16(b[6:]), b[8:10], b[10:16])
}
func phoneGuardAndNetwork(c Config) error {
	if e := fullOSConfig(c, runtime.GOARCH, os.Getenv("SystemRoot"), os.Getenv("SystemDrive")); e != nil {
		return e
	}
	var key syscall.Handle
	p, _ := syscall.UTF16PtrFromString(`SYSTEM\CurrentControlSet\Control\MiniNT`)
	e := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, p, 0, syscall.KEY_READ, &key)
	if e == nil {
		syscall.RegCloseKey(key)
		return fmt.Errorf("full-OS worker refuses MiniNT")
	}
	if e != syscall.ERROR_FILE_NOT_FOUND && e != syscall.ERROR_PATH_NOT_FOUND {
		return fmt.Errorf("MiniNT absence not established: %v", e)
	}
	drive, _ := syscall.UTF16PtrFromString("C:")
	name := make([]uint16, 32768)
	n, _, qe := kernel.NewProc("QueryDosDeviceW").Call(uintptr(unsafe.Pointer(drive)), uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)))
	if n == 0 || n > uintptr(len(name)) {
		return fmt.Errorf("C: device query: %v", qe)
	}
	device := syscall.UTF16ToString(name[:n])
	path, _ := syscall.UTF16PtrFromString(`\\.\C:`)
	h, e := syscall.CreateFile(path, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0)
	if e != nil {
		return e
	}
	defer syscall.CloseHandle(h)
	b := make([]byte, 4096)
	var got uint32
	e = syscall.DeviceIoControl(h, 0x70048, nil, 0, &b[0], uint32(len(b)), &got, nil)
	if e != nil || got < 144 || binary.LittleEndian.Uint32(b) != 1 {
		return fmt.Errorf("C: GPT partition info: %v", e)
	}
	chars := make([]uint16, 36)
	for i := range chars {
		chars[i] = binary.LittleEndian.Uint16(b[72+i*2:])
	}
	if e = fullOSVolume(device, syscall.UTF16ToString(chars), fullGUID(b[32:48]), fullGUID(b[48:64]), binary.LittleEndian.Uint64(b[8:16]), binary.LittleEndian.Uint64(b[16:24])); e != nil {
		return e
	}
	log.Printf("Full-OS guard passed: C: is the verified super partition; MiniNT absent")
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		ifs, ie := net.Interfaces()
		if ie != nil {
			return ie
		}
		matches := []net.Interface{}
		for _, i := range ifs {
			if strings.EqualFold(i.HardwareAddr.String(), "00:00:00:00:00:00") {
				matches = append(matches, i)
			}
		}
		if len(matches) > 1 {
			return fmt.Errorf("ambiguous project USB adapter")
		}
		if len(matches) == 1 {
			i := matches[0]
			addresses, ae := i.Addrs()
			if ae == nil && fullOSUSBAddress(addresses) {
				log.Printf("Verified preconfigured USB address: adapter=%q MAC=%s addresses=%v", i.Name, i.HardwareAddr, addresses)
				return nil
			}
			out, code, ce := command(Job{Program: filepath.Join(os.Getenv("SystemRoot"), "System32", "netsh.exe"), Args: []string{"interface", "ipv4", "set", "address", "name=" + i.Name, "source=static", "address=192.0.2.10", "mask=255.255.0.0", "store=active"}, Timeout: 15})
			log.Printf("Full-OS USB static IP adapter=%q MAC=%s exit=%d output=%s", i.Name, i.HardwareAddr, code, out)
			if ce == nil {
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("verified USB adapter did not become usable within 120 seconds")
}
