package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func dosDevice(drive string) (string, error) {
	p, e := syscall.UTF16PtrFromString(drive)
	if e != nil {
		return "", e
	}
	b := make([]uint16, 32768)
	n, _, e := syscall.NewLazyDLL("kernel32.dll").NewProc("QueryDosDeviceW").Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	if n == 0 || n > uintptr(len(b)) {
		return "", fmt.Errorf("QueryDosDevice: %v", e)
	}
	return syscall.UTF16ToString(b[:n]), nil
}
func requireRAM() (string, string, error) {
	x, e := dosDevice("X:")
	if e != nil {
		return "", "", e
	}
	if !validRAMDevice(x) {
		return x, "", fmt.Errorf("refusing volume exclusion: system X: is not the captured RAM-device form")
	}
	b, e := exec.Command(`X:\Windows\System32\reg.exe`, "query", `HKLM\SYSTEM\CurrentControlSet\Control`, "/v", "SystemBootDevice").CombinedOutput()
	if e != nil || !strings.Contains(strings.ToLower(string(b)), "ramdisk(0)") {
		return x, string(b), fmt.Errorf("independent SystemBootDevice RAM guard: %v", e)
	}
	return x, string(b), nil
}
func volumeOpen(drive string, write bool) (*os.File, error) {
	p, e := syscall.UTF16PtrFromString(`\\.\` + drive)
	if e != nil {
		return nil, e
	}
	a := uint32(syscall.GENERIC_READ)
	if write {
		a |= syscall.GENERIC_WRITE
	}
	h, e := syscall.CreateFile(p, a, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(h), drive), nil
}
func matchingVolume(f *os.File, d *Opened) error {
	i, e := ioctl(f, 0x70048, 144)
	if e != nil {
		return e
	}
	x, e := ioctl(f, 0x560000, 4096)
	if e != nil {
		return e
	}
	return verifySuperVolume(i, x, d.Target, d.Index, d.Partition)
}
func findSuperDrive(d *Opened) (string, error) {
	matches := []string{}
	for letter := 'A'; letter <= 'Z'; letter++ {
		drive := string(letter) + ":"
		if drive == "X:" {
			continue
		}
		device, e := dosDevice(drive)
		if e != nil || !strings.HasPrefix(strings.ToLower(device), `\device\harddiskvolume`) {
			continue
		}
		f, e := volumeOpen(drive, false)
		if e != nil {
			continue
		}
		e = matchingVolume(f, d)
		f.Close()
		if e == nil {
			matches = append(matches, drive)
		}
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("need exactly one matched super volume, found %d", len(matches))
	}
	return matches[0], nil
}
func volumeControl(f *os.File, code uint32) error {
	var n uint32
	return syscall.DeviceIoControl(syscall.Handle(f.Fd()), code, nil, 0, nil, 0, &n, nil)
}
func leaseJournal(path string, r map[string]any) error {
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return e
	}
	tmp := path + ".new"
	f, e := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(tmp, path)
}

// Lock and dismount only the matched super filesystem. There is no raw write.
// A process exit closes the locking handle and releases the lock automatically.
func probeSuperExclusion(path string) (err error) {
	x, boot, e := requireRAM()
	if e != nil {
		return e
	}
	if e = pathGuard(path); e != nil {
		return e
	}
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		return fmt.Errorf("preserve existing lease journal")
	}
	release, e := writerMutex()
	if e != nil {
		return e
	}
	defer release()
	d, e := discover(targets["super"])
	if e != nil {
		return e
	}
	defer d.f.Close()
	drive, e := findSuperDrive(d)
	if e != nil {
		return e
	}
	wim := drive + `\OpenG18\G18-maintenance.wim`
	const expectedWim = "1db2c5d735281ddcb11f1723bb729753e81a74793a495a83c0bece2ffd26d7e9"
	before, n, e := fileHash(wim)
	if e != nil || n != 644359648 || before != expectedWim {
		return fmt.Errorf("source WIM preflight guard: %v", e)
	}
	r := map[string]any{"version": "G18-super-exclusion-r3", "phase": "preflight", "x_device": x, "SystemBootDevice": boot, "source_drive": drive, "source_target": d.Target, "disk_index": d.Index, "partition_number": d.Partition, "gpt_header_sha256": d.HeaderSHA, "gpt_array_sha256": d.ArraySHA, "before_wim_sha256": before, "raw_writes": 0, "filesystem_flush_may_occur": true, "journal": path}
	if e = leaseJournal(path, r); e != nil {
		return e
	}
	f, e := volumeOpen(drive, true)
	if e != nil {
		return e
	}
	locked := false
	defer func() {
		if f != nil {
			if locked {
				if u := volumeControl(f, 0x9001c); u != nil {
					r["deferred_unlock_error"] = u.Error()
					if err == nil {
						err = u
					}
				}
			}
			f.Close()
			f = nil
			r["locking_handle_closed"] = true
		}
		if err != nil {
			r["phase"] = "failed"
			r["error"] = err.Error()
			_ = leaseJournal(path, r)
		}
	}()
	if e = matchingVolume(f, d); e != nil {
		return e
	}
	if e = volumeControl(f, 0x90018); e != nil {
		return fmt.Errorf("FSCTL_LOCK_VOLUME: %w", e)
	}
	locked = true
	r["phase"] = "locked"
	if e = leaseJournal(path, r); e != nil {
		return e
	}
	if e = volumeControl(f, 0x90020); e != nil {
		return fmt.Errorf("FSCTL_DISMOUNT_VOLUME after successful lock: %w", e)
	}
	r["phase"] = "locked_and_dismounted"
	if e = leaseJournal(path, r); e != nil {
		return e
	}
	x2, boot2, e := requireRAM()
	if e != nil || x2 != x {
		return fmt.Errorf("system device changed while excluded: %v", e)
	}
	r["system_boot_device_while_locked"] = boot2
	marker := path + ".ram-marker"
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i ^ 0x5a)
	}
	m, e := os.OpenFile(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	nw, e := m.Write(data)
	if e == nil && nw != len(data) {
		e = fmt.Errorf("short RAM-marker write")
	}
	if e == nil {
		e = m.Sync()
	}
	ce := m.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	read, e := os.ReadFile(marker)
	if e != nil || !bytes.Equal(read, data) {
		return fmt.Errorf("RAM marker readback: %v", e)
	}
	r["RAM_marker_sha256_while_locked"] = sum(read)
	cmd, e := exec.Command(`X:\Windows\System32\cmd.exe`, "/d", "/c", "ver").CombinedOutput()
	if e != nil {
		return fmt.Errorf("RAM child process while locked: %v", e)
	}
	r["RAM_child_process_while_locked"] = string(cmd)
	c, e := net.DialTimeout("tcp", "192.0.2.10:50117", 3*time.Second)
	if e != nil {
		return fmt.Errorf("existing USB relay TCP connection while locked: %w", e)
	}
	c.Close()
	r["existing_USB_relay_TCP_while_locked"] = true
	time.Sleep(5 * time.Second)
	r["phase"] = "exclusion_checks_passed"
	if e = leaseJournal(path, r); e != nil {
		return e
	}
	if e = volumeControl(f, 0x9001c); e != nil {
		return fmt.Errorf("explicit FSCTL_UNLOCK_VOLUME: %w", e)
	}
	locked = false
	if e = f.Close(); e != nil {
		f = nil
		return e
	}
	f = nil
	r["locking_handle_closed"] = true
	after, n, e := fileHash(wim)
	if e != nil || n != 644359648 || after != expectedWim {
		return fmt.Errorf("source remount/WIM hash after unlock: %v", e)
	}
	r["after_wim_sha256"] = after
	r["phase"] = "verified_released_and_source_remounted"
	if e = leaseJournal(path, r); e != nil {
		return e
	}
	emit(r)
	return nil
}
