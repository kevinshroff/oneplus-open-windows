package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func readRAMUpdateEnvironment() (ramUpdateEnvironment, error) {
	e := ramUpdateEnvironment{CPUs: uint32(runtime.NumCPU())}
	version := make([]byte, 276)
	binary.LittleEndian.PutUint32(version, uint32(len(version)))
	r, _, _ := syscall.NewLazyDLL("ntdll.dll").NewProc("RtlGetVersion").Call(uintptr(unsafe.Pointer(&version[0])))
	if uint32(r) != 0 {
		return e, fmt.Errorf("RtlGetVersion status0x%x", r)
	}
	e.Build = u32(version, 12)
	var err error
	e.XDevice, err = dosDevice("X:")
	if err != nil {
		return e, err
	}
	var key syscall.Handle
	p, _ := syscall.UTF16PtrFromString(`SYSTEM\CurrentControlSet\Control`)
	if err = syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, p, 0, syscall.KEY_QUERY_VALUE, &key); err != nil {
		return e, err
	}
	defer syscall.RegCloseKey(key)
	value, _ := syscall.UTF16PtrFromString("SystemBootDevice")
	buf := make([]uint16, 2048)
	size, typ := uint32(len(buf)*2), uint32(0)
	r, _, callerr := syscall.NewLazyDLL("advapi32.dll").NewProc("RegQueryValueExW").Call(uintptr(key), uintptr(unsafe.Pointer(value)), 0, uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r != 0 || typ != 1 || size < 2 || size > uint32(len(buf)*2) || size%2 != 0 {
		return e, fmt.Errorf("SystemBootDevice query result%d: %v", r, callerr)
	}
	if buf[size/2-1] != 0 {
		return e, fmt.Errorf("unterminated SystemBootDevice")
	}
	e.BootDevice = syscall.UTF16ToString(buf[:size/2])
	if uint32(len(syscall.StringToUTF16(e.BootDevice))*2) != size {
		return e, fmt.Errorf("embedded terminator in SystemBootDevice")
	}
	firmware := syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemFirmwareTable")
	n, _, callerr := firmware.Call(0x41435049, 0x54445344, 0, 0)
	if n != 576 {
		return e, fmt.Errorf("original DSDT length%d: %v", n, callerr)
	}
	table := make([]byte, n)
	got, _, callerr := firmware.Call(0x41435049, 0x54445344, uintptr(unsafe.Pointer(&table[0])), n)
	if got != n {
		return e, fmt.Errorf("short DSDT read: %v", callerr)
	}
	e.DSDTBytes, e.DSDTSHA = len(table), sum(table)
	return e, validateRAMUpdateEnvironment(e)
}

func verifyRAMJSONDirectory(parent, ramDevice string) error {
	p, err := syscall.UTF16PtrFromString(parent)
	if err != nil {
		return err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0x02000000|0x00200000, 0)
	if err != nil {
		return fmt.Errorf("RAM directory open: %w", err)
	}
	defer syscall.CloseHandle(h)
	var info syscall.ByHandleFileInformation
	if err = syscall.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&0x10 == 0 || info.FileAttributes&0x400 != 0 {
		return fmt.Errorf("RAM directory nonreparse guard: %v", err)
	}
	buf := make([]uint16, 32768)
	n, _, err := syscall.NewLazyDLL("kernel32.dll").NewProc("GetFinalPathNameByHandleW").Call(uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 2)
	if n == 0 || n >= uintptr(len(buf)) || !strings.EqualFold(syscall.UTF16ToString(buf[:n]), ramDevice+parent[2:]) {
		return fmt.Errorf("RAM directory final NT path guard: %v", err)
	}
	return nil
}

// Run from the established original-table RAM image; discover the physical
// super volume rather than assuming its drive letter. Raw handles remain
// read-only. Only the fixed inactive regular WIM receives write access.
func updateTrialWIMFromRAM(planPath, journalPath string) error {
	env, e := readRAMUpdateEnvironment()
	if e != nil {
		return e
	}
	planParent, journalParent, e := validateRAMUpdatePaths(planPath, journalPath)
	if e != nil {
		return e
	}
	for _, parent := range []string{planParent, journalParent} {
		if e = verifyRAMJSONDirectory(parent, env.XDevice); e != nil {
			return e
		}
	}
	if _, e = os.Stat(journalPath); !os.IsNotExist(e) {
		return fmt.Errorf("preserve existing RAM WIM journal")
	}
	p, e := readWIMPlan(planPath)
	if e != nil {
		return e
	}
	if e = validateRAMWIMPair(p); e != nil {
		return e
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
	device, e := dosDevice(drive)
	if e != nil || !strings.HasPrefix(strings.ToLower(device), `\device\harddiskvolume`) {
		return fmt.Errorf("matched super device: %v", e)
	}
	v, e := volumeOpen(drive, false)
	if e != nil {
		return e
	}
	e = matchingVolume(v, d)
	v.Close()
	if e != nil {
		return fmt.Errorf("matched super volume identity: %w", e)
	}
	maintenance := drive + `\OpenG18\G18-maintenance.wim`
	h, n, e := fileHash(maintenance)
	if e != nil || n != 644359648 || h != "1db2c5d735281ddcb11f1723bb729753e81a74793a495a83c0bece2ffd26d7e9" {
		return fmt.Errorf("preserved maintenance WIM full hash: %v", e)
	}
	path := drive + `\OpenG18\` + trialWIMName
	f, e := inactiveTrialHandle(path, device)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || uint64(st.Size()) != p.BeforeBytes {
		return fmt.Errorf("inactive WIM exact preimage size: %v", e)
	}
	identity := map[string]any{"target": d.Target, "file": path, "x_device": env.XDevice, "physical_volume": device, "environment": env, "disk_index": d.Index, "partition_number": d.Partition, "gpt_header_sha256": d.HeaderSHA, "gpt_array_sha256": d.ArraySHA, "access": "exclusive regular file; FILE_FLAG_WRITE_THROUGH; final NT path verified", "raw_writes": 0, "journal_root": "proved RAM"}
	checkpoint := func(phase string, written []uint64) error {
		return leaseJournal(journalPath, map[string]any{"version": "G65-RAM-trial-wim-v1", "phase": phase, "identity": identity, "plan": p, "write_attempted_offsets": append([]uint64{}, written...), "utc": time.Now().UTC().Format(time.RFC3339Nano)})
	}
	if e = applyWIMPlan(f, p, checkpoint); e != nil {
		return e
	}
	st, e = f.Stat()
	if e != nil || uint64(st.Size()) != p.AfterBytes {
		return fmt.Errorf("inactive WIM final size: %v", e)
	}
	emit(map[string]any{"phase": "verified", "identity": identity, "before_sha256": p.BeforeSHA, "after_sha256": p.AfterSHA, "before_bytes": p.BeforeBytes, "after_bytes": p.AfterBytes, "changed_ranges": len(p.Changes), "tail_bytes": len(p.Tail), "journal": journalPath})
	return nil
}
