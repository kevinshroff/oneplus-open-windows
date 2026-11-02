package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func partitionPath(d *Opened) string {
	return fmt.Sprintf(`\\?\GLOBALROOT\Device\Harddisk%d\Partition%d`, d.Index, d.Partition)
}
func partitionHandle(d *Opened, write bool) (*os.File, error) {
	path := partitionPath(d)
	p, e := syscall.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	access := uint32(syscall.GENERIC_READ)
	flags := uint32(0)
	if write {
		access |= syscall.GENERIC_WRITE
		flags = 0x80000000
	} // FILE_FLAG_WRITE_THROUGH
	h, e := syscall.CreateFile(p, access, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, flags, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(h), path)
	info, e := ioctl(f, 0x70048, 144) // IOCTL_DISK_GET_PARTITION_INFO_EX
	if e != nil || len(info) < 144 || u32(info, 0) != 1 || u64(info, 8) != d.Target.Offset || u64(info, 16) != d.Target.Bytes || u32(info, 24) != d.Partition || guid(info[32:48]) != d.Target.TypeGUID || guid(info[48:64]) != d.Target.PartitionGUID || wstr(info[72:144]) != d.Target.Name {
		f.Close()
		return nil, fmt.Errorf("partition-handle identity guard: %v", e)
	}
	return f, nil
}
func readPlan(path string) (Patch, error) {
	var p Patch
	if e := pathGuard(path); e != nil {
		return p, e
	}
	f, e := os.Open(path)
	if e != nil {
		return p, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || st.Size() > 16<<20 {
		return p, fmt.Errorf("plan size guard")
	}
	dec := json.NewDecoder(io.LimitReader(f, 16<<20))
	dec.DisallowUnknownFields()
	if e = dec.Decode(&p); e != nil {
		return p, e
	}
	var extra any
	if e = dec.Decode(&extra); e != io.EOF {
		return p, fmt.Errorf("trailing plan data")
	}
	return p, validatePatch(p)
}
func journal(path string, p Patch, identity any) (func(string, []uint64) error, error) {
	if e := pathGuard(path); e != nil {
		return nil, e
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		return nil, fmt.Errorf("preserve existing journal")
	}
	return func(phase string, written []uint64) error {
		r := map[string]any{"version": "G18-fat-r1", "phase": phase, "identity": identity, "plan": p, "write_attempted_offsets": append([]uint64{}, written...), "utc": time.Now().UTC().Format(time.RFC3339Nano)}
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
	}, nil
}
func writerMutex() (func(), error) {
	dll := syscall.NewLazyDLL("kernel32.dll")
	p, _ := syscall.UTF16PtrFromString(`Local\OnePlusOpenG18DiskWriter`)
	h, _, e := dll.NewProc("CreateMutexW").Call(0, 0, uintptr(unsafe.Pointer(p)))
	if h == 0 {
		return nil, e
	}
	if e == syscall.ERROR_ALREADY_EXISTS {
		dll.NewProc("CloseHandle").Call(h)
		return nil, fmt.Errorf("another G18 writer exists")
	}
	return func() { dll.NewProc("CloseHandle").Call(h) }, nil
}
func applyFat(planPath, journalPath string) error {
	p, e := readPlan(planPath)
	if e != nil {
		return e
	}
	if p.Target != "userdata" || p.PrefixBytes != 256<<20 {
		return fmt.Errorf("only existing 256 MiB userdata FAT prefix is writable")
	}
	release, e := writerMutex()
	if e != nil {
		return e
	}
	defer release()
	d, e := discover(targets["userdata"])
	if e != nil {
		return e
	}
	defer d.f.Close()
	// The only writable OS handle is the exact validated partition device,
	// with relative offsets. A disk handle is never opened for writing.
	f, e := partitionHandle(d, true)
	if e != nil {
		return e
	}
	defer f.Close()
	boot, e := stable(f, 0, 4096)
	if e != nil {
		return e
	}
	if boot[510] != 0x55 || boot[511] != 0xaa || string(boot[82:87]) != "FAT32" {
		return fmt.Errorf("userdata FAT32 identity guard")
	}
	geometry, e := ioctl(f, 0x700a0, 1024)
	if e != nil || len(geometry) < 32 || u32(geometry, 20) != 4096 {
		return fmt.Errorf("partition sector size guard: %v", e)
	}
	witness := map[string]any{"target": d.Target, "partition_path": partitionPath(d), "disk_index": d.Index, "partition_number": d.Partition, "gpt_header_sha256": d.HeaderSHA, "gpt_array_sha256": d.ArraySHA, "writable_handle": "partition only; FILE_FLAG_WRITE_THROUGH"}
	checkpoint, e := journal(journalPath, p, witness)
	if e != nil {
		return e
	}
	if e = applyPatch(f, 0, p, checkpoint); e != nil {
		return e
	}
	emit(map[string]any{"version": "G18-fat-r1", "phase": "verified", "identity": witness, "before_sha256": p.BeforeSHA, "after_sha256": p.AfterSHA, "prefix_bytes": p.PrefixBytes, "sectors_written": len(p.Changes), "journal": journalPath})
	return nil
}
func applyFile(planPath, filePath, journalPath string) error {
	if e := pathGuard(filePath); e != nil {
		return e
	}
	if strings.EqualFold(filepath.Clean(filePath), filepath.Clean(planPath)) || strings.EqualFold(filepath.Clean(filePath), filepath.Clean(journalPath)) {
		return fmt.Errorf("distinct plan/data/journal required")
	}
	p, e := readPlan(planPath)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(filePath, os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || uint64(st.Size()) != p.PrefixBytes {
		return fmt.Errorf("regular-file test size")
	}
	checkpoint, e := journal(journalPath, p, map[string]any{"test_file": filePath, "raw_writes": 0})
	if e != nil {
		return e
	}
	if e = applyPatch(f, 0, p, checkpoint); e != nil {
		return e
	}
	emit(map[string]any{"phase": "verified", "test_file": filePath, "after_sha256": p.AfterSHA, "raw_writes": 0})
	return nil
}
