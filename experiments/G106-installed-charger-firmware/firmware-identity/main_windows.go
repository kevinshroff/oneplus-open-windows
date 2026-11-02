package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

func rawOpen(path string) (*os.File, error) {
	p, e := syscall.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, e := syscall.CreateFile(p, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(h), path), nil
}
func ioctl(f *os.File, code uint32, size int) ([]byte, error) {
	b := make([]byte, size)
	var n uint32
	e := syscall.DeviceIoControl(syscall.Handle(f.Fd()), code, nil, 0, &b[0], uint32(len(b)), &n, nil)
	if e != nil {
		return nil, e
	}
	if int(n) > len(b) {
		return nil, fmt.Errorf("IOCTL count")
	}
	return b[:n], nil
}

type Opened struct {
	f                   *os.File
	Target              Target
	Index               int
	Partition           uint32
	HeaderSHA, ArraySHA string
}

func discover(t Target) (*Opened, error) {
	var matches []*Opened
	for i := 0; i < 6; i++ {
		f, e := rawOpen(fmt.Sprintf(`\\.\PhysicalDrive%d`, i))
		if e != nil {
			continue
		}
		length, le := ioctl(f, 0x7405c, 8)
		geom, ge := ioctl(f, 0x700a0, 1024)
		if le != nil || ge != nil || len(length) < 8 || len(geom) < 32 || u64(length, 0) != t.DiskBytes || u32(geom, 20) != 4096 {
			f.Close()
			continue
		}
		primary, e := stable(f, sector, sector)
		if e != nil {
			f.Close()
			continue
		}
		h, e := header(primary, t.DiskBytes, 1)
		if e != nil || h.DiskGUID != t.DiskGUID {
			f.Close()
			continue
		}
		backup, e := stable(f, t.DiskBytes-sector, sector)
		if e != nil {
			f.Close()
			continue
		}
		bh, e := header(backup, t.DiskBytes, t.DiskBytes/sector-1)
		if e != nil {
			f.Close()
			continue
		}
		a, e := stable(f, h.ArrayLBA*sector, uint64(h.Count)*uint64(h.Stride))
		if e != nil {
			f.Close()
			continue
		}
		b, e := stable(f, bh.ArrayLBA*sector, uint64(bh.Count)*uint64(bh.Stride))
		if e != nil {
			f.Close()
			continue
		}
		part, e := matchArrays(t, h, bh, a, b)
		if e != nil {
			f.Close()
			continue
		}
		layout, e := ioctl(f, 0x70050, 65536)
		if e != nil || len(layout) < 48 || u32(layout, 0) != 1 || guid(layout[8:24]) != t.DiskGUID {
			f.Close()
			continue
		}
		count := u32(layout, 4)
		valid := false
		if count < 4096 && uint64(48)+uint64(count)*144 <= uint64(len(layout)) {
			for j := uint32(0); j < count; j++ {
				v := layout[48+j*144 : 48+(j+1)*144]
				if guid(v[48:64]) == t.PartitionGUID && u32(v, 0) == 1 && u64(v, 8) == t.Offset && u64(v, 16) == t.Bytes && u32(v, 24) == part && guid(v[32:48]) == t.TypeGUID && wstr(v[72:144]) == t.Name {
					valid = true
				}
			}
		}
		if !valid {
			f.Close()
			continue
		}
		matches = append(matches, &Opened{f, t, i, part, sum(primary), sum(a)})
	}
	if len(matches) != 1 {
		for _, m := range matches {
			m.f.Close()
		}
		return nil, fmt.Errorf("expected exactly one fully verified %s target; found %d", t.Name, len(matches))
	}
	return matches[0], nil
}

func runIdentity() (map[string]any, error) {
	if len(os.Args) != 1 {
		return nil, fmt.Errorf("this fixed read-only helper takes no arguments")
	}
	if e := fullOSGuard(); e != nil {
		return nil, e
	}
	firmware := syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemFirmwareTable")
	n, _, _ := firmware.Call(0x41435049, 0x54445344, 0, 0)
	if n != 576 {
		return nil, fmt.Errorf("DSDT length differs: %d", n)
	}
	table := make([]byte, n)
	got, _, _ := firmware.Call(0x41435049, 0x54445344, uintptr(unsafe.Pointer(&table[0])), n)
	if got != n || sum(table) != "c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01" {
		return nil, fmt.Errorf("DSDT identity differs")
	}
	d, e := discover(targets["boot_a"])
	if e != nil {
		return nil, e
	}
	defer d.f.Close()
	h := sha256.New()
	prefix := ""
	for done := uint64(0); done < d.Target.Bytes; {
		n := uint64(16 << 20)
		if n > d.Target.Bytes-done {
			n = d.Target.Bytes - done
		}
		b, e := stable(d.f, d.Target.Offset+done, n)
		if e != nil {
			return nil, e
		}
		if done == 0 {
			prefix = sum(b[:2760704])
		}
		h.Write(b)
		done += n
	}
	full := hex.EncodeToString(h.Sum(nil))
	return map[string]any{"ok": true, "tool": "G106-fixed-readonly-firmware-identity", "systemroot": os.Getenv("SystemRoot"), "DSDT_sha256": sum(table), "target": d.Target, "disk_index": d.Index, "partition_number": d.Partition, "gpt_header_sha256": d.HeaderSHA, "gpt_array_sha256": d.ArraySHA, "access": "GENERIC_READ", "raw_writes": 0, "bytes": d.Target.Bytes, "double_read_bytes": d.Target.Bytes * 2, "sha256": full, "matches_retained_G80_full_image": full == "d488d725bac28b20ede177757db2ac4e2beb5ad4b6616b8f858416b911079248", "Android_image_bytes": 2760704, "Android_image_sha256": prefix, "matches_retained_G80_Android_image": prefix == "7659428a3fe0ec55ff3532c29bc28e2ecb2a5ba9413ce0407a7853fe36804b42"}, nil
}
func main() {
	start := time.Now()
	r, e := runIdentity()
	if e != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": false, "error": e.Error(), "raw_writes": 0})
		os.Exit(1)
	}
	r["duration_ms"] = time.Since(start).Milliseconds()
	json.NewEncoder(os.Stdout).Encode(r)
}
