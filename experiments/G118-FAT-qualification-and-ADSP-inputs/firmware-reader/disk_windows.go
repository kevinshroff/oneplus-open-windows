package main

import (
	"fmt"
	"os"
	"syscall"
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
