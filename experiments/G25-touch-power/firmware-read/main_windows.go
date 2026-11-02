package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

func fail(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(1) }
func emit(v any) {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		fail(e)
	}
	fmt.Println(string(b))
}
func winpe() error {
	if runtime.GOARCH != "arm64" || !strings.EqualFold(os.Getenv("SystemRoot"), `X:\Windows`) {
		return fmt.Errorf("requires ARM64 WinPE X:\\Windows")
	}
	if e := exec.Command(`X:\Windows\System32\reg.exe`, "query", `HKLM\SYSTEM\CurrentControlSet\Control\MiniNT`).Run(); e != nil {
		return fmt.Errorf("MiniNT guard: %w", e)
	}
	return nil
}
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

// Ordinary, new output files only. No arbitrary directory, device, or ADS names.
func pathGuard(p string) error {
	clean := filepath.Clean(p)
	if !strings.EqualFold(filepath.Dir(clean), `X:\OpenG17\payloads`) {
		return fmt.Errorf("output must be a direct lab-payload file")
	}
	base := filepath.Base(clean)
	if !strings.HasPrefix(base, "G25-firmware-read-") || len(base) > 160 {
		return fmt.Errorf("fixed output prefix required")
	}
	for _, c := range base {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return fmt.Errorf("ordinary filename characters only")
		}
	}
	return nil
}
func backup(d *Opened, off, n uint64, prefix string) error {
	if e := bounds(d.Target, off, n); e != nil {
		return e
	}
	if e := pathGuard(prefix); e != nil {
		return e
	}
	result := map[string]any{"version": "G25-firmware-read-r1", "target": d.Target, "disk_index": d.Index, "partition_number": d.Partition, "offset": off, "bytes": n, "gpt_header_sha256": d.HeaderSHA, "gpt_array_sha256": d.ArraySHA, "access": "GENERIC_READ", "raw_writes": 0}
	pieces := []any{}
	whole := sha256.New()
	for done := uint64(0); done < n; {
		size := uint64(16 << 20)
		if size > n-done {
			size = n - done
		}
		b, e := stable(d.f, d.Target.Offset+off+done, size)
		if e != nil {
			return e
		}
		whole.Write(b)
		p := fmt.Sprintf("%s-%03d.zip", prefix, done/(16<<20))
		if e := pathGuard(p); e != nil {
			return e
		}
		f, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		z := zip.NewWriter(f)
		w, e := z.Create("raw.bin")
		if e == nil {
			_, e = w.Write(b)
		}
		ce := z.Close()
		se := f.Sync()
		fe := f.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
		if se != nil {
			return se
		}
		if fe != nil {
			return fe
		}
		digest, bytes, e := fileHash(p)
		if e != nil {
			return e
		}
		pieces = append(pieces, map[string]any{"path": p, "offset": off + done, "raw_bytes": size, "raw_sha256": sum(b), "zip_bytes": bytes, "zip_sha256": digest})
		done += size
	}
	result["raw_sha256"], result["pieces"] = hex.EncodeToString(whole.Sum(nil)), pieces
	p := prefix + "-manifest.json"
	f, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	e = json.NewEncoder(f).Encode(result)
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
	emit(result)
	return nil
}
func hashTarget(d *Opened, off, n uint64) error {
	if e := bounds(d.Target, off, n); e != nil {
		return e
	}
	h := sha256.New()
	for done := uint64(0); done < n; {
		size := uint64(16 << 20)
		if size > n-done {
			size = n - done
		}
		b, e := stable(d.f, d.Target.Offset+off+done, size)
		if e != nil {
			return e
		}
		h.Write(b)
		done += size
	}
	emit(map[string]any{"target": d.Target, "disk_index": d.Index, "offset": off, "bytes": n, "sha256": hex.EncodeToString(h.Sum(nil)), "access": "GENERIC_READ", "raw_writes": 0})
	return nil
}

// This executable has no raw-disk write operation and accepts no arbitrary offsets.
func run() error {
	if e := winpe(); e != nil {
		return e
	}
	a := os.Args[1:]
	if len(a) < 2 {
		return fmt.Errorf("inspect TARGET | capture TARGET PREFIX | hash TARGET")
	}
	t, ok := targets[a[1]]
	if !ok {
		return fmt.Errorf("target is outside the four-entry AOP read allowlist")
	}
	if !((a[0] == "inspect" && len(a) == 2) || (a[0] == "hash" && len(a) == 2) || (a[0] == "capture" && len(a) == 3)) {
		return fmt.Errorf("unknown read-only operation")
	}
	if a[0] == "capture" {
		if e := pathGuard(a[2]); e != nil {
			return e
		}
	}
	d, e := discover(t)
	if e != nil {
		return e
	}
	defer d.f.Close()
	switch a[0] {
	case "inspect":
		emit(map[string]any{"version": "G25-firmware-read-r1", "target": t, "disk_index": d.Index, "partition_number": d.Partition, "gpt_header_sha256": d.HeaderSHA, "gpt_array_sha256": d.ArraySHA, "access": "GENERIC_READ", "raw_writes": 0})
	case "capture":
		return backup(d, 0, t.Bytes, a[2])
	case "hash":
		return hashTarget(d, 0, t.Bytes)
	}
	return nil
}
func main() {
	if e := run(); e != nil {
		fail(e)
	}
}
