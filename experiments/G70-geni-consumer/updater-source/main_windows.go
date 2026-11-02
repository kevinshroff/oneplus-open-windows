package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
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
func pathGuard(p string) error {
	clean := filepath.Clean(p)
	if !strings.HasPrefix(strings.ToLower(clean), `x:\openg17\payloads\`) && !strings.HasPrefix(strings.ToLower(clean), `x:\openg18\`) {
		return fmt.Errorf("output must remain inside lab payloads")
	}
	if strings.HasSuffix(clean, `\`) {
		return fmt.Errorf("file path required")
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
	result := map[string]any{"version": "G18-readonly-r2", "target": d.Target, "disk_index": d.Index, "partition_number": d.Partition, "offset": off, "bytes": n, "gpt_header_sha256": d.HeaderSHA, "gpt_array_sha256": d.ArraySHA, "access": "GENERIC_READ", "raw_writes": 0}
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
func appendFile(chunk, dest string, off uint64, expected string) error {
	if e := pathGuard(chunk); e != nil {
		return e
	}
	if e := pathGuard(dest); e != nil {
		return e
	}
	if strings.EqualFold(filepath.Clean(chunk), filepath.Clean(dest)) {
		return fmt.Errorf("source equals destination")
	}
	digest, n, e := fileHash(chunk)
	if e != nil {
		return e
	}
	if digest != expected || n > 32<<20 || n < 1 || off > 1<<30 || uint64(n) > 1<<30-off {
		return fmt.Errorf("chunk identity/bounds")
	}
	if e = os.MkdirAll(filepath.Dir(dest), 0700); e != nil {
		return e
	}
	flag := os.O_WRONLY | os.O_APPEND
	if off == 0 {
		flag |= os.O_CREATE | os.O_EXCL
	}
	f, e := os.OpenFile(dest, flag, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || uint64(st.Size()) != off {
		return fmt.Errorf("destination length mismatch")
	}
	src, e := os.Open(chunk)
	if e != nil {
		return e
	}
	defer src.Close()
	written, e := io.Copy(f, src)
	if e != nil {
		return e
	}
	if written != n {
		return fmt.Errorf("short append")
	}
	if e = f.Sync(); e != nil {
		return e
	}
	emit(map[string]any{"file": dest, "offset": off, "chunk_bytes": n, "chunk_sha256": digest, "total_bytes": off + uint64(n), "raw_writes": 0})
	return nil
}
func run() error {
	if e := winpe(); e != nil {
		return e
	}
	a := os.Args[1:]
	if len(a) == 0 {
		return fmt.Errorf("inspect TARGET | backup TARGET OFFSET BYTES PREFIX | hash TARGET OFFSET BYTES | append CHUNK DEST OFFSET SHA256 | filehash PATH")
	}
	if a[0] == "probe-super-exclusion" && len(a) == 3 && a[2] == "--lock-matched-source-volume" {
		return probeSuperExclusion(a[1])
	}
	if a[0] == "apply-fat" && len(a) == 4 && a[3] == "--write-userdata-prefix" {
		return applyFat(a[1], a[2])
	}
	if a[0] == "apply-boot-a" && len(a) == 4 && a[3] == "--write-verified-boot-a-prefix" {
		return applyBootA(a[1], a[2])
	}
	if a[0] == "apply-file" && len(a) == 4 {
		return applyFile(a[1], a[2], a[3])
	}
	if a[0] == "update-trial-wim" && len(a) == 4 && a[3] == "--update-only-inactive-trial-file" {
		return updateTrialWIM(a[1], a[2])
	}
	if a[0] == "update-trial-wim-ram" && len(a) == 4 && a[3] == "--update-only-inactive-trial-file-from-ram" {
		return updateTrialWIMFromRAM(a[1], a[2])
	}
	if a[0] == "filehash" && len(a) == 2 {
		if e := pathGuard(a[1]); e != nil {
			return e
		}
		h, n, e := fileHash(a[1])
		if e != nil {
			return e
		}
		emit(map[string]any{"file": a[1], "bytes": n, "sha256": h})
		return nil
	}
	if a[0] == "append" && len(a) == 5 {
		o, e := number(a[3])
		if e != nil {
			return e
		}
		return appendFile(a[1], a[2], o, a[4])
	}
	if len(a) < 2 {
		return fmt.Errorf("missing target")
	}
	t, ok := targets[a[1]]
	if !ok {
		return fmt.Errorf("target outside allowlist")
	}
	d, e := discover(t)
	if e != nil {
		return e
	}
	defer d.f.Close()
	switch a[0] {
	case "probe-partition":
		if len(a) != 2 {
			return fmt.Errorf("partition probe arguments")
		}
		f, e := partitionHandle(d, false)
		if e != nil {
			return e
		}
		defer f.Close()
		b, e := stable(f, 0, 4096)
		if e != nil {
			return e
		}
		emit(map[string]any{"partition_path": partitionPath(d), "first_sector_sha256": sum(b), "raw_writes": 0, "requested_access": "GENERIC_READ"})
		return nil
	case "inspect":
		if len(a) != 2 {
			return fmt.Errorf("inspect arguments")
		}
		b, e := stable(d.f, t.Offset, sector)
		if e != nil {
			return e
		}
		emit(map[string]any{"version": "G18-readonly-r2", "target": t, "disk_index": d.Index, "partition_number": d.Partition, "first_sector_sha256": sum(b), "first_16_hex": hex.EncodeToString(b[:16]), "gpt_header_sha256": d.HeaderSHA, "gpt_array_sha256": d.ArraySHA, "raw_writes": 0})
		return nil
	case "hash", "backup":
		if len(a) != 4 && len(a) != 5 {
			return fmt.Errorf("range arguments")
		}
		off, e := number(a[2])
		if e != nil {
			return e
		}
		n, e := number(a[3])
		if e != nil {
			return e
		}
		if a[0] == "hash" && len(a) == 4 {
			return hashTarget(d, off, n)
		}
		if a[0] == "backup" && len(a) == 5 {
			return backup(d, off, n, a[4])
		}
		return fmt.Errorf("command arguments")
	default:
		return fmt.Errorf("unsupported command")
	}
}
func main() {
	start := time.Now()
	if e := run(); e != nil {
		fail(e)
	}
	fmt.Fprintln(os.Stderr, "completed_ms", time.Since(start).Milliseconds())
}
