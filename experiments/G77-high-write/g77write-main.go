// g77write: qualify the Windows/storufs WRITE path above 4GiB absolute.
// Writes only two-pattern tests inside three 1MiB windows on the USERDATA
// partition (unmounted, GPT+IOCTL identity-guarded partition device,
// write-through), each restored and verified against a saved backup before
// moving on. Also reads fixed super windows to pin the fastboot truncation
// boundary. No GPT, boot_a/b, super, or bootloader partition is ever opened
// for writing.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"syscall"
)

const (
	sector      = uint64(4096)
	diskGUID    = "bc5c99e5-16e0-14b8-b43a-de06f8ea711b"
	udPartGUID  = "5982c0bf-b83f-025d-4354-68009ba0a5d1" // userdata unique GUID
	udOffset    = uint64(0x4582EC000)
	udLength    = uint64(0x71BB90F000)
	superOffset = uint64(0x2208000)
	winSize     = uint64(1 << 20)
)

var udRel = []uint64{0x100000000, 0x200000000, 0x1000000000} // 4GiB, 8GiB, 64GiB relative

var superReads = []struct {
	Rel  uint64
	Name string
}{
	{0xE0000000, "s3.50GiB"},
	{0xE8000000, "s3.625GiB"},
	{0x102000000, "s4.03125GiB"},
	{0x104000000, "s4.0625GiB"},
	{0x108000000, "s4.125GiB"},
	{0x110000000, "s4.25GiB"},
}

type step struct {
	Name     string `json:"name"`
	Offset   uint64 `json:"offset"`
	SHA256   string `json:"sha256,omitempty"`
	Ok       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
}

func main() {
	out := map[string]any{"tool": "g77write-r0", "steps": []step{}}
	steps := out["steps"].([]step)
	add := func(s step) { steps = append(steps, s); out["steps"] = steps }

	// --- read-only super boundary probes (physical drive, GENERIC_READ) ---
	disk := openDiskRO()
	if disk != nil {
		defer disk.Close()
		for _, p := range superReads {
			h, e := hashAt(disk, superOffset+p.Rel, winSize)
			s := step{Name: "super_read_" + p.Name, Offset: superOffset + p.Rel}
			if e != nil {
				s.Error = e.Error()
			} else {
				s.SHA256, s.Ok = h, true
			}
			add(s)
		}
	} else {
		add(step{Name: "super_read_open", Error: "disk not found"})
	}

	// --- userdata partition write qualification ---
	pf, e := openPartWrite()
	if e != nil {
		add(step{Name: "userdata_open", Error: e.Error()})
		fmt.Println(jsonString(out))
		os.Exit(1)
	}
	defer pf.Close()
	add(step{Name: "userdata_open", Ok: true})

	allOk := true
	for i, rel := range udRel {
		name := fmt.Sprintf("w%d_%x", i+1, rel)
		orig := make([]byte, winSize)
		if e := readFull(pf, rel, orig); e != nil {
			add(step{Name: name + "_backup_read", Error: e.Error()})
			allOk = false
			break
		}
		origHash := sha256.Sum256(orig)
		bk := fmt.Sprintf(`X:\OpenG17\payloads\g77-backup-%s.bin`, name)
		if e := os.WriteFile(bk, orig, 0644); e != nil {
			add(step{Name: name + "_backup_save", Error: e.Error()})
			allOk = false
			break
		}
		add(step{Name: name + "_backup", Ok: true, SHA256: hex.EncodeToString(origHash[:])})

		pA := patternA(int(winSize))
		pB := patternB(int(winSize), rel)
		ok := true
		for _, ph := range []struct {
			tag  string
			data []byte
		}{{"A", pA}, {"B", pB}} {
			if e := writeFull(pf, rel, ph.data); e != nil {
				add(step{Name: name + "_write" + ph.tag, Error: e.Error()})
				ok = false
				break
			}
			if e := pf.Sync(); e != nil {
				add(step{Name: name + "_flush" + ph.tag, Error: e.Error()})
				ok = false
				break
			}
			h, e := hashAt(pf, rel, winSize)
			want := sha256.Sum256(ph.data)
			if e != nil {
				add(step{Name: name + "_readback" + ph.tag, Error: e.Error()})
				ok = false
				break
			}
			good := h == hex.EncodeToString(want[:])
			add(step{Name: name + "_readback" + ph.tag, Ok: good, SHA256: h})
			if !good {
				ok = false
				break
			}
		}
		// restore regardless
		if e := writeFull(pf, rel, orig); e != nil {
			add(step{Name: name + "_restore_write", Error: e.Error()})
			allOk = false
			break
		}
		if e := pf.Sync(); e != nil {
			add(step{Name: name + "_restore_flush", Error: e.Error()})
			allOk = false
			break
		}
		h, e := hashAt(pf, rel, winSize)
		good := e == nil && h == hex.EncodeToString(origHash[:])
		add(step{Name: name + "_restore_verify", Ok: good, SHA256: h})
		if !good || !ok {
			allOk = false
			break
		}
	}
	out["all_windows_pass"] = allOk
	fmt.Println(jsonString(out))
	if !allOk {
		os.Exit(2)
	}
}

func openDiskRO() *os.File {
	for i := 0; i < 6; i++ {
		f, e := os.OpenFile(fmt.Sprintf(`\\.\PhysicalDrive%d`, i), os.O_RDONLY, 0)
		if e != nil {
			continue
		}
		sec := make([]byte, sector)
		if _, e = f.ReadAt(sec, int64(sector)); e == nil && string(sec[:8]) == "EFI PART" && guid(sec, 56) == diskGUID {
			return f
		}
		f.Close()
	}
	return nil
}

func openPartWrite() (*os.File, error) {
	// find partition number on the GPT disk first (read-only), then open device
	idx := -1
	var partNo uint32
	var df *os.File
	for i := 0; i < 6; i++ {
		f, e := os.OpenFile(fmt.Sprintf(`\\.\PhysicalDrive%d`, i), os.O_RDONLY, 0)
		if e != nil {
			continue
		}
		sec := make([]byte, sector)
		if _, e = f.ReadAt(sec, int64(sector)); e == nil && string(sec[:8]) == "EFI PART" && guid(sec, 56) == diskGUID {
			hdr := sec
			count := binary.LittleEndian.Uint32(hdr[80:84])
			stride := binary.LittleEndian.Uint32(hdr[84:88])
			arr := make([]byte, uint64(count)*uint64(stride))
			if _, e = f.ReadAt(arr, int64(binary.LittleEndian.Uint64(hdr[72:80])*sector)); e == nil {
				for n := uint32(0); n < count; n++ {
					ent := arr[uint64(n)*uint64(stride):]
					if guid(ent, 16) == udPartGUID {
						first := binary.LittleEndian.Uint64(ent[32:40])
						last := binary.LittleEndian.Uint64(ent[40:48])
						if first*sector == udOffset && (last+1-first)*sector == udLength {
							idx = i
							partNo = n + 1
							df = f
							break
						}
					}
				}
			}
			if idx >= 0 {
				break
			}
		}
		f.Close()
	}
	if idx < 0 {
		return nil, fmt.Errorf("userdata entry not found on GPT disk")
	}
	defer df.Close()
	path := fmt.Sprintf(`\\?\GLOBALROOT\Device\Harddisk%d\Partition%d`, idx, partNo)
	p, e := syscall.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, e := syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING,
		0x80000000 /*FILE_FLAG_WRITE_THROUGH*/, 0)
	if e != nil {
		return nil, fmt.Errorf("CreateFile write: %w", e)
	}
	f := os.NewFile(uintptr(h), path)
	// IOCTL_DISK_GET_PARTITION_INFO_EX identity guard
	info := make([]byte, 144)
	var n uint32
	e = syscall.DeviceIoControl(syscall.Handle(f.Fd()), 0x70048, nil, 0, &info[0], 144, &n, nil)
	if e != nil || n < 144 {
		f.Close()
		return nil, fmt.Errorf("partition info: %v", e)
	}
	if binary.LittleEndian.Uint64(info[8:16]) != udOffset || binary.LittleEndian.Uint64(info[16:24]) != udLength {
		f.Close()
		return nil, fmt.Errorf("partition identity mismatch")
	}
	return f, nil
}

func readFull(f *os.File, rel uint64, buf []byte) error {
	var done uint64
	for done < uint64(len(buf)) {
		n, e := f.ReadAt(buf[done:], int64(rel+done))
		if n == 0 && e != nil {
			return e
		}
		done += uint64(n)
	}
	return nil
}

func writeFull(f *os.File, rel uint64, buf []byte) error {
	var done uint64
	for done < uint64(len(buf)) {
		n, e := f.WriteAt(buf[done:], int64(rel+done))
		if n == 0 && e != nil {
			return e
		}
		done += uint64(n)
	}
	return nil
}

func hashAt(f *os.File, abs, size uint64) (string, error) {
	h := sha256.New()
	buf := make([]byte, 64<<10)
	var done uint64
	for done < size {
		want := uint64(len(buf))
		if want > size-done {
			want = size - done
		}
		if e := readFull(f, abs+done, buf[:want]); e != nil {
			return "", e
		}
		h.Write(buf[:want])
		done += want
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func patternA(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 0xA5
	}
	return b
}

func patternB(n int, seed uint64) []byte {
	b := make([]byte, n)
	for i := 0; i+8 <= n; i += 8 {
		binary.LittleEndian.PutUint64(b[i:], seed*0x9E3779B97F4A7C15+uint64(i))
	}
	for i := n - n%8; i < n; i++ {
		b[i] = byte(i)
	}
	return b
}

func guid(b []byte, o int) string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x",
		binary.LittleEndian.Uint32(b[o:]), binary.LittleEndian.Uint16(b[o+4:]),
		binary.LittleEndian.Uint16(b[o+6:]), b[o+8:o+10], b[o+10:o+16])
}

func jsonString(v any) string {
	b, _ := json.MarshalIndent(v, "", " ")
	return string(b)
}
