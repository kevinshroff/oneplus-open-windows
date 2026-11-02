package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"strconv"
	"unicode/utf16"
)

const sector = uint64(4096)

type Target struct {
	Name, DiskGUID, PartitionGUID, TypeGUID string
	DiskBytes, Offset, Bytes, MaxRead       uint64
}

var targets = map[string]Target{
	"boot_a": {"boot_a", "7f75e746-e26a-9214-d881-0848763b077d", "36d91b5e-7e00-ea3c-33f7-a991e3ff6c79", "20117f86-e985-4357-b9ee-374bc1d8487d", 4043309056, 0x1a986000, 0xc000000, 0xc000000},
}

func sum(b []byte) string        { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func u32(b []byte, o int) uint32 { return binary.LittleEndian.Uint32(b[o : o+4]) }
func u64(b []byte, o int) uint64 { return binary.LittleEndian.Uint64(b[o : o+8]) }
func guid(b []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", u32(b, 0), binary.LittleEndian.Uint16(b[4:6]), binary.LittleEndian.Uint16(b[6:8]), b[8:10], b[10:16])
}
func wstr(b []byte) string {
	v := []uint16{}
	for i := 0; i+1 < len(b); i += 2 {
		x := binary.LittleEndian.Uint16(b[i:])
		if x == 0 {
			break
		}
		v = append(v, x)
	}
	return string(utf16.Decode(v))
}
func number(s string) (uint64, error) { return strconv.ParseUint(s, 0, 64) }
func bounds(t Target, off, n uint64) error {
	if n == 0 || off%sector != 0 || n%sector != 0 || off > t.MaxRead || n > t.MaxRead-off || off > t.Bytes || n > t.Bytes-off {
		return fmt.Errorf("range outside aligned target allowlist")
	}
	return nil
}

type Header struct {
	Current, Backup, First, Last, ArrayLBA uint64
	Count, Stride, ArrayCRC                uint32
	DiskGUID                               string
}

func header(b []byte, diskBytes, expectedLBA uint64) (Header, error) {
	var h Header
	if len(b) != int(sector) || string(b[:8]) != "EFI PART" || u32(b, 8) != 0x10000 {
		return h, fmt.Errorf("GPT signature/revision")
	}
	size := u32(b, 12)
	if size < 92 || size > uint32(sector) || u32(b, 20) != 0 {
		return h, fmt.Errorf("GPT header size/reserved")
	}
	raw := append([]byte(nil), b[:size]...)
	for i := 16; i < 20; i++ {
		raw[i] = 0
	}
	if crc32.ChecksumIEEE(raw) != u32(b, 16) {
		return h, fmt.Errorf("GPT header CRC")
	}
	h = Header{u64(b, 24), u64(b, 32), u64(b, 40), u64(b, 48), u64(b, 72), u32(b, 80), u32(b, 84), u32(b, 88), guid(b[56:72])}
	last := diskBytes/sector - 1
	if h.Current != expectedLBA || !((h.Current == 1 && h.Backup == last) || (h.Current == last && h.Backup == 1)) || h.First < 2 || h.Last >= last || h.First > h.Last {
		return h, fmt.Errorf("GPT header bounds/copy identity")
	}
	n := uint64(h.Count) * uint64(h.Stride)
	if h.Count == 0 || h.Count > 4096 || h.Stride < 128 || h.Stride%8 != 0 || n > 256<<10 || n%sector != 0 || h.ArrayLBA >= diskBytes/sector || n/sector > diskBytes/sector-h.ArrayLBA {
		return h, fmt.Errorf("GPT array bounds")
	}
	if h.Current == 1 && (h.ArrayLBA <= 1 || h.ArrayLBA+n/sector > h.First) {
		return h, fmt.Errorf("primary array placement")
	}
	if h.Current == last && (h.ArrayLBA <= h.Last || h.ArrayLBA+n/sector > last) {
		return h, fmt.Errorf("backup array placement")
	}
	return h, nil
}
func matchArrays(t Target, a, b Header, ap, bp []byte) (uint32, error) {
	if a.DiskGUID != t.DiskGUID || b.DiskGUID != a.DiskGUID || a.First != b.First || a.Last != b.Last || a.Count != b.Count || a.Stride != b.Stride || a.ArrayCRC != b.ArrayCRC || !bytes.Equal(ap, bp) || crc32.ChecksumIEEE(ap) != a.ArrayCRC {
		return 0, fmt.Errorf("GPT copy/array identity mismatch")
	}
	if len(ap) != int(a.Count*a.Stride) {
		return 0, fmt.Errorf("array size")
	}
	found := uint32(0)
	for i := uint32(0); i < a.Count; i++ {
		v := ap[i*a.Stride : (i+1)*a.Stride]
		if guid(v[16:32]) == t.PartitionGUID {
			if found != 0 || guid(v[:16]) != t.TypeGUID || wstr(v[56:128]) != t.Name || u64(v, 32)*sector != t.Offset || u64(v, 40) < u64(v, 32) || (u64(v, 40)-u64(v, 32)+1)*sector != t.Bytes {
				return 0, fmt.Errorf("partition identity/extent mismatch")
			}
			found = i + 1
		}
	}
	if found == 0 {
		return 0, fmt.Errorf("partition not found")
	}
	return found, nil
}
func stable(f *os.File, off, n uint64) ([]byte, error) {
	if n == 0 || n > 16<<20 || off+n < off {
		return nil, fmt.Errorf("bounded read required")
	}
	a, b := make([]byte, int(n)), make([]byte, int(n))
	_, ea := f.ReadAt(a, int64(off))
	_, eb := f.ReadAt(b, int64(off))
	if ea != nil || eb != nil {
		return nil, fmt.Errorf("double read: %v / %v", ea, eb)
	}
	if !bytes.Equal(a, b) {
		return nil, fmt.Errorf("unstable double read")
	}
	return a, nil
}
func fileHash(p string) (string, int64, error) {
	f, e := os.Open(p)
	if e != nil {
		return "", 0, e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, e
}
