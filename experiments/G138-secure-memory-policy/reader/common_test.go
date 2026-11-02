package main

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/" + name)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func fixCRC(b []byte) {
	binary.LittleEndian.PutUint32(b[16:], 0)
	binary.LittleEndian.PutUint32(b[16:], crc32.ChecksumIEEE(b[:u32(b, 12)]))
}
func TestNativeGPTAndLayout(t *testing.T) {
	p, a, b, ba := fixture(t, "primary.bin"), fixture(t, "array.bin"), fixture(t, "backup.bin"), fixture(t, "backup-array.bin")
	if !knownGPT(p, a, b) {
		t.Fatal("retained native metadata identity")
	}
	for name, part := range map[string]uint32{"tz_a": 4, "tz_b": 36} {
		t.Run(name, func(t *testing.T) {
			target := targets[name]
			h, e := header(p, target.DiskBytes, 1)
			if e != nil {
				t.Fatal(e)
			}
			bh, e := header(b, target.DiskBytes, target.DiskBytes/sector-1)
			if e != nil {
				t.Fatal(e)
			}
			if h.Count != 96 || h.Stride != 128 {
				t.Fatal("native array is 96 entries")
			}
			got, e := matchArrays(target, h, bh, a, ba)
			if e != nil || got != part {
				t.Fatalf("partition %d: %v", got, e)
			}
			if !verifiedLayout(fixture(t, "layout.bin"), target, part) {
				t.Fatal("OS layout did not bind")
			}
			if bounds(target, 0, target.Bytes) != nil {
				t.Fatal("complete fixed capture refused")
			}
		})
	}
	if len(targets) != 2 {
		t.Fatal("allowlist expanded")
	}
}
func TestMetadataRefusals(t *testing.T) {
	target := targets["tz_a"]
	for name, change := range map[string]func([]byte){
		"bad CRC":                  func(b []byte) { b[16] ^= 1 },
		"revision":                 func(b []byte) { b[8] ^= 1; fixCRC(b) },
		"copy pointer":             func(b []byte) { b[32] ^= 1; fixCRC(b) },
		"array overlaps partition": func(b []byte) { binary.LittleEndian.PutUint64(b[72:], u64(b, 40)); fixCRC(b) },
		"array too large":          func(b []byte) { binary.LittleEndian.PutUint32(b[80:], 4096); fixCRC(b) },
	} {
		t.Run(name, func(t *testing.T) {
			p := fixture(t, "primary.bin")
			change(p)
			if _, e := header(p, target.DiskBytes, 1); e == nil {
				t.Fatal("invalid header admitted")
			}
		})
	}
	p, b := fixture(t, "primary.bin"), fixture(t, "backup.bin")
	h, _ := header(p, target.DiskBytes, 1)
	bh, _ := header(b, target.DiskBytes, target.DiskBytes/sector-1)
	for name, change := range map[string]func([]byte){
		"type":           func(a []byte) { a[3*128] ^= 1 },
		"name":           func(a []byte) { a[3*128+56] ^= 1 },
		"offset":         func(a []byte) { a[3*128+32] ^= 1 },
		"wrapped offset": func(a []byte) { binary.LittleEndian.PutUint64(a[3*128+32:], u64(a, 3*128+32)+(1<<52)) },
		"length":         func(a []byte) { a[3*128+40] ^= 1 },
		"duplicate":      func(a []byte) { copy(a[4*128:5*128], a[3*128:4*128]) },
		"missing":        func(a []byte) { a[3*128+16] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			a := fixture(t, "array.bin")
			change(a)
			x, y := h, bh
			x.ArrayCRC = crc32.ChecksumIEEE(a)
			y.ArrayCRC = x.ArrayCRC
			if _, e := matchArrays(target, x, y, a, a); e == nil {
				t.Fatal("invalid target admitted")
			}
			if knownGPT(p, a, b) {
				t.Fatal("changed array hash admitted")
			}
		})
	}
	a, ba := fixture(t, "array.bin"), fixture(t, "backup-array.bin")
	ba[0] ^= 1
	if _, e := matchArrays(target, h, bh, a, ba); e == nil {
		t.Fatal("different copies admitted")
	}
	if _, e := matchArrays(target, h, bh, a[:128], a[:128]); e == nil {
		t.Fatal("truncated array admitted")
	}
	l := fixture(t, "layout.bin")
	if verifiedLayout(l[:100], target, 4) || verifiedLayout(l, target, 36) {
		t.Fatal("invalid OS layout admitted")
	}
	l[48+3*144+8] ^= 1
	if verifiedLayout(l, target, 4) {
		t.Fatal("wrong layout offset admitted")
	}
}
func TestBoundedReads(t *testing.T) {
	target := targets["tz_a"]
	for _, r := range [][2]uint64{{0, 0}, {1, 4096}, {0, 4095}, {0, target.Bytes + 4096}, {target.Bytes, 4096}, {^uint64(0) - 4095, 8192}} {
		if bounds(target, r[0], r[1]) == nil {
			t.Fatalf("range admitted %v", r)
		}
	}
	f, e := os.CreateTemp(t.TempDir(), "stable")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	p := fixture(t, "primary.bin")
	if _, e = f.Write(p); e != nil {
		t.Fatal(e)
	}
	b, e := stable(f, 0, 4096)
	if e != nil || sum(b) != sum(p) {
		t.Fatalf("stable fixture: %v", e)
	}
	for _, r := range [][2]uint64{{4096, 4096}, {0, 16<<20 + 1}, {^uint64(0) - 1, 4}} {
		if _, e := stable(f, r[0], r[1]); e == nil {
			t.Fatalf("unsafe/truncated read admitted %v", r)
		}
	}
}
