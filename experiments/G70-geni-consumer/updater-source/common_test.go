package main

import (
	"encoding/binary"
	"hash/crc32"
	"math"
	"testing"
)

func TestWriteExtentCannotBeRepresentedByReadRange(t *testing.T) {
	// A wrapped end and an aligned range spilling into an adjacent partition
	// must both be rejected before any OS handle is requested.
	x := targets["boot_a"]
	for _, v := range [][2]uint64{{0, 0}, {1, 4096}, {0, 1}, {x.Bytes, 4096}, {x.Bytes - 4096, 8192}, {math.MaxUint64 - 4095, 8192}, {0, math.MaxUint64 - 4095}} {
		if bounds(x, v[0], v[1]) == nil {
			t.Fatalf("accepted invalid range %#v", v)
		}
	}
	for _, v := range [][2]uint64{{0, 4096}, {x.Bytes - 4096, 4096}, {0, x.Bytes}} {
		if e := bounds(x, v[0], v[1]); e != nil {
			t.Fatal(e)
		}
	}
}
func TestRejectMisplacedOrCorruptGPT(t *testing.T) {
	const diskBytes = uint64(4096 * 100)
	b := make([]byte, 4096)
	copy(b, "EFI PART")
	binary.LittleEndian.PutUint32(b[8:], 0x10000)
	binary.LittleEndian.PutUint32(b[12:], 92)
	binary.LittleEndian.PutUint64(b[24:], 1)
	binary.LittleEndian.PutUint64(b[32:], 99)
	binary.LittleEndian.PutUint64(b[40:], 6)
	binary.LittleEndian.PutUint64(b[48:], 94)
	binary.LittleEndian.PutUint64(b[72:], 2)
	binary.LittleEndian.PutUint32(b[80:], 128)
	binary.LittleEndian.PutUint32(b[84:], 128)
	fix := func() {
		binary.LittleEndian.PutUint32(b[16:], 0)
		binary.LittleEndian.PutUint32(b[16:], crc32.ChecksumIEEE(b[:92]))
	}
	fix()
	if _, e := header(b, diskBytes, 1); e != nil {
		t.Fatal(e)
	}
	b[80] ^= 1
	if _, e := header(b, diskBytes, 1); e == nil {
		t.Fatal("accepted corrupt CRC")
	}
	b[80] ^= 1
	binary.LittleEndian.PutUint64(b[72:], 5)
	fix()
	if _, e := header(b, diskBytes, 1); e == nil {
		t.Fatal("accepted GPT array overlapping usable area")
	}
}
