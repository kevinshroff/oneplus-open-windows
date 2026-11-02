package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func capturedHeaderShape() []byte {
	b := make([]byte, 4096)
	copy(b, "ANDROID!")
	binary.LittleEndian.PutUint32(b[8:], 2257036)
	binary.LittleEndian.PutUint32(b[20:], 1580)
	binary.LittleEndian.PutUint32(b[40:], 3)
	return b
}
func TestFirmwareContainerBounds(t *testing.T) {
	b := capturedHeaderShape()
	if e := validateBootHeader(b, 16<<20); e != nil {
		t.Fatal(e)
	}
	for _, n := range []int{0, 7, 511, 4095} {
		if validateBootHeader(b[:n], 16<<20) == nil {
			t.Fatal("accepted truncated header")
		}
	}
	for _, at := range []int{0, 12, 20, 24, 40} {
		x := bytes.Clone(b)
		x[at] ^= 1
		if validateBootHeader(x, 16<<20) == nil {
			t.Fatalf("accepted incompatible header field%d", at)
		}
	}
	for _, n := range []uint32{0, 16 << 20, 0xffffffff} {
		x := bytes.Clone(b)
		binary.LittleEndian.PutUint32(x[8:], n)
		if validateBootHeader(x, 16<<20) == nil {
			t.Fatal("accepted invalid payload size")
		}
	}
}
func TestBootPatchCannotTargetProtectedPartitions(t *testing.T) {
	_, p, _ := patchFixture()
	p.Version = 2
	p.Target = "boot_a"
	p.PrefixBytes = 16 << 20
	if e := validatePatch(p); e != nil {
		t.Fatal(e)
	}
	for _, target := range []string{"boot_b", "super", "userdata", "xbl_a", "abl_a"} {
		q := p
		q.Target = target
		if validatePatch(q) == nil {
			t.Fatalf("accepted boot patch for%s", target)
		}
	}
	for _, n := range []uint64{0, 4096, (16 << 20) - 4096, (16 << 20) + 4096, 201326592} {
		q := p
		q.PrefixBytes = n
		if validatePatch(q) == nil {
			t.Fatal("accepted wrong boot window")
		}
	}
	q := p
	q.Version = 1
	if validatePatch(q) == nil {
		t.Fatal("old version accepted boot target")
	}
}
