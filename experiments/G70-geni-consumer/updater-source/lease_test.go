package main

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestRAMGuardAgainstObservedPhysicalRoots(t *testing.T) {
	for _, s := range []string{`\Device\HarddiskVolume6`, `\Device\HarddiskVolume40`, `\Device\RamdiskFake`, `\Device\Ramdisk{d9b257fc-684e-4dcb-ab79-03cfa2f6b750}\Windows`, `\Device\Ramdisk{d9b257fc684e4dcbab7903cfa2f6b750}`, `\Device\Ramdisk{d9b257fc-684e-4dcb-ab79-03cfa2f6b75z}`} {
		if validRAMDevice(s) {
			t.Fatalf("accepted non-RAM system device %q", s)
		}
	}
	for _, s := range []string{`\Device\Ramdisk{d9b257fc-684e-4dcb-ab79-03cfa2f6b750}`, `\DEVICE\RAMDISK{D9B257FC-684E-4DCB-AB79-03CFA2F6B750}`} {
		if !validRAMDevice(s) {
			t.Fatalf("rejected captured RAM device %q", s)
		}
	}
}
func volumeFixture() ([]byte, []byte) {
	i, e := make([]byte, 144), make([]byte, 32)
	binary.LittleEndian.PutUint32(i, 1)
	binary.LittleEndian.PutUint64(i[8:], 35684352)
	binary.LittleEndian.PutUint64(i[16:], 18253611008)
	binary.LittleEndian.PutUint32(i[24:], 6)
	a, _ := hex.DecodeString("a2a0d0ebe5b9334487c068b6b72699c7")
	copy(i[32:], a)
	a, _ = hex.DecodeString("1e51681caf28c9a8dd6fe3303d568c04")
	copy(i[48:], a)
	for n, c := range "super" {
		binary.LittleEndian.PutUint16(i[72+2*n:], uint16(c))
	}
	binary.LittleEndian.PutUint32(e, 1)
	binary.LittleEndian.PutUint32(e[8:], 0)
	binary.LittleEndian.PutUint64(e[16:], 35684352)
	binary.LittleEndian.PutUint64(e[24:], 18253611008)
	return i, e
}
func TestRejectForeignAndAmbiguousVolumes(t *testing.T) {
	i, e := volumeFixture()
	target := targets["super"]
	if x := verifySuperVolume(i, e, target, 0, 6); x != nil {
		t.Fatal(x)
	}
	for _, at := range []int{0, 8, 16, 24, 32, 48, 72} {
		b := append([]byte(nil), i...)
		b[at] ^= 1
		if verifySuperVolume(b, e, target, 0, 6) == nil {
			t.Fatalf("accepted changed partition identity field at%d", at)
		}
	}
	for _, at := range []int{0, 8, 16, 24} {
		b := append([]byte(nil), e...)
		b[at] ^= 1
		if verifySuperVolume(i, b, target, 0, 6) == nil {
			t.Fatalf("accepted changed extent field at%d", at)
		}
	}
	for n := 0; n < 144; n++ {
		if verifySuperVolume(i[:n], e, target, 0, 6) == nil {
			t.Fatal("accepted short partition buffer")
		}
	}
	for n := 0; n < 32; n++ {
		if verifySuperVolume(i, e[:n], target, 0, 6) == nil {
			t.Fatal("accepted short extent buffer")
		}
	}
	if verifySuperVolume(i, e, targets["userdata"], 0, 6) == nil {
		t.Fatal("userdata accepted as source volume")
	}
	if verifySuperVolume(i, e, target, 4, 6) == nil {
		t.Fatal("accepted modem disk number")
	}
}
