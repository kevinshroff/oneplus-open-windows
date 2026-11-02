package main

import (
	"encoding/binary"
	"os"
	"testing"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/modeled-OPAS.bin")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func checksum(b []byte) {
	b[9] = 0
	var sum byte
	for _, v := range b {
		sum += v
	}
	b[9] = 0 - sum
}

func TestActualCModelReport(t *testing.T) {
	r, e := decodeReport(fixture(t))
	if e != nil {
		t.Fatal(e)
	}
	if !r.ReportValid || !r.MetadataVerified || !r.SCMCodeVerified || r.SCMABI != "ARMv8" || r.RequestedPasStages != 0 || r.ImagesAttempted != 2 {
		t.Fatalf("%+v", r)
	}
}

func TestRefuseCorruptionAndStaleReports(t *testing.T) {
	cases := map[string]func([]byte) []byte{
		"short":         func(b []byte) []byte { return b[:len(b)-1] },
		"long":          func(b []byte) []byte { return append(b, 0) },
		"checksum":      func(b []byte) []byte { b[100] ^= 1; return b },
		"version":       func(b []byte) []byte { b[8] = 2; checksum(b); return b },
		"OEM":           func(b []byte) []byte { b[16] = 'X'; checksum(b); return b },
		"input":         func(b []byte) []byte { b[36+248] ^= 1; checksum(b); return b },
		"config":        func(b []byte) []byte { b[36+344] ^= 1; checksum(b); return b },
		"MDT":           func(b []byte) []byte { b[36+1480] ^= 1; checksum(b); return b },
		"PAS":           func(b []byte) []byte { binary.LittleEndian.PutUint32(b[36+196:], 1); checksum(b); return b },
		"count":         func(b []byte) []byte { binary.LittleEndian.PutUint32(b[36+192:], 3); checksum(b); return b },
		"unknown-flag":  func(b []byte) []byte { binary.LittleEndian.PutUint32(b[36+184:], 0x1fff); checksum(b); return b },
		"ABI":           func(b []byte) []byte { binary.LittleEndian.PutUint32(b[36+188:], 3); checksum(b); return b },
		"header-status": func(b []byte) []byte { binary.LittleEndian.PutUint64(b[36+16+11*8:], 3); checksum(b); return b },
		"overall":       func(b []byte) []byte { binary.LittleEndian.PutUint64(b[36+16:], 1); checksum(b); return b },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := decodeReport(mut(fixture(t))); e == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestValidFailureReportStaysFailure(t *testing.T) {
	b := fixture(t)
	// Clear the main header-success bit and record its raw error. The rest of
	// the original C report remains useful; a logical failure is not success.
	f := binary.LittleEndian.Uint32(b[36+184:])
	binary.LittleEndian.PutUint32(b[36+184:], f&^(1<<8))
	binary.LittleEndian.PutUint64(b[36+16+12*8:], 3)
	binary.LittleEndian.PutUint64(b[36+16:], 0x8000000000000006)
	checksum(b)
	r, e := decodeReport(b)
	if e != nil {
		t.Fatal(e)
	}
	if !r.ReportValid || r.MetadataVerified || r.Images[1].CPUHeaderAccepted {
		t.Fatalf("%+v", r)
	}
}
