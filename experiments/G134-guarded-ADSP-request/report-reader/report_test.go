package main

import (
	"encoding/base64"
	"encoding/binary"
	"os"
	"testing"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/modeled-OADP.bin")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func checksum(b []byte) {
	b[9] = 0
	var sum byte
	for _, c := range b {
		sum += c
	}
	b[9] = 0 - sum
}
func put32(b []byte, n int, v uint32) { binary.LittleEndian.PutUint32(b[36+n:], v) }
func put64(b []byte, n int, v uint64) { binary.LittleEndian.PutUint64(b[36+n:], v) }
func TestActualAdapterCWire(t *testing.T) {
	b := fixture(t)
	r, e := decodeReport(b)
	if e != nil {
		t.Fatal(e)
	}
	if !r.SequenceAccepted || r.RecordCount != 6 || r.EnteredStages != 6 || r.ReturnedStages != 6 || r.CpuPages != 18689 || r.HookStores != 2 || r.DSPRunning || r.GlinkReady || r.ChargingQualified {
		t.Fatalf("C wire facts: %+v", r)
	}
	raw, e := base64.StdEncoding.DecodeString(r.RawTableBase64)
	if e != nil || string(raw) != string(b) {
		t.Fatal("raw bytes not preserved")
	}
}
func TestNativeServiceFailureIsNotTransportSuccess(t *testing.T) {
	b := fixture(t)
	put32(b, 160, 2047&^(512|1024))
	put64(b, 80, 0x8000000000000007)
	put64(b, 16+6*8, 0x8000000000000001)
	put32(b, 172, 32)
	put32(b, 180, 2)
	put32(b, 188, 1)
	last := 208 + 5*96
	put64(b, last+56, 0xfffffffffffffff9)
	put64(b, last+80, 0x8000000000000007)
	put32(b, last+92, 32)
	checksum(b)
	r, e := decodeReport(b)
	if e != nil {
		t.Fatal(e)
	}
	if r.SequenceAccepted || r.DSPRunning || r.GlinkReady || r.ChargingQualified || r.AuthEntered != 3 || r.AuthAccepted != 1 || r.Records[5].OriginalStatus != 0 || r.Records[5].Results[1] != 0xfffffffffffffff9 {
		t.Fatalf("partial/failure interpretation: %+v", r)
	}
}
func TestRefusalReportDoesNotRequireAPASAttempt(t *testing.T) {
	b := fixture(t)
	for i := 36; i < len(b); i++ {
		b[i] = 0
	}
	put32(b, 0, bodyBytes)
	put32(b, 4, 1)
	copy(b[44:52], "G134DSP1")
	for i := 0; i < 8; i++ {
		put64(b, 16+i*8, 0x8000000000000006)
	}
	put64(b, 80, 0x8000000000000006)
	checksum(b)
	r, e := decodeReport(b)
	if e != nil || r.SequenceAccepted || r.RecordCount != 0 {
		t.Fatalf("refusal %v %+v", e, r)
	}
}
func TestSuccessStatusAloneDoesNotClaimSequence(t *testing.T) {
	b := fixture(t)
	put64(b, 80, 0)
	put32(b, 160, 7)
	put32(b, 164, 0)
	put32(b, 168, 0)
	put32(b, 176, 0)
	put32(b, 180, 0)
	put32(b, 184, 0)
	put32(b, 188, 0)
	for n := 36 + 208; n < len(b); n++ {
		b[n] = 0
	}
	checksum(b)
	r, e := decodeReport(b)
	if e != nil || r.SequenceAccepted || r.DSPRunning {
		t.Fatalf("raw success promoted: %v %+v", e, r)
	}
}
func TestCorruptOrContradictoryReports(t *testing.T) {
	cases := map[string]func([]byte){
		"OEM": func(b []byte) { b[10] = 'X' }, "version": func(b []byte) { put32(b, 4, 2) }, "body_size": func(b []byte) { put32(b, 0, bodyBytes-8) }, "magic": func(b []byte) { b[44] = 0 },
		"count": func(b []byte) { put32(b, 168, 17) }, "unknown_flag": func(b []byte) { put32(b, 160, 4095) }, "CPU": func(b []byte) { put64(b, 128, 0) },
		"restore": func(b []byte) { put64(b, 72, 1) }, "fatal": func(b []byte) { put32(b, 204, 1) }, "entry": func(b []byte) { put32(b, 208+12, 0) },
		"accepted_mask": func(b []byte) { put32(b, 184, 1) }, "old_memory": func(b []byte) { put64(b, 208+96+24, 0x9e980000) },
		"transport": func(b []byte) { put64(b, 208+5*96+40, 0x8000000000000007) }, "unused_ledger": func(b []byte) { b[36+208+6*96] = 1 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			b := fixture(t)
			change(b)
			checksum(b)
			if _, e := decodeReport(b); e == nil {
				t.Fatal("accepted corrupted/contradictory packet")
			}
		})
	}
	for _, n := range []int{0, 4, 36, 100, bodyBytes + 35} {
		if _, e := decodeReport(fixture(t)[:n]); e == nil {
			t.Fatalf("accepted length %d", n)
		}
	}
	b := fixture(t)
	b[len(b)-1] ^= 1
	if _, e := decodeReport(b); e == nil {
		t.Fatal("accepted invalid checksum")
	}
}
