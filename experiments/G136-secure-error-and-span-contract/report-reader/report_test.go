package main

import (
	"encoding/binary"
	"os"
	"testing"
)

func pair(t *testing.T, name string) ([]byte, []byte) {
	t.Helper()
	a, e := os.ReadFile("testdata/" + name + "-DSP.bin")
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile("testdata/" + name + "-OSER.bin")
	if e != nil {
		t.Fatal(e)
	}
	return a, b
}
func combined(a, b []byte) (Report, error) {
	d, e := decodeReport(a)
	if e != nil {
		return d, e
	}
	s, e := decodeScmLog(b)
	if e != nil {
		return d, e
	}
	return bindScmLog(d, s)
}
func checksum(b []byte) {
	b[9] = 0
	var sum byte
	for _, v := range b {
		sum += v
	}
	b[9] = 0 - sum
}
func put32(b []byte, at int, v uint32) { binary.LittleEndian.PutUint32(b[36+at:], v) }
func put64(b []byte, at int, v uint64) { binary.LittleEndian.PutUint64(b[36+at:], v) }
func TestActualCWire(t *testing.T) {
	a, b := pair(t, "error-mem")
	r, e := combined(a, b)
	if e != nil {
		t.Fatal(e)
	}
	if !r.ReportValid || r.MemorySetupAccepted || r.DiagnosticStop || r.SequenceAccepted || r.AuthEntered != 0 || r.AuthAccepted != 0 || r.EnteredStages != 2 || r.SCMError == nil || !r.SCMError.Raw32Qualified || r.SCMError.FullX0Qualified || r.SCMError.Records[0].Signed32 != -2 || r.SCMError.OriginalCalls != 2 {
		t.Fatalf("bad original-C interpretation: %+v", r)
	}
	if r.DSPRunning || r.GlinkReady || r.ChargingQualified {
		t.Fatal("diagnostic promoted peripheral readiness")
	}
}
func TestAcceptedMemoryStopsBeforeStart(t *testing.T) {
	a, b := pair(t, "success")
	r, e := combined(a, b)
	if e != nil {
		t.Fatal(e)
	}
	if !r.MemorySetupAccepted || !r.DiagnosticStop || r.SequenceAccepted || r.AuthEntered != 0 || r.AuthAccepted != 0 || r.SCMError.Count != 0 || r.SCMError.Raw32Qualified || !r.SCMError.DiagnosticStop {
		t.Fatalf("bad diagnostic stop: %+v", r)
	}
}
func TestEarlyRefusalAndFatalRestore(t *testing.T) {
	for _, name := range []string{"source-refused", "serial-fatal"} {
		t.Run(name, func(t *testing.T) {
			a, b := pair(t, name)
			r, e := combined(a, b)
			if e != nil {
				t.Fatal(e)
			}
			if name == "source-refused" {
				if r.EnteredStages != 0 || r.SCMError.OriginalCalls != 0 || r.SCMError.Raw32Qualified {
					t.Fatal(r)
				}
			} else if !r.FatalRestore || !r.SCMError.FatalRestore || !r.SCMError.Raw32Qualified {
				t.Fatal("fatal restoration hidden")
			}
		})
	}
}
func TestRejectContradictorySerialReports(t *testing.T) {
	for _, kind := range []string{"short", "checksum", "identity", "body-size", "body-magic", "count", "matched", "active", "pending", "reserved", "cache", "method", "low-stack", "record-command", "record-index", "record-api", "unobserved-bytes", "original-calls", "stop", "restored"} {
		t.Run(kind, func(t *testing.T) {
			a, b := pair(t, "error-mem")
			fix := true
			switch kind {
			case "short":
				b = b[:len(b)-1]
				fix = false
			case "checksum":
				b[100] ^= 1
				fix = false
			case "identity":
				b[16] ^= 1
			case "body-size":
				put32(b, 0, 264)
			case "body-magic":
				b[36+8] ^= 1
			case "count":
				put32(b, 120, 5)
			case "matched":
				put32(b, 104, 0)
			case "active":
				put32(b, 112, 1)
			case "pending":
				put32(b, 116, 0x42000202)
			case "reserved":
				put32(b, 140, 1)
			case "cache":
				put64(b, 24, binary.LittleEndian.Uint64(b[36+24:])+8)
			case "method":
				put64(b, 64, binary.LittleEndian.Uint64(b[36+64:])+4)
			case "low-stack":
				put64(b, 72, 0xc7b7000)
			case "record-command":
				put32(b, 144, 0x42000205)
			case "record-index":
				put32(b, 144+8, 2)
			case "record-api":
				put64(b, 144+16, 0x8000000000000003)
			case "unobserved-bytes":
				b[36+144+32] = 1
			case "original-calls":
				put32(b, 136, 1)
			case "stop":
				put32(b, 124, 1)
			case "restored":
				put64(b, 56, 0x8000000000000007)
				put32(b, 92, 1)
			}
			if fix {
				checksum(b)
			}
			if _, e := combined(a, b); e == nil {
				t.Fatal("accepted contradiction", kind)
			}
		})
	}
}
func TestMissingOrInconsistentErrorTextIsRetained(t *testing.T) {
	for _, kind := range []string{"missing", "zero", "positive", "mapping"} {
		t.Run(kind, func(t *testing.T) {
			a, b := pair(t, "error-mem")
			switch kind {
			case "missing":
				put32(b, 120, 0)
				put32(b, 104, 0)
				put32(b, 108, 1)
				put32(b, 128, 8)
				for i := 36 + 144; i < len(b); i++ {
					b[i] = 0
				}
			case "zero":
				put32(b, 144+4, 0)
			case "positive":
				put32(b, 144+4, 1)
			case "mapping":
				put32(b, 144+4, 0xffffffff)
			}
			checksum(b)
			r, e := combined(a, b)
			if e != nil {
				t.Fatal(e)
			}
			if r.SCMError.Raw32Qualified || !r.SCMError.ReportValid || r.SCMError.RawTableBase64 == "" {
				t.Fatal("bad raw evidence retention")
			}
		})
	}
}
func TestRejectForbiddenOrContradictoryPasLedger(t *testing.T) {
	for _, kind := range []string{"auth", "main", "auth-mask", "phase", "request-count", "record-count", "fault", "CPU", "restoration"} {
		t.Run(kind, func(t *testing.T) {
			a, b := pair(t, "error-mem")
			switch kind {
			case "auth":
				put32(a, 208+96, 0x42000205)
			case "main":
				put32(a, 208+96+8, 1)
			case "auth-mask":
				put32(a, 184, 1)
			case "phase":
				put32(a, 176, 3)
			case "request-count":
				put32(a, 164, 2)
			case "record-count":
				put32(a, 168, 17)
			case "fault":
				put32(a, 172, 1024)
			case "CPU":
				put64(a, 128, 37377)
			case "restoration":
				put64(a, 72, 0x8000000000000007)
			}
			checksum(a)
			if _, e := combined(a, b); e == nil {
				t.Fatal("accepted contradictory PAS ledger")
			}
		})
	}
}
