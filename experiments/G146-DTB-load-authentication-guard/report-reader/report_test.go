package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
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
func TestAllActualCReports(t *testing.T) {
	names, e := filepath.Glob("testdata/*-DSP.bin")
	if e != nil || len(names) != 72 {
		t.Fatal(len(names), e)
	}
	for _, path := range names {
		name := strings.TrimSuffix(filepath.Base(path), "-DSP.bin")
		t.Run(name, func(t *testing.T) {
			a, b := pair(t, name)
			r, e := combined(a, b)
			if e != nil {
				t.Fatal(e)
			}
			if !r.ReportValid || r.SCMError == nil || !r.SCMError.ReportValid || !r.StopBeforeMain || r.DSPRunning || r.GlinkReady || r.ChargingQualified || r.Dtb.GlobalDmaQualified || r.Dtb.ProductionPowerLease {
				t.Fatal("diagnostic promoted peripheral qualification", r)
			}
		})
	}
}
func TestDtbSuccessAndLateFailureAreSeparate(t *testing.T) {
	for _, name := range []string{"success", "loader-POST-failure"} {
		t.Run(name, func(t *testing.T) {
			a, b := pair(t, name)
			r, e := combined(a, b)
			if e != nil {
				t.Fatal(e)
			}
			if !r.MemorySetupAccepted || !r.SequenceAccepted || r.AuthEntered != 1 || r.AuthAccepted != 1 || r.EnteredStages != 3 || !r.Dtb.FiniteAdmissionComplete || r.SCMError.OriginalCalls != 3 {
				t.Fatal("lost accepted DTB evidence", r)
			}
			if r.DtbPublicSuccess != (name == "success") || r.DiagnosticStop != (name == "success") {
				t.Fatal("public/secure outcomes conflated", r)
			}
		})
	}
}
func TestDeniedCopyOrPayloadNeverAuthenticates(t *testing.T) {
	for _, name := range []string{"copy-admission-refused", "payload-admission-refused", "loader-PRE-failure", "loader-segment-failure"} {
		t.Run(name, func(t *testing.T) {
			a, b := pair(t, name)
			r, e := combined(a, b)
			if e != nil {
				t.Fatal(e)
			}
			if !r.MemorySetupAccepted || r.SequenceAccepted || r.AuthEntered != 0 || r.AuthAccepted != 0 || r.DtbPublicSuccess || r.DiagnosticStop || r.SCMError.OriginalCalls != 2 {
				t.Fatal("denied boundary authenticated", r)
			}
		})
	}
}
func TestAuthErrorTextBindsToAuthRecord(t *testing.T) {
	a, b := pair(t, "error-auth")
	r, e := combined(a, b)
	if e != nil {
		t.Fatal(e)
	}
	if r.AuthEntered != 1 || r.AuthAccepted != 0 || r.SequenceAccepted || !r.Dtb.FiniteAdmissionComplete || !r.SCMError.Raw32Qualified || r.SCMError.FullX0Qualified || r.SCMError.Records[0].Sequence != 2 || r.SCMError.Records[0].Command != 0x42000205 || r.SCMError.Records[0].Signed32 != -2 {
		t.Fatal(r)
	}
}
func TestRejectContradictoryDtbClaims(t *testing.T) {
	for _, kind := range []string{"short", "identity", "old-magic", "body-size", "count", "main", "shutdown", "order", "auth-param", "auth-argument", "auth-mask", "phase", "fault", "CPU", "CPU-tag", "CPU-page", "restoration", "unused-ledger", "admission-size", "copy-count", "copy-denied", "hash-outcome", "digest", "posthash-map", "posthash-clock", "posthash-Demura", "check-status", "check-incomplete", "check-query", "check-version", "outer-main", "outer-return", "outer-public", "outer-reserved", "load-status"} {
		t.Run(kind, func(t *testing.T) {
			a, b := pair(t, "success")
			switch kind {
			case "short":
				a = a[:len(a)-1]
			case "identity":
				a[16] ^= 1
			case "old-magic":
				a[36+8] ^= 1
			case "body-size":
				put32(a, 0, 1744)
			case "count":
				put32(a, 168, 17)
			case "main":
				put32(a, 208+192+8, 1)
			case "shutdown":
				put32(a, 208+192, 0x42000206)
			case "order":
				put32(a, 208+96, 0x42000201)
			case "auth-param":
				put32(a, 208+192+4, 3)
			case "auth-argument":
				put64(a, 208+192+24, 1)
			case "auth-mask":
				put32(a, 184, 0)
			case "phase":
				put32(a, 176, 2)
			case "fault":
				put32(a, 172, 4096)
			case "CPU":
				put64(a, 128, 37377)
			case "CPU-tag":
				put64(a, 144, 0xff000000a327f000)
			case "CPU-page":
				put64(a, 152, 0x440000009e980000)
			case "restoration":
				put64(a, 72, 0x8000000000000007)
			case "unused-ledger":
				a[36+208+288] = 1
			case "admission-size":
				put32(a, 1744, 384)
			case "copy-count":
				put32(a, 1744+8, 2)
			case "copy-denied":
				put32(a, 1744+16, 0)
			case "hash-outcome":
				put32(a, 1744+28, 2)
			case "digest":
				a[36+1744+360] ^= 1
			case "posthash-map":
				put64(a, 1744+48+208+48, 0xff0000009e982000)
			case "posthash-clock":
				put32(a, 1744+48+208+64, 0)
			case "posthash-Demura":
				put32(a, 1744+48+208+84, 1)
			case "check-status":
				put64(a, 1744+48, 0x8000000000000007)
			case "check-incomplete":
				put32(a, 1744+48+100, 0)
			case "check-query":
				put64(a, 1744+48+24, 10)
			case "check-version":
				put32(a, 1744+48+80, 0x90000000)
			case "outer-main":
				put32(a, 2136, 0)
			case "outer-return":
				put32(a, 2140, 0)
			case "outer-public":
				put32(a, 2144, 0)
			case "outer-reserved":
				put32(a, 2148, 1)
			case "load-status":
				put64(a, 56, 0x8000000000000007)
			}
			if kind != "short" {
				checksum(a)
			}
			if _, e := combined(a, b); e == nil {
				t.Fatal("accepted contradiction", kind)
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
