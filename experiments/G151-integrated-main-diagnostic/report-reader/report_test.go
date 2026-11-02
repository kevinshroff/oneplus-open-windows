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
func TestActualAdapterReports(t *testing.T) {
	paths, e := filepath.Glob("testdata/*-DSP.bin")
	if e != nil || len(paths) != 96 {
		t.Fatal(len(paths), e)
	}
	for _, p := range paths {
		name := strings.TrimSuffix(filepath.Base(p), "-DSP.bin")
		t.Run(name, func(t *testing.T) {
			a, b := pair(t, name)
			r, e := combined(a, b)
			if e != nil {
				t.Fatal(e)
			}
			if !r.ReportValid || r.SCMError == nil || !r.SCMError.ReportValid || !r.MainEnabled || r.DSPRunning || r.GlinkReady || r.ChargingQualified || r.Dtb.GlobalDmaQualified || r.Dtb.ProductionPowerLease || r.Main.GlobalDmaQualified || r.Main.ProductionPowerLease {
				t.Fatal("diagnostic promoted peripheral/ownership qualification")
			}
		})
	}
}
func TestPublicAndSecureOutcomesRemainSeparate(t *testing.T) {
	for _, name := range []string{"success", "loader-POST-failure", "main-loader-POST-failure", "main-error-auth"} {
		t.Run(name, func(t *testing.T) {
			a, b := pair(t, name)
			r, e := combined(a, b)
			if e != nil {
				t.Fatal(e)
			}
			if !r.DtbSequenceAccepted || r.DtbPublicSuccess != (name != "loader-POST-failure") || r.DtbPublicComplete != (name != "loader-POST-failure") {
				t.Fatal("lost DTB result", r)
			}
			if r.MainPublicSuccess != (name == "success") || r.DiagnosticStop != (name == "success") {
				t.Fatal("public result promoted", r)
			}
			if name == "main-loader-POST-failure" && (!r.SequenceAccepted || r.AuthAccepted != 3 || !r.Payload.Complete) {
				t.Fatal("lost accepted main evidence", r)
			}
			if name == "main-error-auth" {
				s := r.SCMError
				if !s.Raw32Qualified || s.FullX0Qualified || len(s.Records) != 1 || s.Records[0].Image != 1 || s.Records[0].Sequence != 5 || s.Records[0].Signed32 != -2 {
					t.Fatal("main error not cross-bound", s)
				}
			}
		})
	}
}
func TestLateRefusalsDoNotAuthenticate(t *testing.T) {
	for _, name := range []string{"main-post-AT", "main-post-demura", "main-hash-last", "main-zero-last", "main-owner-after-read"} {
		t.Run(name, func(t *testing.T) {
			a, b := pair(t, name)
			r, e := combined(a, b)
			if e != nil {
				t.Fatal(e)
			}
			if r.AuthEntered != 1 || r.AuthAccepted != 1 || r.MainPublicSuccess || r.SequenceAccepted || r.Payload.Complete || r.EnteredStages != 5 {
				t.Fatal("refusal authenticated", r)
			}
			if strings.HasPrefix(name, "main-post-") && (r.Payload.VerifiedBytes != 64910785 || r.Payload.Fault != 128 || r.Main.AcceptedRefreshes != 1) {
				t.Fatal("lost matched bytes before late refusal", r)
			}
		})
	}
}
func TestRejectMainCompletionContradictions(t *testing.T) {
	kinds := []string{"short", "checksum", "identity", "old-revision", "old-body", "unknown-fault", "main-image", "main-order", "shutdown", "main-base", "main-size", "main-auth-param", "main-auth-mask", "source-flag", "source-status", "unused-ledger", "main-enabled", "DTB-return", "DTB-public", "DTB-marker", "DTB-marker-status", "main-return", "main-public", "outer-reserved", "main-ABI", "copy-grant", "refresh-count", "refresh-fault", "last-CPU-page", "CPU-queries", "CPU-tag", "final-demura", "final-clock", "payload-ABI", "payload-attempt", "payload-complete", "payload-read-bytes", "payload-verified-bytes", "payload-phase", "payload-reserved", "payload-read-count", "payload-owner-count", "extent-identity", "extent-kind", "extent-complete", "extent-digest", "extent-read-bytes", "main-load-status", "final-status", "restore-status"}
	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			a, b := pair(t, "success")
			p := 2544
			m := 2176
			switch kind {
			case "short":
				a = a[:len(a)-1]
			case "checksum":
				a[100] ^= 1
			case "identity":
				a[16] ^= 1
			case "old-revision":
				binary.LittleEndian.PutUint32(a[24:], 146)
			case "old-body":
				put32(a, 0, 2152)
			case "unknown-fault":
				put32(a, 172, 8192)
			case "main-image":
				put32(a, 208+3*96+8, 36)
			case "main-order":
				put32(a, 208+4*96, 0x42000201)
			case "shutdown":
				put32(a, 208+5*96, 0x42000206)
			case "main-base":
				put64(a, 208+4*96+24, 0x9e980000)
			case "main-size":
				put64(a, 208+4*96+32, 0x80000)
			case "main-auth-param":
				put32(a, 208+5*96+4, 3)
			case "main-auth-mask":
				put32(a, 188, 1)
			case "source-flag":
				put32(a, 160, 254)
			case "source-status":
				put64(a, 16, 7)
			case "unused-ledger":
				a[36+208+6*96] = 1
			case "main-enabled":
				put32(a, 2136, 0)
			case "DTB-return":
				put32(a, 2140, 0)
			case "DTB-public":
				put32(a, 2144, 0)
			case "DTB-marker":
				put32(a, 2148, 0)
			case "DTB-marker-status":
				put64(a, 2152, 7)
			case "main-return":
				put32(a, 2160, 0)
			case "main-public":
				put32(a, 2164, 0)
			case "outer-reserved":
				put32(a, 2168, 1)
			case "main-ABI":
				put32(a, m, 392)
			case "copy-grant":
				put32(a, m+16, 0)
			case "refresh-count":
				put32(a, m+12, 1)
			case "refresh-fault":
				put32(a, m+24, 4)
			case "last-CPU-page":
				put64(a, m+56+208+40, 0x44000000a327f000)
			case "CPU-queries":
				put64(a, m+56+208+24, 31706)
			case "CPU-tag":
				put64(a, m+56+208+48, 0xff000000a2836000)
			case "final-demura":
				put32(a, m+56+208+88, 1)
			case "final-clock":
				put32(a, m+56+208+72, 0)
			case "payload-ABI":
				put32(a, p, 6535)
			case "payload-attempt":
				put32(a, p+8, 0)
			case "payload-complete":
				put32(a, p+12, 0)
			case "payload-read-bytes":
				put64(a, p+24, 64910784)
			case "payload-verified-bytes":
				put64(a, p+32, 64910784)
			case "payload-phase":
				put32(a, p+112, 3)
			case "payload-reserved":
				put32(a, p+116, 1)
			case "payload-read-count":
				put32(a, p+84, 15887)
			case "payload-owner-count":
				put32(a, p+88, 31779)
			case "extent-identity":
				put32(a, p+128, 1)
			case "extent-kind":
				put32(a, p+128+4, 2)
			case "extent-complete":
				put32(a, p+128+8, 0)
			case "extent-digest":
				a[36+p+128+40] ^= 1
			case "extent-read-bytes":
				put64(a, p+128+24, 0)
			case "main-load-status":
				put64(a, 64, 0x8000000000000007)
			case "final-status":
				put64(a, 80, 0)
			case "restore-status":
				put64(a, 72, 7)
			}
			if kind != "short" && kind != "checksum" {
				checksum(a)
			}
			if _, e := combined(a, b); e == nil {
				t.Fatal("accepted contradiction", kind)
			}
		})
	}
}
func TestRejectMainErrorMisbindings(t *testing.T) {
	for _, kind := range []string{"short", "checksum", "old-magic", "old-body", "image", "reserved", "sequence", "api", "active", "pending", "unused", "calls", "fatal"} {
		t.Run(kind, func(t *testing.T) {
			a, b := pair(t, "main-error-auth")
			switch kind {
			case "short":
				b = b[:len(b)-1]
			case "checksum":
				b[100] ^= 1
			case "old-magic":
				copy(b[36+8:], "G136LOG1")
			case "old-body":
				put32(b, 0, 272)
			case "image":
				put32(b, 144+16, 36)
			case "reserved":
				put32(b, 144+20, 1)
			case "sequence":
				put32(b, 144+8, 2)
			case "api":
				put64(b, 144+24, 3)
			case "active":
				put32(b, 112, 1)
			case "pending":
				put32(b, 116, 0x42000205)
			case "unused":
				b[36+144+40] = 1
			case "calls":
				put32(b, 136, 5)
			case "fatal":
				put32(b, 92, 1)
			}
			if kind != "short" && kind != "checksum" {
				checksum(b)
			}
			if _, e := combined(a, b); e == nil {
				t.Fatal("accepted serial contradiction", kind)
			}
		})
	}
}

func TestRestorationAndUnusedArguments(t *testing.T) {
	for _, kind := range []string{"root-fatal", "restored-flag", "INIT-unused-argument"} {
		t.Run(kind, func(t *testing.T) {
			name := "main-error-auth"
			if kind == "root-fatal" {
				name = "main-owner-after-read"
			}
			a, b := pair(t, name)
			switch kind {
			case "root-fatal":
				put32(a, 204, 0)
			case "restored-flag":
				put32(a, 160, 127)
			case "INIT-unused-argument":
				put64(a, 208+3*96+32, 1)
			}
			checksum(a)
			if _, e := combined(a, b); e == nil {
				t.Fatal("accepted restoration/argument contradiction")
			}
		})
	}
}
