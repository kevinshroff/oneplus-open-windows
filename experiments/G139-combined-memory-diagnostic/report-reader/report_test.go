package main

import (
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/" + name + ".bin")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func wire(header []byte, text string) []byte {
	b := append(append([]byte(nil), header[:36]...), []byte(text)...)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	b[9] = 0
	var n byte
	for _, x := range b {
		n += x
	}
	b[9] = 0 - n
	return b
}
func changed(t *testing.T, from, to string) []byte {
	t.Helper()
	b := fixture(t, "success")
	s := string(b[36:])
	if !strings.Contains(s, from) {
		t.Fatalf("missing mutation input %q", from)
	}
	return wire(b, strings.Replace(s, from, to, 1))
}
func TestActualCFixtures(t *testing.T) {
	for _, name := range []string{"success", "cpu-pool-fail", "bad-el", "cpu-fault", "cpu-alias", "cpu-mixed-tags"} {
		t.Run(name, func(t *testing.T) {
			b := fixture(t, name)
			r, e := decodeReport(b)
			if e != nil {
				t.Fatal(e)
			}
			if !r.ReportValid || r.MemoryEligible || r.DmaOwnership || r.DspStarted || !r.QueriesComplete {
				t.Fatalf("incorrect evidence classification %+v", r)
			}
			if name == "cpu-pool-fail" {
				if r.CpuAllocated || r.CpuComplete || r.Queries != 0 {
					t.Fatal("CPU allocation failure elevated")
				}
				return
			}
			if name == "bad-el" {
				if r.CpuComplete || r.Refusal != 1 || r.El != 3 || r.Queries != 0 {
					t.Fatal("unsupported EL elevated")
				}
				return
			}
			if !r.CpuComplete || r.Pages != pages || r.Queries != 37376 || len(r.Framebuffers) != 2 {
				t.Fatal("C counters not decoded")
			}
			if name == "cpu-fault" && (r.ReadFaults != 1 || r.FirstFault.Address != 0x9e980000) {
				t.Fatal("C fault sample")
			}
			if name == "cpu-alias" && (r.WriteAliases != 1 || r.FirstAlias.Address != 0x9e980000) {
				t.Fatal("C alias sample")
			}
			if name == "cpu-mixed-tags" && (len(r.Tags) != 256 || r.TagDifferences != pages || r.FirstTagDifference.Address != 0x9e980000) {
				t.Fatal("C mixed attribute records")
			}
		})
	}
	b := fixture(t, "success")
	if _, e := decodeReport(wire(b, strings.ReplaceAll(string(b[36:]), "\n", "\r\n"))); e != nil {
		t.Fatal("native CRLF", e)
	}
	if _, e := decodeReport(fixture(t, "text-clipped")); e == nil {
		t.Fatal("truncated C report accepted")
	}
}
func TestRefusals(t *testing.T) {
	for name, pair := range map[string][2]string{
		"policy":            {"policy_end=A3280000", "policy_end=AE880000"},
		"range":             {"main=9EA00000:4880000", "main=AA000000:4880000"},
		"PAS":               {"PAS_requests=0 target_data", "PAS_requests=1 target_data"},
		"query count":       {"queries=37376", "queries=37375"},
		"counter overflow":  {"pages=18688", "pages=18446744073709551616"},
		"unsupported EL":    {"el=1 complete=1", "el=3 complete=1"},
		"histogram missing": {"P139_cpu_tag value=44 reads=18688 writes=18688\n", ""},
		"tag width":         {"value=44 reads=", "value=100 reads="},
		"histogram total":   {"reads=18688 writes=18688", "reads=18687 writes=18688"},
		"fault sample":      {"P139_cpu_first_fault address=0", "P139_cpu_first_fault address=9E980000"},
		"GOP contradiction": {"bytes=151C380 overlap=0", "bytes=151C380 overlap=1"},
		"GOP row count":     {"P139_gop_valid_rows=2", "P139_gop_valid_rows=1"},
		"GOP handle count":  {"P139_gop_status=0 count=2", "P139_gop_status=0 count=3"},
		"GOP duplicate":     {"P139_gop index=1", "P139_gop index=0"},
		"GOP overflow":      {"base=B8000000 bytes=151C380", "base=FFFFFFFFFFFFFFF8 bytes=10"},
		"bare CR":           {"CPU_not_present", "CPU_not_present"},
	} {
		t.Run(name, func(t *testing.T) {
			if name == "bare CR" {
				pair = [2]string{"P139_cpu el=1", "P139_cpu\rel=1"}
			}
			b := changed(t, pair[0], pair[1])
			if _, e := decodeReport(b); e == nil {
				t.Fatal("invalid report accepted")
			}
		})
	}
	b := fixture(t, "success")
	for name, edit := range map[string]func([]byte) []byte{
		"empty": func(b []byte) []byte { return b[:0] }, "short": func(b []byte) []byte { return b[:35] },
		"identity": func(b []byte) []byte { b[16] = 'X'; return wire(b, string(b[36:])) },
		"checksum": func(b []byte) []byte { b[9] ^= 1; return b },
		"length":   func(b []byte) []byte { b[4] ^= 1; return b },
		"duplicate CPU": func(b []byte) []byte {
			s := string(b[36:])
			line := "P139_cpu el=1 complete=1 refusal=0 pages=18688 queries=37376\n"
			return wire(b, strings.Replace(s, line, line+line, 1))
		},
		"duplicate tag": func(b []byte) []byte {
			s := string(b[36:])
			line := "P139_cpu_tag value=44 reads=18688 writes=18688\n"
			return wire(b, strings.Replace(s, line, line+line, 1))
		},
		"duplicate final": func(b []byte) []byte {
			s := string(b[36:])
			i := strings.Index(s, "G139_FINAL ")
			return wire(b, s+s[i:])
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := decodeReport(edit(append([]byte(nil), b...))); e == nil {
				t.Fatal("invalid wire data accepted")
			}
		})
	}
}
func TestOverlapStaysObservation(t *testing.T) {
	b := changed(t, "base=B8000000 bytes=151C380 overlap=0", "base=9E980000 bytes=151C380 overlap=1")
	r, e := decodeReport(b)
	if e != nil || !r.Framebuffers[0].Overlap || r.MemoryEligible || r.DmaOwnership || r.DspStarted {
		t.Fatalf("observed overlap: %v", e)
	}
}
