package main

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func packet(text string) []byte {
	b := make([]byte, 36+len(text))
	copy(b, "OAPF")
	binary.LittleEndian.PutUint32(b[4:8], uint32(len(b)))
	b[8] = 1
	copy(b[10:16], "OPEN  ")
	copy(b[16:24], "G119PFLT")
	binary.LittleEndian.PutUint32(b[24:28], 119)
	copy(b[28:32], "OPEN")
	binary.LittleEndian.PutUint32(b[32:36], 1)
	copy(b[36:], text)
	var sum byte
	for _, v := range b {
		sum += v
	}
	b[9] = 0 - sum
	return b
}
func positive(status string) string {
	s := "OPEN-ADSP-PREFLIGHT G119 version=1\ninput_sha256=" + inputSHA + "\nDSP_start=not_armed source_writes=blocked\n"
	s += "OPEN-KERNEL-FOOTPRINT G131 version=1\nK131_image_overlaps=0 failures=0\nK131_DONE queries_complete=1 PAS_allowed=0 DMA_ownership=not_proved region_writes=0\n"
	s += "reservation status=" + status + " hardware_display_ownership=not_tested\nmetadata_before status=" + status + "\n"
	for i, f := range expectedFiles {
		s += fmt.Sprintf("file %d %s bytes=%d read=%d status=%s\n", i, f.Name, f.Bytes, f.Bytes, status)
	}
	s += "files_completed=64 total=64 status=" + status + "\nmetadata_after status=" + status + "\ndisconnect status=" + status + "\nuninstall status=" + status + "\n"
	s += "read_calls=20 read_bytes=409600 requested_bytes=409600 denied_writes=0 failures=0 kept_facade=0\n"
	s += "FINAL file_status=" + status + " memory_status=" + status + " cleanup_status=" + status + " truncated=0\nDSP_start=not_armed request_count=0\n"
	return s
}
func TestPositiveNamedAndModelStatus(t *testing.T) {
	for _, s := range []string{"Success", "0"} {
		t.Run(s, func(t *testing.T) {
			r, e := decodeReport(packet(positive(s)))
			if e != nil || !r.ReportValid || !r.FilesVerified || !r.ReservationVerified || !r.CleanupComplete || r.DSPStarted || r.DisplayOwnershipQualified {
				t.Fatalf("%+v %v", r, e)
			}
		})
	}
}
func TestInvalidPackets(t *testing.T) {
	cases := map[string]func([]byte) []byte{
		"short": func(b []byte) []byte { return b[:35] }, "signature": func(b []byte) []byte { b[0] ^= 1; return b }, "length": func(b []byte) []byte { b[4]++; return b }, "checksum": func(b []byte) []byte { b[9]++; return b }, "OEM": func(b []byte) []byte { b[10] ^= 1; return b }, "revision": func(b []byte) []byte { b[8]++; return b },
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := decodeReport(f(packet(positive("Success")))); e == nil {
				t.Fatal("accepted invalid packet")
			}
		})
	}
}
func TestInvalidText(t *testing.T) {
	original := positive("Success")
	cases := map[string]string{"input": strings.Replace(original, inputSHA, strings.Repeat("0", 64), 1), "armed": strings.ReplaceAll(original, "DSP_start=not_armed", "DSP_start=armed"), "truncated": strings.Replace(original, "truncated=0", "truncated=1", 1), "duplicate_final": original + "FINAL file_status=Success memory_status=Success cleanup_status=Success truncated=0\nDSP_start=not_armed request_count=0\n", "encoding": original + "\x00", "file_order": strings.Replace(original, "file 0 ", "file 1 ", 1), "file_name": strings.Replace(original, "adsp.b00", "adsp.bad", 1), "file_size": strings.Replace(original, "bytes=1940", "bytes=1941", 1)}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := decodeReport(packet(text)); e == nil {
				t.Fatal("accepted invalid text")
			}
		})
	}
}
func TestValidFailureReports(t *testing.T) {
	cases := map[string]string{"memory": strings.Replace(positive("Success"), "memory_status=Success", "memory_status=Not Found", 1), "cleanup": strings.Replace(positive("Success"), "kept_facade=0", "kept_facade=1", 1), "file": strings.Replace(positive("Success"), "file_status=Success", "file_status=Device Error", 1), "denied_write": strings.Replace(positive("Success"), "denied_writes=0", "denied_writes=1", 1)}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			r, e := decodeReport(packet(text))
			if e != nil || !r.ReportValid {
				t.Fatalf("%v", e)
			}
			if r.FilesVerified && r.ReservationVerified && r.CleanupComplete {
				t.Fatal("promoted failure to full pass")
			}
		})
	}
}
