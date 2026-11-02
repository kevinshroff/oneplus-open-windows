package main

import (
	"os"
	"strings"
	"testing"
)

func TestActualG131FirmwareCRLF(t *testing.T) {
	b, e := os.ReadFile("testdata/native-G131-OAPF.bin")
	if e != nil {
		t.Fatal(e)
	}
	r, e := decodeReport(b)
	if e != nil || r.TableSHA256 != "43ed94cd9aeb40ba2b705ee6a5c4cd2b1bad3d8e2913450994e9a4ba388738a0" || !r.ReportValid || !r.FilesVerified || !r.ReservationVerified || !r.CleanupComplete || r.FileRows != 64 || r.KernelQueriesComplete || r.KernelMemoryEligible || r.DSPStarted {
		t.Fatalf("%+v %v", r, e)
	}
}
func TestCRLFDoesNotAdmitOtherControls(t *testing.T) {
	s := strings.ReplaceAll(positive("Success"), "\n", "\r\n")
	if _, e := decodeReport(packet(s)); e != nil {
		t.Fatal(e)
	}
	for _, c := range []string{"\r", "\x00", "\t", "\x7f", "\xc3\xa9"} {
		bad := strings.Replace(s, "K131_image_overlaps=0", "K131_image_overlaps="+c+"0", 1)
		if _, e := decodeReport(packet(bad)); e == nil {
			t.Fatalf("accepted %q", c)
		}
	}
}
