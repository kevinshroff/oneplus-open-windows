package main

import (
	"os"
	"strings"
	"testing"
)

func TestNativeG133CopiedHobAndScmMaps(t *testing.T) {
	b, e := os.ReadFile("testdata/native-G133-OAPF.bin")
	if e != nil {
		t.Fatal(e)
	}
	r, e := decodeReport(b)
	if e != nil {
		t.Fatal(e)
	}
	if r.TableSHA256 != "8699a32692bc16f8da269247b3585f9dbedbe103d597d29ed1ea4ed8a1170ff7" ||
		!r.ReportValid || !r.FilesVerified || !r.ReservationVerified || !r.CleanupComplete ||
		!r.KernelQueriesComplete || !r.HobStorageBounded || r.HobCount != 122 ||
		r.HobWalkedBytes != 6384 || r.HobCopiedBase != "0x00000000c5cbe018" ||
		r.HobLimit != "0x00000000c5cc3000" || !r.ScmMapsObserved ||
		r.ScmTable != "0x00000000c50c5140" || r.ScmSlot != "0x00000000c50c5178" ||
		r.ScmGCDAttributes != "0x8" || r.ScmEFIAttributes != "0x100F" {
		t.Fatalf("native G133 observations changed: %+v", r)
	}
	if r.KernelImageOverlaps != 0 || r.KernelMemoryEligible || r.ScmHookEligible ||
		r.DisplayOwnershipQualified || r.DSPStarted {
		t.Fatal("native inventory was promoted into ownership, hook or DSP eligibility")
	}
}

func TestRejectPreviousG131Firmware(t *testing.T) {
	b, e := os.ReadFile("testdata/native-G131-OAPF.bin")
	if e != nil {
		t.Fatal(e)
	}
	if _, e := decodeReport(b); e == nil {
		t.Fatal("accepted prior G131 inventory without G133 copy bounds")
	}
}
func TestCRLFDoesNotAdmitOtherControls(t *testing.T) {
	s := strings.ReplaceAll(positive("Success"), "\n", "\r\n")
	if _, e := decodeReport(packet(s)); e != nil {
		t.Fatal(e)
	}
	for _, c := range []string{"\r", "\x00", "\t", "\x7f", "\xc3\xa9"} {
		bad := strings.Replace(s, "K133_image_overlaps=0", "K133_image_overlaps="+c+"0", 1)
		if _, e := decodeReport(packet(bad)); e == nil {
			t.Fatalf("accepted %q", c)
		}
	}
}
