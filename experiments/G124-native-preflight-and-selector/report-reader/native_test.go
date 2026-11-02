package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestNativeFirmwareCRLF(t *testing.T) {
	b, err := os.ReadFile("testdata/native-G119-OAPF.bin")
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	if hex.EncodeToString(h[:]) != "44d8cead9c1ae469c31a378612cd758336e238a88f527900536219c698ffdde2" {
		t.Fatal("native fixture identity")
	}
	r, err := decodeReport(b)
	if err != nil || !r.ReportValid || !r.FilesVerified || !r.ReservationVerified || !r.CleanupComplete || r.FileRows != 64 || r.DSPStarted || r.DisplayOwnershipQualified {
		t.Fatalf("native report: %+v / %v", r, err)
	}
	if r.TableSHA256 != hex.EncodeToString(h[:]) || strings.ContainsRune(r.Text, '\r') {
		t.Fatal("raw identity or normalized text")
	}
}

func TestCRLFDoesNotHideFailure(t *testing.T) {
	text := strings.ReplaceAll(positive("Success"), "\n", "\r\n")
	text = strings.Replace(text, "file_status=Success", "file_status=Device Error", 1)
	r, err := decodeReport(packet(text))
	if err != nil || !r.ReportValid || r.FilesVerified {
		t.Fatalf("promoted native-style failure: %+v / %v", r, err)
	}
}

func TestBareCRAndOtherControlsRejected(t *testing.T) {
	for _, control := range []string{"\r", "\r\r\n", "\x00", "\t", "\x1b", "\x80"} {
		t.Run(strings.ReplaceAll(control, "\n", "LF"), func(t *testing.T) {
			text := strings.Replace(positive("Success"), "\n", control, 1)
			if _, err := decodeReport(packet(text)); err == nil {
				t.Fatal("accepted unexpected control byte")
			}
		})
	}
}
