package main

import (
	"fmt"
	"os"
	"testing"
)

func captureFixture(t *testing.T) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/success.bin")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestActualCWinPECapture(t *testing.T) {
	b := captureFixture(t)
	r, e := decodeCapture(b, 123)
	if e != nil {
		t.Fatal(e)
	}
	m := r["telemetry"].(map[string]any)
	if m["state_first"] != "DISABLED" || m["float_voltage_mV"] != uint32(4470) || m["APSD_type"] != "SDP" {
		t.Fatal(m)
	}
}
func TestDamagedSuccess(t *testing.T) {
	for _, at := range []int{0, 4, 8, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 80, 88, 92, 96, 100, 120, 124, 136, 140, 144, 148, 152, 156, 160, 164, 184, 188, 192, 196, 200, 204, 208, 212, 216, 220, 224, 228, 232, 236, 240, 244, 248, 252, 256, 260, 264, 268, 272, 276, 280, 284, 288, 292, 296, 300, 304, 308, 312, 316, 320, 324, 328, 332, 344, 348, 352, 356} {
		t.Run(fmt.Sprint(at), func(t *testing.T) {
			b := captureFixture(t)
			b[at] ^= 0xff
			if _, e := decodeCapture(b, 123); e == nil {
				t.Fatalf("accepted changed field at %d", at)
			}
		})
	}
}
func TestUncertainReadRetained(t *testing.T) {
	b := captureFixture(t)
	le.PutUint32(b[124:], 6)
	le.PutUint32(b[148:], 1)
	le.PutUint32(b[332:], 15)
	r, e := decodeCapture(b, 123)
	if e != nil {
		t.Fatal(e)
	}
	if r["uncertain_read"] != true {
		t.Fatal(r)
	}
	if _, yes := r["telemetry"]; yes {
		t.Fatal("failure interpreted as telemetry")
	}
}
func TestCaptureTruncationAndNonce(t *testing.T) {
	b := captureFixture(t)
	for _, n := range []int{0, 79, 80, 119, 999} {
		if _, e := decodeCapture(b[:n], 123); e == nil {
			t.Fatal(n)
		}
	}
	if _, e := decodeCapture(b, 124); e == nil {
		t.Fatal("nonce")
	}
}
