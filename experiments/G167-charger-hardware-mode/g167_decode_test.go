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
	if m["state_first"] != "DISABLED" || m["float_voltage_mV"] != uint32(4470) || m["APSD_type"] != "SDP" || m["FV_callback_halves_input"] != false || m["cell_mode_bits"] != uint32(0x40) {
		t.Fatal(m)
	}
}
func TestDamagedSuccess(t *testing.T) {
	atList := []int{0, 4, 8, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 80, 88, 92, 96, 100, 120, 124, 136, 140, 144, 148, 152, 156, 160, 164}
	for i := 0; i < 19; i++ {
		atList = append(atList, 336+i*40, 340+i*40, 344+i*40, 348+i*40, 372+i*40)
	}
	for _, at := range atList {
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
	le.PutUint32(b[348:], 15)
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
	for _, n := range []int{0, 79, 80, 119, 1095} {
		if _, e := decodeCapture(b[:n], 123); e == nil {
			t.Fatal(n)
		}
	}
	if _, e := decodeCapture(b, 124); e == nil {
		t.Fatal("nonce")
	}
}

// Mode bits follow original initializer 601720a0 and callback 60172500.
// Updating both captured byte and trace payload preserves their binding.
func TestAllHardwareModeBitPatterns(t *testing.T) {
	for _, bits := range []byte{0, 0x40, 0x80, 0xc0} {
		b := captureFixture(t)
		b[120+64+8*17] = bits | 0x15
		b[120+216+40*17+28] = bits | 0x15
		r, e := decodeCapture(b, 123)
		if e != nil {
			t.Fatal(e)
		}
		m := r["telemetry"].(map[string]any)
		if m["cell_mode_bits"] != uint32(bits) || m["FV_callback_halves_input"] != (bits == 0) {
			t.Fatal(bits, m)
		}
	}
}
