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
	if m["state_first"] != "DISABLED" || m["charge_enable_bit"] != byte(0) || m["usb_suspend_bit"] != byte(0) || m["effective_input_limit_mA"] != uint32(1500) || m["configured_input_limit_mA"] != uint32(1500) {
		t.Fatal(m)
	}
}
func TestDamagedSuccess(t *testing.T) {
	atList := []int{0, 4, 8, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 80, 88, 92, 96, 100, 120, 124, 136, 140, 144, 148, 152, 156, 160, 164}
	for i := 0; i < 11; i++ {
		atList = append(atList, 272+i*40, 276+i*40, 280+i*40, 284+i*40, 308+i*40)
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
	le.PutUint32(b[284:], 15)
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
	for _, n := range []int{0, 79, 80, 119, 711} {
		if _, e := decodeCapture(b[:n], 123); e == nil {
			t.Fatal(n)
		}
	}
	if _, e := decodeCapture(b, 124); e == nil {
		t.Fatal("nonce")
	}
}

// QPC may have a different epoch from KeQueryInterruptTime. Only the capture
// wrapper's interrupt timestamps can be compared to the G170 charging timer.
func TestClockDomainsRemainSeparate(t *testing.T) {
	b := captureFixture(t)
	r, e := decodeCapture(b, 123)
	if e != nil {
		t.Fatal(e)
	}
	if r["begin_us"].(uint64) <= r["capture_begin_interrupt_us"].(uint64)+4000000 {
		t.Fatal("model must exercise a real clock-epoch difference")
	}
	if r["capture_end_interrupt_us"].(uint64) < r["capture_begin_interrupt_us"].(uint64) {
		t.Fatal("interrupt capture ordering")
	}
}
