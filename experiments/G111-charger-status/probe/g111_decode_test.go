package main

import (
	"os"
	"testing"
)

func TestCapture(t *testing.T) {
	b, e := os.ReadFile("private/capture-01/fixture.bin")
	if e != nil {
		t.Fatal(e)
	}
	r, e := decodeCapture(b, 123)
	if e != nil {
		t.Fatal(e)
	}
	m := r["telemetry"].(map[string]any)
	if m["state_first"] != "DISABLED" || m["float_voltage_mV"] != uint32(4470) || m["fast_current_mA"] != uint32(300) || m["precharge_mA"] != uint32(300) || m["APSD_type"] != "SDP" {
		t.Fatal(m)
	}
	q := encodeRequest(123)
	if len(q) != 32 || le.Uint64(q[8:]) != le.Uint64(b[8:]) || le.Uint64(q[16:]) != 123 {
		t.Fatal("C/Go request ABI")
	}
	for _, offset := range []int{0, 4, 8, 80, 120, 148, 320, 324, 328, 332} {
		c := append([]byte(nil), b...)
		c[offset] ^= 1
		if _, e = decodeCapture(c, 123); e == nil {
			t.Fatalf("field accepted %d", offset)
		}
	}
	if _, e = decodeCapture(b[:100], 123); e == nil {
		t.Fatal("short")
	}
	if _, e = decodeCapture(b, 124); e == nil {
		t.Fatal("nonce")
	}
	c := append([]byte(nil), b...)
	le.PutUint32(c[124:], 6)
	le.PutUint32(c[148:], 1)
	le.PutUint32(c[332:], 15)
	r, e = decodeCapture(c, 123)
	if e != nil {
		t.Fatal(e)
	}
	if r["uncertain_read"] != true {
		t.Fatal("uncertain issued READ hidden")
	}
	if _, ok := r["telemetry"]; ok {
		t.Fatal("decoded failed capture as telemetry")
	}
}
