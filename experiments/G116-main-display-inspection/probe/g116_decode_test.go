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
	if _, e = decodeCapture(b, 123); e != nil {
		t.Fatal(e)
	}
	q := encodeRequest(123)
	if len(q) != 32 || le.Uint32(q) != 32 || le.Uint32(q[4:]) != 1 || le.Uint64(q[8:]) != le.Uint64(b[8:]) || le.Uint64(q[16:]) != 123 || le.Uint64(q[24:]) != 0 {
		t.Fatal("C/Go request ABI mismatch")
	}
	for _, offset := range []int{0, 4, 8, 80, 120, 124, 128, 136, 140, 144, 148, 152, 156, 92} {
		c := append([]byte(nil), b...)
		c[offset] ^= 1
		if _, e = decodeCapture(c, 123); e == nil {
			t.Fatalf("accepted modified field %d", offset)
		}
	}
	if _, e = decodeCapture(b[:100], 123); e == nil {
		t.Fatal("short")
	}
	if _, e = decodeCapture(b, 124); e == nil {
		t.Fatal("nonce")
	}
	// First sample without second is valid only on a reported refusal. It
	// must not manufacture a second sample or changed-byte comparison.
	c := append([]byte(nil), b...)
	le.PutUint32(c[88:], 2001)
	le.PutUint32(c[92:], 0)
	for i := 0; i < 15; i++ {
		le.PutUint32(c[128+32*i+28:], 1)
	}
	r, e := decodeCapture(c, 123)
	if e != nil {
		t.Fatal(e)
	}
	for _, region := range r["regions"].([]map[string]any) {
		if _, ok := region["changed_bytes"]; ok {
			t.Fatal("comparison without two samples")
		}
		for _, word := range region["words"].([]map[string]any) {
			if _, ok := word["second"]; ok {
				t.Fatal("invented second sample")
			}
		}
	}
}
