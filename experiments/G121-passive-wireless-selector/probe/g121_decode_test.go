// SPDX-License-Identifier: MIT
package main

import (
	"os"
	"testing"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	b, e := os.ReadFile("private/capture-01/fixture.bin")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestCABI(t *testing.T) {
	b := fixture(t)
	r, e := decodeCapture(b, 123)
	if e != nil {
		t.Fatal(e)
	}
	if r["source_selection_qualified"] != true || r["physical_PCI_identity_verified"] != false || r["source_selected_device_id"] != "0x1107" || r["source_selected_root_complex"] != 0 {
		t.Fatal(r)
	}
	q := encodeRequest(123)
	if len(q) != 32 || le.Uint32(q) != 32 || le.Uint32(q[4:]) != 1 || le.Uint64(q[8:]) != le.Uint64(b[8:]) || le.Uint64(q[16:]) != 123 || le.Uint64(q[24:]) != 0 {
		t.Fatal("request ABI")
	}
}
func TestSelection(t *testing.T) {
	for _, c := range []uint32{0, 1, 2, 0x40, 0x800, 0x840, 0x80000000} {
		for _, io := range []uint32{0, 1, 2, 3, 0xffffffff} {
			b := fixture(t)
			for _, off := range []int{120, 128} {
				le.PutUint32(b[off:], c)
				le.PutUint32(b[off+4:], io)
			}
			r, e := decodeCapture(b, 123)
			if e != nil {
				t.Fatal(e)
			}
			want := "0x1107"
			if io&1 != 0 {
				want = "0x1103"
			}
			if r["source_selected_device_id"] != want || r["physical_PCI_identity_verified"] != false {
				t.Fatal(r)
			}
		}
	}
}
func TestNoInventedSelection(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		control, inout, code uint32
	}{
		{"mux", 4, 0, 2001}, {"OE", 512, 0, 2001}, {"EGPIO", 4096, 0, 2001}, {"changed-input", 0x840, 1, 2002}, {"changed-control", 0x841, 0, 2002},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := fixture(t)
			le.PutUint32(b[88:], tc.code)
			le.PutUint32(b[52:], 1)
			le.PutUint32(b[128:], tc.control)
			le.PutUint32(b[132:], tc.inout)
			r, e := decodeCapture(b, 123)
			if e != nil {
				t.Fatal(e)
			}
			if r["source_selection_qualified"] != false || r["physical_PCI_identity_verified"] != false {
				t.Fatal(r)
			}
			if _, ok := r["source_selected_device_id"]; ok {
				t.Fatal("invented candidate")
			}
		})
	}
}
func TestRejectMalformed(t *testing.T) {
	for _, offset := range []int{0, 4, 8, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 80, 88, 92, 96, 100} {
		t.Run("field-"+string(rune('A'+offset)), func(t *testing.T) {
			b := fixture(t)
			b[offset] ^= 1
			if _, e := decodeCapture(b, 123); e == nil {
				t.Fatalf("accepted field %d", offset)
			}
		})
	}
	b := fixture(t)
	for _, n := range []int{0, 1, 79, 80, 135, 137} {
		c := make([]byte, n)
		copy(c, b)
		if _, e := decodeCapture(c, 123); e == nil {
			t.Fatalf("length %d", n)
		}
	}
	for _, nonce := range []uint64{0, 124} {
		if _, e := decodeCapture(b, nonce); e == nil {
			t.Fatal("nonce")
		}
	}
	for _, code := range []uint32{1000, 1003, 1006, 2003, 0xffffffff} {
		c := append([]byte(nil), b...)
		le.PutUint32(c[88:], code)
		le.PutUint32(c[52:], 1)
		if _, e := decodeCapture(c, 123); e == nil {
			t.Fatal("code")
		}
	}
	le.PutUint64(b[112:], le.Uint64(b[104:])-1)
	if _, e := decodeCapture(b, 123); e == nil {
		t.Fatal("time reversal")
	}
}
func TestRefusalsAndPartialCapture(t *testing.T) {
	for _, tc := range []struct{ code, mask, reads, maps uint32 }{
		{1001, 0, 0, 0}, {1002, 0, 0, 0}, {1005, 0, 0, 1}, {1004, 0, 0, 0}, {1004, 0, 0, 1}, {1004, 0, 4, 1}, {1004, 1, 8, 1}, {1004, 1, 12, 1},
	} {
		b := fixture(t)
		le.PutUint32(b[88:], tc.code)
		le.PutUint32(b[92:], tc.mask)
		le.PutUint32(b[96:], tc.reads)
		le.PutUint32(b[100:], tc.maps)
		le.PutUint32(b[40:], tc.maps)
		le.PutUint32(b[52:], 1)
		for n := tc.reads; n < 16; n += 4 {
			le.PutUint32(b[120+n:], 0)
		}
		r, e := decodeCapture(b, 123)
		if e != nil {
			t.Fatal(tc, e)
		}
		if r["source_selection_qualified"] != false {
			t.Fatal(tc, r)
		}
		if tc.reads < 16 {
			b[120+tc.reads] = 1
			if _, e := decodeCapture(b, 123); e == nil {
				t.Fatal("accepted invented unread word", tc)
			}
		}
	}
	for _, tc := range []struct{ mask, reads, maps uint32 }{{2, 8, 1}, {3, 16, 1}, {0, 8, 1}, {1, 4, 1}, {1, 8, 0}, {0, 0, 2}} {
		b := fixture(t)
		le.PutUint32(b[88:], 1004)
		le.PutUint32(b[92:], tc.mask)
		le.PutUint32(b[96:], tc.reads)
		le.PutUint32(b[100:], tc.maps)
		le.PutUint32(b[40:], tc.maps)
		le.PutUint32(b[52:], 1)
		if _, e := decodeCapture(b, 123); e == nil {
			t.Fatal("invalid cancellation", tc)
		}
	}
}
