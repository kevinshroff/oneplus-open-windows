// SPDX-License-Identifier: GPL-2.0-only
package goodix

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
)

func wire(s string) []byte {
	b, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return b
}

// Hand-computed wire fixture, not captured on this phone. Header checksum=0x82;
// two point sums are 337 and 377, total 714=0x02ca. Sparse IDs catch accidental
// array-index assignment and coordinates catch endian reversal.
const twoPoints = "8000020000008200300034127856090470000100ff000108ca02"

func TestWireSnapshot(t *testing.T) {
	s, e := Decode(wire(twoPoints))
	if e != nil {
		t.Fatal(e)
	}
	want := []Contact{{3, 4660, 22136, 9, 4}, {7, 1, 255, 8, 1}}
	if !reflect.DeepEqual(s.Contacts, want) {
		t.Fatalf("got %+v", s)
	}
	padded := append(wire(twoPoints), make([]byte, MaxReportBytes-len(wire(twoPoints)))...)
	if p, e := Decode(padded); e != nil || !reflect.DeepEqual(p, s) {
		t.Fatalf("pre-read padding: %+v %v", p, e)
	}
	up, e := Decode(wire("80000000000080000000"))
	if e != nil || len(up.Contacts) != 0 {
		t.Fatalf("release: %+v %v", up, e)
	}
}

func TestRejectCorruption(t *testing.T) {
	b := wire(twoPoints)
	for i := range b {
		x := bytes.Clone(b)
		x[i] ^= 0x40
		if _, e := Decode(x); e == nil {
			t.Fatalf("accepted single-byte corruption at %d", i)
		}
	}
	for n := 0; n < len(b); n++ {
		if _, e := Decode(b[:n]); e == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
	if _, e := Decode(make([]byte, MaxReportBytes+1)); e == nil {
		t.Fatal("accepted oversize")
	}
	if _, e := Decode(wire("20000000000020000000")); !errors.Is(e, ErrNotTouch) {
		t.Fatalf("gesture decoded as touch: %v", e)
	}
}

func TestRejectSemanticErrors(t *testing.T) {
	// Individually corrected checksums ensure these test semantics, not corruption.
	for _, s := range []string{
		"80000b0000008b000000",                                 // eleven contacts
		"8000010000008100a000010002000304aa00",                 // ID ten
		"8000020000008200300034127856090430000100ff0001088a02", // duplicate ID three
	} {
		if _, e := Decode(wire(s)); e == nil {
			t.Fatalf("accepted %s", s)
		}
	}
	if _, e := Decode(wire("800001000000810003000100020003040d00")); !errors.Is(e, ErrStylus) {
		t.Fatalf("stylus: %v", e)
	}
}

func TestSPIWireFraming(t *testing.T) {
	b, e := ReadRequest(0x01020304, 2)
	if e != nil || !bytes.Equal(b, wire("f101020304ffffff0000")) {
		t.Fatalf("read: %x %v", b, e)
	}
	b, e = WriteRequest(0x12345678, wire("00a5"))
	if e != nil || !bytes.Equal(b, wire("f01234567800a5")) {
		t.Fatalf("write: %x %v", b, e)
	}
	for _, n := range []int{-1, 0, MaxReportBytes + 1} {
		if _, e := ReadRequest(0, n); e == nil {
			t.Fatalf("read bound %d", n)
		}
	}
	if _, e := WriteRequest(0, nil); e == nil {
		t.Fatal("empty write")
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(wire(twoPoints))
	f.Add(wire("80000000000080000000"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		s, e := Decode(b)
		if e != nil {
			return
		}
		if len(s.Contacts) > MaxContacts {
			t.Fatal("too many contacts")
		}
		var seen uint16
		for _, p := range s.Contacts {
			if p.ID >= MaxContacts || seen&(1<<p.ID) != 0 || p.Major < p.Minor {
				t.Fatalf("invalid contact %+v", p)
			}
			seen |= 1 << p.ID
		}
	})
}
