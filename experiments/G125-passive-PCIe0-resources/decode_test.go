package main

import (
	"os"
	"testing"
)

func fixture(t *testing.T) []byte {
	b, e := os.ReadFile("testdata/model-capture.bin")
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestProductionCABIAndLogicalVote(t *testing.T) {
	b := fixture(t)
	r, e := decodeCapture(b, 123)
	if e != nil || r["capture_code"] != uint32(0) || r["source_root0_selection_qualified"] != true {
		t.Fatalf("%+v %v", r, e)
	}
	if r["core_domain"].(map[string]any)["hardware_power"] != "on" {
		t.Fatal("model power status")
	}
	// A logical collapse request never overrides physical completion evidence.
	le.PutUint32(b[128:], 1)
	le.PutUint32(b[128+24*4:], 1)
	r, e = decodeCapture(b, 123)
	if e != nil || r["core_domain"].(map[string]any)["hardware_power"] != "on" || r["core_domain"].(map[string]any)["linux_logical_vote_enabled"] != false {
		t.Fatal("conflated vote and power", e)
	}
}

func TestHardwareStatusAmbiguityAndInstability(t *testing.T) {
	for _, cfg := range []uint32{0, 1<<15 | 1<<16, 1 << 15} {
		b := fixture(t)
		le.PutUint32(b[128+5*4:], cfg)
		le.PutUint32(b[128+(24+5)*4:], cfg)
		r, e := decodeCapture(b, 123)
		if e != nil || r["core_domain"].(map[string]any)["hardware_power"] != "unknown" {
			t.Fatal("promoted ambiguous status", cfg, e)
		}
	}
	b := fixture(t)
	le.PutUint32(b[128+(24+5)*4:], 1<<15)
	r, e := decodeCapture(b, 123)
	if e != nil || r["core_domain"].(map[string]any)["hardware_power"] != "unknown" {
		t.Fatal("promoted unstable status", e)
	}
}

func TestRefusedSelectionDoesNotBecomeRootQualification(t *testing.T) {
	for _, code := range []uint32{2001, 2002, 2003} {
		b := fixture(t)
		le.PutUint32(b[88:], code)
		le.PutUint32(b[52:], 1)
		switch code {
		case 2001:
			le.PutUint32(b[128+16*4:], 1<<9)
		case 2002:
			le.PutUint32(b[128+(24+17)*4:], 1)
		case 2003:
			le.PutUint32(b[128+17*4:], 1)
			le.PutUint32(b[128+(24+17)*4:], 1)
		}
		r, e := decodeCapture(b, 123)
		if e != nil || r["source_root0_selection_qualified"] != false || r["core_domain"] != nil {
			t.Fatal("qualified a refusal", code, e)
		}
	}
}

func TestEveryCancellationWordBoundary(t *testing.T) {
	for count := uint32(0); count < 48; count++ {
		b := fixture(t)
		le.PutUint32(b[88:], 1004)
		le.PutUint32(b[52:], 1)
		le.PutUint32(b[96:], count*4)
		first, second := count, uint32(0)
		complete := uint32(0)
		if first >= 24 {
			first, second, complete = 24, count-24, 1
		}
		le.PutUint32(b[92:], complete)
		le.PutUint32(b[120:], (1<<first)-1)
		le.PutUint32(b[124:], (1<<second)-1)
		for i := count; i < 48; i++ {
			le.PutUint32(b[128+4*i:], 0)
		}
		r, e := decodeCapture(b, 123)
		if e != nil || r["source_root0_selection_qualified"] != false {
			t.Fatal("cancel boundary", count, e)
		}
	}
}

func TestMalformedCaptureRejected(t *testing.T) {
	cases := map[string]func([]byte) []byte{
		"short":              func(b []byte) []byte { return b[:319] },
		"magic":              func(b []byte) []byte { b[8] ^= 1; return b },
		"nonce":              func(b []byte) []byte { b[80] ^= 1; return b },
		"sparse_mask":        func(b []byte) []byte { le.PutUint32(b[120:], 5); return b },
		"oversize_mask":      func(b []byte) []byte { le.PutUint32(b[120:], 1<<24); return b },
		"maps":               func(b []byte) []byte { le.PutUint32(b[100:], 8); return b },
		"reads":              func(b []byte) []byte { le.PutUint32(b[96:], 188); return b },
		"complete":           func(b []byte) []byte { le.PutUint32(b[92:], 1); return b },
		"fault":              func(b []byte) []byte { le.PutUint32(b[52:], 1); return b },
		"identity":           func(b []byte) []byte { le.PutUint32(b[16:], 1); return b },
		"refusal_with_reads": func(b []byte) []byte { le.PutUint32(b[88:], 1002); le.PutUint32(b[52:], 1); return b },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := decodeCapture(mutate(fixture(t)), 123); e == nil {
				t.Fatal("accepted malformed capture")
			}
		})
	}
}
