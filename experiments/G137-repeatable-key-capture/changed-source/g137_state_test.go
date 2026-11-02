package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

const modelNonce = uint64(0x1020304050607080)

func fixture(t *testing.T, suffix string) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/model-capture.bin" + suffix)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestActualCStateAndAcknowledgment(t *testing.T) {
	ready, e := decodeCaptureState(fixture(t, ".state-ready"))
	if e != nil {
		t.Fatal(e)
	}
	retired, e := decodeCaptureState(fixture(t, ".state-retired"))
	if e != nil {
		t.Fatal(e)
	}
	fault, e := decodeCaptureState(fixture(t, ".state-fault"))
	if e != nil {
		t.Fatal(e)
	}
	if ready.Phase != 2 || ready.Captures != 1 || retired.Phase != 0 || retired.Retirements != 1 || fault.Phase != 3 || fault.Captures != 2 || fault.TotalMaps != 7 {
		t.Fatal("actual C state layout")
	}
	if e = validateRetirement(ready, retired, modelNonce); e != nil {
		t.Fatal(e)
	}
	if e = validateRetirement(retired, retired, modelNonce); e != nil {
		t.Fatal("lost-reply acknowledgment", e)
	}
	if e = validateRetirement(fault, retired, modelNonce); e == nil {
		t.Fatal("fault acknowledged")
	}
	b := fixture(t, "")
	q, e := retireRequest(modelNonce, b)
	if e != nil {
		t.Fatal(e)
	}
	if len(q) != 32+captureBytes || le.Uint32(q) != 32 || le.Uint32(q[4:]) != 1 || string(q[8:16]) != "OG99KEY1" || le.Uint64(q[16:]) != modelNonce || le.Uint64(q[24:]) != 0 || !bytes.Equal(q[32:], b) {
		t.Fatal("exact wire acknowledgment")
	}
}
func TestMalformedState(t *testing.T) {
	tests := map[string]func([]byte){
		"size": func(b []byte) { b[0]-- }, "version": func(b []byte) { b[4]++ }, "magic": func(b []byte) { b[8] ^= 1 }, "reserved": func(b []byte) { b[60] = 1 },
		"phase": func(b []byte) { le.PutUint32(b[16:], 4) }, "slots": func(b []byte) { le.PutUint32(b[28:], 33) }, "captures": func(b []byte) { le.PutUint32(b[20:], 33) },
		"retired": func(b []byte) { le.PutUint32(b[24:], 2) }, "slot-maps": func(b []byte) { le.PutUint32(b[56:], 6) }, "total-maps": func(b []byte) { le.PutUint64(b[48:], 161) },
		"nonce": func(b []byte) { le.PutUint64(b[32:], 0) }, "premature-retired-nonce": func(b []byte) { le.PutUint64(b[40:], modelNonce) },
		"empty-unretired": func(b []byte) { le.PutUint32(b[16:], 0) }, "ready-maps": func(b []byte) { le.PutUint64(b[48:], 4) }, "busy-maps": func(b []byte) { le.PutUint32(b[16:], 1) },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			b := fixture(t, ".state-ready")
			change(b)
			if _, e := decodeCaptureState(b); e == nil {
				t.Fatal("accepted invalid state")
			}
		})
	}
	for _, size := range []int{0, 1, 16, 63} {
		t.Run("truncated-"+string(rune('A'+size)), func(t *testing.T) {
			if _, e := decodeCaptureState(fixture(t, ".state-ready")[:size]); e == nil {
				t.Fatal("truncation")
			}
		})
	}
}
func TestWrongRetirementResponse(t *testing.T) {
	ready, _ := decodeCaptureState(fixture(t, ".state-ready"))
	retired, _ := decodeCaptureState(fixture(t, ".state-retired"))
	tests := map[string]func(*captureState){"phase": func(s *captureState) { s.Phase = 2 }, "count": func(s *captureState) { s.Captures++ }, "retired": func(s *captureState) { s.Retirements-- }, "current": func(s *captureState) { s.CurrentNonce++ }, "last": func(s *captureState) { s.LastRetiredNonce++ }, "maps": func(s *captureState) { s.TotalMaps++ }, "slot": func(s *captureState) { s.SlotMaps-- }}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			s := retired
			change(&s)
			if e := validateRetirement(ready, s, modelNonce); e == nil {
				t.Fatal("accepted contradiction")
			}
		})
	}
	if e := validateRetirement(ready, retired, modelNonce+1); e == nil {
		t.Fatal("wrong nonce")
	}
}
func TestDurableCapture(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.bin")
	b := fixture(t, "")
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	got, sum, e := durableCapture(path, modelNonce)
	if e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(b)
	if !bytes.Equal(got, b) || sum != hex.EncodeToString(hash[:]) {
		t.Fatal("save/reopen hash")
	}
	for name, data := range map[string][]byte{"truncated": b[:len(b)-1], "extra": append(append([]byte(nil), b...), 0), "wrong-nonce": func() []byte { c := append([]byte(nil), b...); c[80] ^= 1; return c }(), "failed-capture": func() []byte { c := append([]byte(nil), b...); le.PutUint32(c[108:], 1006); return c }()} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, name+".bin")
			if e := os.WriteFile(p, data, 0600); e != nil {
				t.Fatal(e)
			}
			if _, _, e := durableCapture(p, modelNonce); e == nil {
				t.Fatal("invalid durable file accepted")
			}
		})
	}
	if _, _, e := durableCapture(filepath.Join(dir, "missing.bin"), modelNonce); e == nil {
		t.Fatal("missing capture created")
	}
	if _, e := os.Stat(filepath.Join(dir, "missing.bin")); !os.IsNotExist(e) {
		t.Fatal("retirement created file")
	}
	if _, _, e := durableCapture(dir, modelNonce); e == nil {
		t.Fatal("directory accepted")
	}
}
