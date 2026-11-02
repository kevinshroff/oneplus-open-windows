package main

import (
	"os"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/" + name + ".bin")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestActualKernelCaptureFixtures(t *testing.T) {
	for _, tc := range []struct {
		name string
		code uint32
	}{{"success-batch", 0}, {"extensions-rejected", 0}, {"refused-FDT", 1004}, {"timeout-closed", 2012}, {"bad-reply-closed", 2009}} {
		t.Run(tc.name, func(t *testing.T) {
			v, e := decodeCapture(fixture(t, tc.name), 0x1234)
			if e != nil {
				t.Fatal(e)
			}
			if v["code"] != tc.code || v["all_queries_answered"] != (tc.code == 0) || v["charging_qualified"] != false {
				t.Fatal(v)
			}
		})
	}
}
func TestFalseCompletionRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		at    int
		value uint32
	}{
		{"status-magic", 8, 0}, {"status-size", 0, 79}, {"status-version", 4, 2}, {"status-build", 16, 1}, {"status-maps", 40, 5},
		{"nonce", 80, 123}, {"capture-maps", 108, 0}, {"admission", 112, 0}, {"reserved", 132, 1}, {"FDT-digest", 136, 0},
		{"not-complete", stateAt + 4, 0}, {"false-fault", stateAt + 8, 1}, {"terminal", stateAt + 12, 1}, {"bad-query-mask", stateAt + 23*4, 1},
		{"not-closed", stateAt + 29*4, 0}, {"bad-reply-mask", stateAt + 24*4, 1}, {"trace-count", stateAt + 7*4, 129}, {"bad-trace", stateAt + 44120, 0},
		{"wrong-remaining", stateAt + 164 + 10*4, 1}, {"wrong-current", stateAt + 164 + 19*4, 1}, {"bad-reply-size", stateAt + 33840, 1025},
		{"reply-owner", stateAt + 33880, 1}, {"reply-type", stateAt + 33880 + 4, 2}, {"reply-id", stateAt + 33880 + 732, 1},
		{"live-TX", 48436, 0}, {"live-RX", 48436 + 12, 0}, {"slot-overlap", 172, 0}, {"tail-padding", 81236, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := fixture(t, "success-batch")
			le.PutUint32(b[tc.at:], tc.value)
			if _, e := decodeCapture(b, 0x1234); e == nil {
				t.Fatal("accepted damaged completion")
			}
		})
	}
}
func TestWrongSizeAndNonce(t *testing.T) {
	b := fixture(t, "success-batch")
	for _, n := range []int{0, 79, 188, 81239} {
		if _, e := decodeCapture(b[:n], 0x1234); e == nil {
			t.Fatal(n)
		}
	}
	if _, e := decodeCapture(b, 0x1235); e == nil {
		t.Fatal("wrong nonce")
	}
	if _, e := decodeCapture(b, 0); e == nil {
		t.Fatal("zero nonce")
	}
}
