package main

import (
	"os"
	"testing"
)

func TestActualCWinPECaptures(t *testing.T) {
	for _, tc := range []struct {
		name string
		code uint32
	}{{"success", 0}, {"refused-RAM", 1005}, {"refused-live-state", 2}, {"timeout-cleaned", 7}, {"wrong-ID-cleaned", 12}} {
		t.Run(tc.name, func(t *testing.T) {
			b, e := os.ReadFile("testdata/" + tc.name + ".bin")
			if e != nil {
				t.Fatal(e)
			}
			v, e := decodeCapture(b, 0x1234)
			if e != nil {
				t.Fatal(e)
			}
			if v["operation_code"] != tc.code {
				t.Fatal(v)
			}
		})
	}
}
func TestFalseWinPESuccessRefused(t *testing.T) {
	for _, at := range []int{0, 4, 8, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 80, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 148, 152, 156, 160, 164, 168, 172, 176, 180, 202, 280, 284, 300, 9008, 17736, 17740} {
		t.Run(string(rune(at)), func(t *testing.T) {
			b, e := os.ReadFile("testdata/success.bin")
			if e != nil {
				t.Fatal(e)
			}
			b[at] ^= 0xff
			if _, e = decodeCapture(b, 0x1234); e == nil {
				t.Fatalf("damaged success accepted at %d", at)
			}
		})
	}
}
