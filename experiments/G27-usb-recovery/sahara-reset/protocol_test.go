package main

import (
	"bytes"
	"testing"
)

func TestExactReset(t *testing.T) {
	if !bytes.Equal(resetRequest(), []byte{7, 0, 0, 0, 8, 0, 0, 0}) {
		t.Fatal("reset frame")
	}
	good := []byte{8, 0, 0, 0, 8, 0, 0, 0}
	if !resetResponse(good) {
		t.Fatal("ACK")
	}
	for i := range good {
		b := append([]byte{}, good...)
		b[i] ^= 1
		if resetResponse(b) {
			t.Fatal(i)
		}
	}
	for _, b := range [][]byte{nil, good[:7], append(append([]byte{}, good...), 0)} {
		if resetResponse(b) {
			t.Fatal("length")
		}
	}
}
func TestDescriptorGuards(t *testing.T) {
	good := []byte{9, 4, 0, 0, 2, 0xff, 0xff, 0x10, 0}
	if validateInterface(good) != nil {
		t.Fatal("valid descriptor")
	}
	for i := 0; i < 8; i++ {
		b := append([]byte{}, good...)
		b[i] ^= 1
		if validateInterface(b) == nil {
			t.Fatal(i)
		}
	}
	if validateInterface(good[:8]) == nil {
		t.Fatal("size")
	}
}
