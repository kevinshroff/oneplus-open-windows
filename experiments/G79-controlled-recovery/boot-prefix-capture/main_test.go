package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"
)

type strictReader struct {
	data  []byte
	calls int
}

func (r *strictReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off%4096 != 0 || len(p)%4096 != 0 {
		panic("unaligned read")
	}
	r.calls++
	return bytes.NewReader(r.data).ReadAt(p, off)
}
func TestBoundedPrefix(t *testing.T) {
	b := make([]byte, 3<<20)
	for i := range b {
		b[i] = byte(i * 17)
	}
	r := &strictReader{data: b}
	var w bytes.Buffer
	h, e := copyPrefix(&w, r, (2<<20)+4096)
	if e != nil {
		t.Fatal(e)
	}
	want := b[:(2<<20)+4096]
	sum := sha256.Sum256(want)
	if !bytes.Equal(w.Bytes(), want) || h != hex.EncodeToString(sum[:]) || r.calls != 3 {
		t.Fatal("capture mismatch")
	}
	r = &strictReader{data: b}
	w.Reset()
	if _, e = copyPrefix(&w, r, 4<<20); e != io.EOF {
		t.Fatalf("short source: %v", e)
	}
	for _, n := range []int64{-4096, 0, 4095, 4097, (1 << 30) + 4096} {
		r.calls = 0
		if _, e = copyPrefix(&w, r, n); e == nil || r.calls != 0 {
			t.Fatal("invalid range reached source", n)
		}
	}
}
func TestFacadeBounds(t *testing.T) {
	if checkBounds(1<<30, 1<<30, 4096) != nil {
		t.Fatal("valid facade refused")
	}
	for _, v := range [][3]int64{{17 << 30, 17 << 30, 4096}, {(1 << 30) - 4096, 1 << 30, 4096}, {1 << 30, 1 << 30, 4097}, {1 << 30, 1 << 30, (1 << 30) + 4096}} {
		if checkBounds(v[0], v[1], v[2]) == nil {
			t.Fatal("bad facade accepted", v)
		}
	}
}
