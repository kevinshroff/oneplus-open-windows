package main

import (
	"bytes"
	"io"
	"testing"
)

type strictReader struct {
	b     []byte
	calls int
}

func (s *strictReader) ReadAt(p []byte, o int64) (int, error) {
	if o%4096 != 0 || len(p)%4096 != 0 {
		panic("unaligned physical read")
	}
	s.calls++
	return bytes.NewReader(s.b).ReadAt(p, o)
}
func TestAlignedReadAndBounds(t *testing.T) {
	b := make([]byte, 65536)
	for i := range b {
		b[i] = byte(i * 13)
	}
	s := &strictReader{b: b}
	a := &alignedReader{s, int64(len(b))}
	for _, v := range []struct {
		off int64
		n   int
	}{{0, 1}, {1, 8191}, {4095, 4098}, {65000, 536}, {4096, 0}} {
		p := make([]byte, v.n)
		n, e := a.ReadAt(p, v.off)
		if e != nil || n != v.n || !bytes.Equal(p, b[v.off:int(v.off)+v.n]) {
			t.Fatalf("valid read %v: %d %v", v, n, e)
		}
	}
	before := s.calls
	for _, v := range []struct {
		off int64
		n   int
	}{{-1, 1}, {65536, 1}, {65535, 2}, {1 << 62, 4096}} {
		if _, e := a.ReadAt(make([]byte, v.n), v.off); e != io.EOF {
			t.Fatalf("range accepted: %v", v)
		}
	}
	if s.calls != before {
		t.Fatal("invalid read reached physical source")
	}
}
func TestEvidencePaths(t *testing.T) {
	for _, p := range []string{"Windows/Panther/setupact.log", "$WINDOWS.~BT/Sources/Panther"} {
		if !safePath(p) {
			t.Fatal(p)
		}
	}
	for _, p := range []string{"../x", "Windows/../x", "/x", `Windows\x`, `C:/x`, ".", ""} {
		if safePath(p) {
			t.Fatal(p)
		}
	}
}

func TestPhysicalPath(t *testing.T) {
	p := string([]byte{92, 92, 46, 92})
	for _, s := range []string{p + "PhysicalDrive0", p + "PhysicalDrive123"} {
		if !rawPhysicalName(s) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{p + "PhysicalDrive", p + "C:", p + "PhysicalDrive-1", p + "PhysicalDrive1/foo", "PhysicalDrive1"} {
		if rawPhysicalName(s) {
			t.Fatal(s)
		}
	}
}
