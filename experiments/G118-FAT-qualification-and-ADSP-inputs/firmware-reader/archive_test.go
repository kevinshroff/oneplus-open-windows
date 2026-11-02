package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestDirectoryIdentity(t *testing.T) {
	var a []FATEntry
	if e := json.Unmarshal([]byte(expectedDirectoryJSON), &a); e != nil {
		t.Fatal(e)
	}
	if _, e := checkDirectory(a); e != nil {
		t.Fatal(e)
	}
	for _, mode := range []int{0, 1, 2, 3, 4, 5} {
		b := append([]FATEntry(nil), a...)
		switch mode {
		case 0:
			b = b[:len(b)-1]
		case 1:
			b[0].Name = "adsp/../../bad"
		case 2:
			b[0].Size++
		case 3:
			b[0].Cluster++
		case 4:
			b[0].Attr |= 0x10
		case 5:
			b = append(b, b[0])
		}
		if _, e := checkDirectory(b); e == nil {
			t.Fatalf("accepted changed source identity %d", mode)
		}
	}
}
func streamFixture() (*FAT, FATEntry, []byte, []byte) {
	const size = 16384
	disk := make([]byte, size*7)
	for i := range disk {
		disk[i] = byte((i/size)*17 + i%251)
	}
	f := &FAT{Sector: 4096, ClusterBytes: size, DataOffset: size, Clusters: 6, Bits: 16, Table: make([]byte, 32), PhysicalBytes: uint64(len(disk))}
	binary.LittleEndian.PutUint16(f.Table[4:], 4)
	binary.LittleEndian.PutUint16(f.Table[8:], 5)
	binary.LittleEndian.PutUint16(f.Table[10:], 0xffff)
	e := FATEntry{Name: "adsp.b42", Cluster: 2, Size: size*3 - 19}
	want := append([]byte(nil), disk[size:2*size]...)
	want = append(want, disk[3*size:5*size-19]...)
	return f, e, disk, want
}

type failWriter struct{ short bool }

func (f failWriter) Write(b []byte) (int, error) {
	if f.short {
		return len(b) - 1, nil
	}
	return 0, errors.New("writer failure")
}
func TestStreamActualExtents(t *testing.T) {
	f, e, disk, want := streamFixture()
	var out bytes.Buffer
	calls := 0
	read := func(off, n uint64) ([]byte, error) {
		calls++
		if n > 1<<20 || off+n > uint64(len(disk)) {
			t.Fatal("source read bounds")
		}
		return disk[off : off+n], nil
	}
	got, err := streamFile(f, e, read, &out)
	if err != nil || !bytes.Equal(out.Bytes(), want) || got.Bytes != uint64(e.Size) || calls != 2 {
		t.Fatalf("ordered/merged capture: %+v %v %d", got, err, calls)
	}
	digest := sha256.Sum256(want)
	if got.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("source hash")
	}
	for i := 0; i < 5; i++ {
		f, e, disk, _ = streamFixture()
		r := read
		var w io.Writer = &bytes.Buffer{}
		switch i {
		case 0:
			r = func(off, n uint64) ([]byte, error) { return nil, errors.New("source failure") }
		case 1:
			r = func(off, n uint64) ([]byte, error) { return disk[off : off+n-1], nil }
		case 2:
			w = failWriter{}
		case 3:
			w = failWriter{short: true}
		case 4:
			binary.LittleEndian.PutUint16(f.Table[10:], 2)
		}
		if _, err := streamFile(f, e, r, w); err == nil {
			t.Fatalf("accepted failure %d", i)
		}
	}
}
func TestSplitArchiveBoundaries(t *testing.T) {
	dir := t.TempDir()
	s, e := newSplitWriter(dir, 37)
	if e != nil {
		t.Fatal(e)
	}
	data := bytes.Repeat([]byte{1, 9, 4, 7}, 31)
	for _, p := range [][]byte{data[:1], data[1:55], data[55:]} {
		if n, e := s.Write(p); e != nil || n != len(p) {
			t.Fatal(n, e)
		}
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	if len(s.parts) != 4 || s.total != int64(len(data)) {
		t.Fatal("parts count")
	}
	var whole []byte
	for _, p := range s.parts {
		b, e := os.ReadFile(filepath.Join(dir, p.Name))
		if e != nil || len(b) > 37 || p.Bytes != int64(len(b)) {
			t.Fatal("part bounds", e)
		}
		h := sha256.Sum256(b)
		if p.SHA256 != hex.EncodeToString(h[:]) {
			t.Fatal("part hash")
		}
		whole = append(whole, b...)
	}
	if !bytes.Equal(whole, data) {
		t.Fatal("part concatenation")
	}
	h := sha256.Sum256(data)
	if hex.EncodeToString(s.totalHash.Sum(nil)) != hex.EncodeToString(h[:]) {
		t.Fatal("whole hash")
	}
	if _, e := s.Write([]byte{1}); e == nil {
		t.Fatal("write after close")
	}
	if e := s.Close(); e == nil {
		t.Fatal("repeat close")
	}
	for _, n := range []int64{0, -1, 24<<20 + 1} {
		if _, e := newSplitWriter(dir, n); e == nil {
			t.Fatal("bad part limit")
		}
	}
	collision := t.TempDir()
	if e := os.WriteFile(filepath.Join(collision, "bundle-00.bin"), []byte{8}, 0600); e != nil {
		t.Fatal(e)
	}
	c, _ := newSplitWriter(collision, 37)
	if _, e := c.Write([]byte{1}); e == nil {
		t.Fatal("overwrote existing part")
	}
}
