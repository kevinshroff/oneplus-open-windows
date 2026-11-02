package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

type fake struct {
	current           []byte
	writes, reads     int
	badWrite, corrupt bool
}

func (f *fake) read(l uint32, b []byte) error { f.reads++; copy(b, f.current); return nil }
func (f *fake) write(l uint32, b []byte) error {
	f.writes++
	if f.badWrite {
		return errors.New("write failed")
	}
	copy(f.current, b)
	if f.corrupt {
		f.current[3] ^= 1
	}
	return nil
}
func TestTransaction(t *testing.T) {
	a := bytes.Repeat([]byte{3}, chunkBytes)
	b := bytes.Repeat([]byte{7}, chunkBytes)
	ah := sha256.Sum256(a)
	bh := sha256.Sum256(b)
	f := &fake{current: bytes.Clone(a)}
	did, e := applyChunk(f, 0, b, ah[:], bh[:])
	if e != nil || !did || f.writes != 1 || !bytes.Equal(f.current, b) {
		t.Fatal(e)
	}
	did, e = applyChunk(f, 0, b, ah[:], bh[:])
	if e != nil || did || f.writes != 1 {
		t.Fatal("idempotence")
	}
	f.current[0] ^= 1
	_, e = applyChunk(f, 0, b, ah[:], bh[:])
	if e == nil || f.writes != 1 {
		t.Fatal("unknown preimage")
	}
	f = &fake{current: bytes.Clone(a)}
	_, e = applyChunk(f, 0, a, ah[:], bh[:])
	if e == nil || f.reads != 0 {
		t.Fatal("bad proposal reached source")
	}
	for _, corrupt := range []bool{false, true} {
		f = &fake{current: bytes.Clone(a), badWrite: !corrupt, corrupt: corrupt}
		_, e = applyChunk(f, 0, b, ah[:], bh[:])
		if e == nil || f.writes != 1 {
			t.Fatal("failed write/readback accepted")
		}
	}
}
func TestCDBBounds(t *testing.T) {
	for _, v := range []struct {
		op byte
		l  uint32
		n  int
		g  byte
	}{{0x2a, 0, 65536, 0}, {0x28, 0, 4096, 31}, {0x28, 0x3fff0, 65536, 0}} {
		if _, e := makeCDB(v.op, v.l, v.n, v.g); e != nil {
			t.Fatal(e)
		}
	}
	for _, v := range []struct {
		op byte
		l  uint32
		n  int
		g  byte
	}{{0x2a, 1, 65536, 0}, {0x2a, 0, 4096, 0}, {0x2a, 0, 65536, 31}, {0x28, 1, 4096, 31}, {0x28, 0x3ffff, 65536, 0}, {0x28, 0, 65537, 0}, {0xff, 0, 4096, 0}} {
		if _, e := makeCDB(v.op, v.l, v.n, v.g); e == nil {
			t.Fatal("bad CDB")
		}
	}
}
func TestPlanIdentity(t *testing.T) {
	b := make([]byte, 256+chunkCount*64)
	copy(b, "OP80P01\x00")
	for off, v := range map[int]uint32{8: 1, 12: 4096, 16: 65536, 20: 16384} {
		binary.LittleEndian.PutUint32(b[off:], v)
	}
	binary.LittleEndian.PutUint64(b[24:], 1<<30)
	binary.LittleEndian.PutUint64(b[32:], 64)
	h := sha256.Sum256(b)
	planSHA = hex.EncodeToString(h[:])
	if _, e := parsePlan(b); e != nil {
		t.Fatal(e)
	}
	b[400] ^= 1
	if _, e := parsePlan(b); e == nil {
		t.Fatal("plan tamper")
	}
	planSHA = ""
	if _, e := parsePlan(b); e == nil {
		t.Fatal("unbound build")
	}
}
