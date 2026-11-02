package main

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type memoryDisk struct {
	b      []byte
	writes int
	failAt int
}

func (m *memoryDisk) ReadAt(b []byte, off int64) (int, error) {
	if off < 0 || off+int64(len(b)) > int64(len(m.b)) {
		return 0, io.EOF
	}
	return copy(b, m.b[off:]), nil
}
func (m *memoryDisk) WriteAt(b []byte, off int64) (int, error) {
	m.writes++
	if m.writes == m.failAt {
		copy(m.b[off:], b[:1024])
		return 1024, errors.New("injected partial device write")
	}
	if off < 0 || off+int64(len(b)) > int64(len(m.b)) {
		return 0, io.ErrShortWrite
	}
	return copy(m.b[off:], b), nil
}
func (m *memoryDisk) Sync() error { return nil }
func patchFixture() (*memoryDisk, Patch, []byte) {
	old := bytes.Repeat([]byte{0x42}, 8*4096)
	after := append([]byte(nil), old...)
	for i := 4096; i < 8192; i++ {
		after[i] = 0x71
	}
	for i := 12288; i < 16384; i++ {
		after[i] = 0x39
	}
	p := Patch{1, "userdata", uint64(len(old)), sum(old), sum(after), []Change{{4096, append([]byte(nil), old[4096:8192]...), append([]byte(nil), after[4096:8192]...)}, {12288, append([]byte(nil), old[12288:16384]...), append([]byte(nil), after[12288:16384]...)}}}
	disk := append(bytes.Repeat([]byte{0x11}, 4096), old...)
	disk = append(disk, bytes.Repeat([]byte{0x99}, 4096)...)
	return &memoryDisk{b: disk}, p, after
}
func TestPatchPreservesAdjacentProtectedRegions(t *testing.T) {
	m, p, after := patchFixture()
	original := append([]byte(nil), m.b...)
	state := ""
	e := applyPatch(m, 4096, p, func(s string, _ []uint64) error { state = s; return nil })
	if e != nil {
		t.Fatal(e)
	}
	if state != "verified" || !bytes.Equal(m.b[4096:len(m.b)-4096], after) || !bytes.Equal(m.b[:4096], original[:4096]) || !bytes.Equal(m.b[len(m.b)-4096:], original[len(m.b)-4096:]) {
		t.Fatal("extent/postimage failure")
	}
}
func TestPartialRawWriteRestoresExactPreimage(t *testing.T) {
	m, p, _ := patchFixture()
	original := append([]byte(nil), m.b...)
	m.failAt = 2
	state := ""
	e := applyPatch(m, 4096, p, func(s string, _ []uint64) error { state = s; return nil })
	if e == nil || state != "rolled_back" || !bytes.Equal(m.b, original) {
		t.Fatalf("rollback failure state=%s err=%v", state, e)
	}
}
func TestBadPreimageAndJournalFailureWriteNothing(t *testing.T) {
	for _, kind := range []string{"preimage", "journal"} {
		t.Run(kind, func(t *testing.T) {
			m, p, _ := patchFixture()
			if kind == "preimage" {
				m.b[4096] ^= 1
			}
			original := append([]byte(nil), m.b...)
			e := applyPatch(m, 4096, p, func(string, []uint64) error { return errors.New("cannot persist journal") })
			if e == nil || m.writes != 0 || !bytes.Equal(m.b, original) {
				t.Fatal("wrote before preflight/journal")
			}
		})
	}
}
func TestRefuseOverlappingAndBootSectorPatches(t *testing.T) {
	_, p, _ := patchFixture()
	p.Changes[1].Offset = p.Changes[0].Offset
	if validatePatch(p) == nil {
		t.Fatal("overlap accepted")
	}
	_, p, _ = patchFixture()
	p.Changes[0].Offset = 0
	if validatePatch(p) == nil {
		t.Fatal("changed FAT BPB accepted")
	}
}

func TestBadDeclaredPostimageWritesNothing(t *testing.T) {
	m, p, _ := patchFixture()
	p.AfterSHA = p.BeforeSHA
	e := applyPatch(m, 4096, p, func(string, []uint64) error { return nil })
	if e == nil || m.writes != 0 {
		t.Fatal("wrote an inconsistent postimage")
	}
}
