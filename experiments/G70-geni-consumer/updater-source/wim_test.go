package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type faultWIM struct {
	b            []byte
	writes       int
	failWrite    int
	failTruncate bool
	order        []int64
}

func (f *faultWIM) ReadAt(b []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(f.b)) {
		return 0, io.EOF
	}
	n := copy(b, f.b[off:])
	if n != len(b) {
		return n, io.EOF
	}
	return n, nil
}
func (f *faultWIM) WriteAt(b []byte, off int64) (int, error) {
	f.writes++
	f.order = append(f.order, off)
	n := len(b)
	if f.writes == f.failWrite {
		n = 17
	}
	if int64(len(f.b)) < off+int64(n) {
		f.b = append(f.b, make([]byte, off+int64(n)-int64(len(f.b)))...)
	}
	copy(f.b[off:], b[:n])
	if n != len(b) {
		return n, io.ErrShortWrite
	}
	return n, nil
}
func (f *faultWIM) Sync() error { return nil }
func (f *faultWIM) Truncate(n int64) error {
	if n <= int64(len(f.b)) {
		f.b = f.b[:n]
	} else {
		f.b = append(f.b, make([]byte, n-int64(len(f.b)))...)
	}
	if f.failTruncate {
		f.failTruncate = false
		return errors.New("injected failure after truncation")
	}
	return nil
}
func wimFixture() ([]byte, []byte, WIMPlan) {
	old := bytes.Repeat([]byte{0x42}, 8192)
	copy(old, []byte{'M', 'S', 'W', 'I', 'M', 0, 0, 0})
	binary.LittleEndian.PutUint32(old[8:], 208)
	binary.LittleEndian.PutUint32(old[44:], 1)
	binary.LittleEndian.PutUint32(old[120:], 1)
	after := append(append([]byte(nil), old...), bytes.Repeat([]byte{0x31}, 1234)...)
	after[100] ^= 3
	after[5200] ^= 7
	p := WIMPlan{Version: "G21-trial-wim-v1", Name: trialWIMName, BeforeBytes: uint64(len(old)), AfterBytes: uint64(len(after)), BeforeSHA: sum(old), AfterSHA: sum(after), Tail: append([]byte(nil), after[len(old):]...)}
	for off := 0; off < len(old); off += 4096 {
		p.Changes = append(p.Changes, WIMChange{uint64(off), append([]byte(nil), old[off:off+4096]...), append([]byte(nil), after[off:off+4096]...)})
	}
	return old, after, p
}
func inverseWIM(p WIMPlan) WIMPlan {
	q := p
	q.BeforeBytes, q.AfterBytes = p.AfterBytes, p.BeforeBytes
	q.BeforeSHA, q.AfterSHA = p.AfterSHA, p.BeforeSHA
	q.Changes = make([]WIMChange, len(p.Changes))
	for i, c := range p.Changes {
		q.Changes[i] = WIMChange{c.Offset, c.After, c.Before}
	}
	return q
}
func TestWIMHeaderIsPublishedAfterResourceReadback(t *testing.T) {
	old, after, p := wimFixture()
	f := &faultWIM{b: append([]byte(nil), old...)}
	phase := ""
	if e := applyWIMPlan(f, p, func(s string, _ []uint64) error { phase = s; return nil }); e != nil {
		t.Fatal(e)
	}
	if phase != "verified" || !bytes.Equal(f.b, after) || !reflect.DeepEqual(f.order, []int64{8192, 4096, 0}) {
		t.Fatal("wrong result/publication order", phase, f.order)
	}
}
func TestWIMPartialAppendInteriorAndHeaderWritesRestoreExactFile(t *testing.T) {
	for _, fail := range []int{1, 2, 3} {
		old, _, p := wimFixture()
		f := &faultWIM{b: append([]byte(nil), old...), failWrite: fail}
		phase := ""
		e := applyWIMPlan(f, p, func(s string, _ []uint64) error { phase = s; return nil })
		if e == nil || phase != "rolled_back" || !bytes.Equal(f.b, old) {
			t.Fatalf("failure%d: phase%s err%v", fail, phase, e)
		}
	}
}
func TestWIMInversePartialWritesAndTruncationRestoreCandidate(t *testing.T) {
	for _, fail := range []int{1, 2, 3} {
		_, after, p := wimFixture()
		q := inverseWIM(p)
		f := &faultWIM{b: append([]byte(nil), after...), failWrite: fail}
		if fail == 3 {
			f.failWrite = 0
			f.failTruncate = true
		}
		phase := ""
		e := applyWIMPlan(f, q, func(s string, _ []uint64) error { phase = s; return nil })
		if e == nil || phase != "rolled_back" || !bytes.Equal(f.b, after) {
			t.Fatalf("inverse failure%d: phase%s err%v", fail, phase, e)
		}
	}
}
func TestWIMBadPreimagePostimageAndInitialJournalWriteNothing(t *testing.T) {
	for _, kind := range []string{"preimage", "postimage", "journal", "scope", "overlap"} {
		t.Run(kind, func(t *testing.T) {
			old, _, p := wimFixture()
			f := &faultWIM{b: append([]byte(nil), old...)}
			switch kind {
			case "preimage":
				f.b[7000] ^= 1
			case "postimage":
				p.AfterSHA = p.BeforeSHA
			case "scope":
				p.Name = "G18-maintenance.wim"
			case "overlap":
				p.Changes[1].Offset = 17
			}
			before := append([]byte(nil), f.b...)
			e := applyWIMPlan(f, p, func(string, []uint64) error {
				if kind == "journal" {
					return errors.New("journal unavailable")
				}
				return nil
			})
			if e == nil || f.writes != 0 || !bytes.Equal(f.b, before) {
				t.Fatal("modified file before complete preflight and durable journal")
			}
		})
	}
}
func TestWIMInverseRejectsIncorrectTailBackupBeforeWrites(t *testing.T) {
	_, after, p := wimFixture()
	q := inverseWIM(p)
	q.Tail = append([]byte(nil), q.Tail...)
	q.Tail[0] ^= 1
	f := &faultWIM{b: append([]byte(nil), after...)}
	e := applyWIMPlan(f, q, func(string, []uint64) error { return nil })
	if e == nil || f.writes != 0 || !bytes.Equal(f.b, after) {
		t.Fatal("incorrect truncation backup was accepted")
	}
}
func TestWIMFinalJournalFailureRollsBack(t *testing.T) {
	old, _, p := wimFixture()
	f := &faultWIM{b: append([]byte(nil), old...)}
	phase := ""
	e := applyWIMPlan(f, p, func(s string, _ []uint64) error {
		phase = s
		if s == "verified" {
			return errors.New("final journal unavailable")
		}
		return nil
	})
	if e == nil || phase != "rolled_back" || !bytes.Equal(f.b, old) {
		t.Fatal("final journal failure lost preimage")
	}
}
func TestWIMRealFileForwardAndInverseHashRoundtrip(t *testing.T) {
	old, after, p := wimFixture()
	path := filepath.Join(t.TempDir(), trialWIMName)
	if e := os.WriteFile(path, old, 0600); e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(path, os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	for _, trial := range []struct {
		plan WIMPlan
		want []byte
	}{{p, after}, {inverseWIM(p), old}} {
		if e := applyWIMPlan(f, trial.plan, func(string, []uint64) error { return nil }); e != nil {
			t.Fatal(e)
		}
		b, e := os.ReadFile(path)
		if e != nil || !bytes.Equal(b, trial.want) {
			t.Fatal("real file roundtrip mismatch", e)
		}
	}
}
