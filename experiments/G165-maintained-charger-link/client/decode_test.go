package main

import (
	"encoding/binary"
	"os"
	"testing"
)

func fixture(t *testing.T, n string) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/" + n)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestActualCRequests(t *testing.T) {
	for _, mode := range []string{"status", "snapshot", "start", "sample", "close"} {
		cookie, id := uint64(0x1234), uint64(7)
		if mode == "status" || mode == "snapshot" {
			cookie = 0
			id = 0
		}
		b, code, e := request(mode, cookie, id)
		if e != nil || code != abi.Codes[mode] {
			t.Fatal(e)
		}
		want := fixture(t, mode+"-request.bin")
		if string(b) != string(want) {
			t.Fatal("actual C request mismatch", mode)
		}
	}
	for _, mode := range []string{"raw", "reset", "setter", "sample"} {
		if _, _, e := request(mode, 0, 0); e == nil {
			t.Fatal("bad request accepted", mode)
		}
	}
	if _, _, e := request("status", 1, 0); e == nil {
		t.Fatal("status cookie accepted")
	}
}
func TestActualCSnapshots(t *testing.T) {
	for _, n := range []string{"open.bin", "read-batch.bin", "closed.bin", "refused.bin", "uncertain.bin"} {
		r, e := decode(fixture(t, n))
		if e != nil {
			t.Fatal(n, e)
		}
		batch := r["last_batch"].(map[string]any)
		if n == "read-batch.bin" && batch["generation"] != uint64(100) {
			t.Fatal(batch)
		}
		if n == "open.bin" || n == "refused.bin" || n == "uncertain.bin" {
			if _, ok := batch["raw_values"]; ok {
				t.Fatal("unmeasured zero values exposed", n)
			}
		}
	}
}
func TestRejectCorruption(t *testing.T) {
	source := fixture(t, "read-batch.bin")
	mutations := []struct {
		N  string
		At int
		V  uint32
	}{
		{"size", 0, 1}, {"ABI", 4, 2}, {"magic", 8, 0}, {"safe active", offset(abi.Snapshot, "SafeToUnload"), 1},
		{"phase", offset(abi.Snapshot, "State") + offset(abi.State, "Phase"), 7},
		{"fault", offset(abi.Snapshot, "State") + offset(abi.State, "Fault"), 100},
		{"boolean", offset(abi.Snapshot, "Running"), 2},
		{"offers", offset(abi.Snapshot, "State") + offset(abi.State, "CurrentOffers"), 33},
		{"batch mask", offset(abi.Snapshot, "State") + offset(abi.State, "LastBatch") + offset(abi.Batch, "Battery"), 0},
		{"stored header", offset(abi.Snapshot, "State") + offset(abi.State, "LastBatch") + offset(abi.Batch, "Replies"), 0},
		{"stored property", offset(abi.Snapshot, "State") + offset(abi.State, "LastBatch") + offset(abi.Batch, "Replies") + 12, 99},
		{"stored value", offset(abi.Snapshot, "State") + offset(abi.State, "LastBatch") + offset(abi.Batch, "Replies") + 16, 9999},
		{"stored length", offset(abi.Snapshot, "State") + offset(abi.State, "LastBatch") + offset(abi.Batch, "ReplyBytes"), 99},
	}
	for _, m := range mutations {
		t.Run(m.N, func(t *testing.T) {
			b := append([]byte(nil), source...)
			binary.LittleEndian.PutUint32(b[m.At:], m.V)
			if _, e := decode(b); e == nil {
				t.Fatal("corruption accepted")
			}
		})
	}
	for _, n := range []int{0, 40, len(source) - 1, len(source) + 1} {
		b := make([]byte, n)
		copy(b, source)
		if _, e := decode(b); e == nil {
			t.Fatal("bad length accepted", n)
		}
	}
}
