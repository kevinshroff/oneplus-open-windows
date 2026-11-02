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
	for _, mode := range []string{"status", "snapshot", "start", "sample", "close", "board-fv"} {
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
	for _, n := range []string{"open.bin", "read-batch.bin", "closed.bin", "refused.bin", "uncertain.bin", "board-fv.bin", "board-fv-timeout.bin"} {
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

func TestControlAckIsNeverVoltageReadback(t *testing.T) {
	b := fixture(t, "board-fv.bin")
	start := offset(abi.Snapshot, "State") + offset(abi.State, "LastBatch")
	raw := start + offset(abi.Batch, "Replies") + 10*1024
	for _, word4 := range []uint32{0, 4470, 8900000, 0xdeadbeef, 0xffffffff} {
		binary.LittleEndian.PutUint32(b[raw+16:], word4)
		r, e := decode(b)
		if e != nil {
			t.Fatal(e)
		}
		batch := r["last_batch"].(map[string]any)
		if _, ok := batch["raw_values"]; ok {
			t.Fatal("stale SET word4 exposed as voltage")
		}
		if batch["requested_mV"] != uint32(4470) || batch["hardware_readback_required"] != true || batch["service_result"] != uint32(0) {
			t.Fatal(batch)
		}
	}
	for _, at := range []int{start + offset(abi.Batch, "Kind"), start + offset(abi.Batch, "Reserved"), raw + 8, raw + 12, raw + 20} {
		c := append([]byte(nil), b...)
		binary.LittleEndian.PutUint32(c[at:], 99)
		if _, e := decode(c); e == nil {
			t.Fatal("invalid control binding", at)
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
