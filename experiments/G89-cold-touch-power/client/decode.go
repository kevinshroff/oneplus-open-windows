package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

var le = binary.LittleEndian

func u(b []byte, o int) uint32 { return le.Uint32(b[o:]) }
func require(ok bool, why string) {
	if !ok {
		panic(why)
	}
}
func status(b []byte) map[string]any {
	require(len(b) >= 96 && u(b, 0) == 96 && u(b, 4) == 1 && le.Uint64(b[8:]) == 0x314c43393847504f, "status ABI")
	require(u(b, 16) == 26300 && u(b, 20) == 8 && u(b, 24) == 0 && u(b, 28) == 576 && u(b, 32) == 1 && u(b, 36) == 50 && u(b, 40) == 0, "platform status refusal")
	return map[string]any{"kernel_build": u(b, 16), "CPUs": u(b, 20), "map_calls": u(b, 44), "run_attempts": u(b, 80), "observer_captures": u(b, 84), "observer_fault": u(b, 88), "off_verified": u(b, 92)}
}
func fixed(b []byte) {
	require(len(b) == 200, "fixed snapshot size")
	for i, want := range expected {
		v := u(b, i*4)
		if i == 12 {
			require(v == 0 || v == 7, "unknown response history")
		} else {
			require(v == want, fmt.Sprintf("fixed register %d: got %x want %x", i, v, want))
		}
	}
}
func snapshot(b []byte) []byte {
	require(len(b) == 304, "snapshot ABI")
	status(b)
	require(u(b, 96) == 50 && u(b, 100) == 0, "snapshot count")
	fixed(b[104:])
	return b[104:]
}
func pmic(b []byte, on bool) map[string]any {
	require(len(b) == 1620, "observer ABI")
	code := u(b, 0)
	want := byte(0x43)
	cfg := []byte{8, 7, 0, 0, 7, 7, 0, 0}
	if on {
		want = 0xc7
		cfg = []byte{8, 7, 8, 7, 7, 7, 128, 0}
	}
	require(code == 0 && b[68] == want && bytes.Equal(b[69:77], cfg), "independent PMIC state")
	require(u(b, 12) == 5 && u(b, 20) == 5 && u(b, 80) <= 128 && u(b, 80) == u(b, 8)+u(b, 12), "observer counters")
	return map[string]any{"status": fmt.Sprintf("0x%02x", b[68]), "configuration": fmt.Sprintf("%x", b[69:77])}
}
func outsidePmic(b []byte) map[string]any {
	require(len(b) == 1744, "external observer ABI")
	status(b)
	p := pmic(b[96:1716], false)
	require(u(b, 1716) == 1, "observer changed fixed registers")
	return p
}
func runResult(b []byte, nonce uint64) map[string]any {
	require(len(b) == 44848, "run ABI")
	status(b)
	require(le.Uint64(b[96:]) == nonce, "run nonce")
	p := b[104:44412]
	result := map[string]any{"code": u(p, 0), "restore_error": u(p, 4), "restored": u(p, 8), "on_verified": u(p, 40), "off_verified": u(p, 44), "transactions": u(p, 56), "observers": u(p, 60), "before_raw": u(p, 120), "on_raw": u(p, 136), "after_raw": u(p, 148)}
	require(u(p, 0) == 0 && u(p, 4) == 0 && u(p, 8) == 1 && u(p, 12) == 0, "cold lease operation or restore failed")
	for _, o := range []int{16, 20, 24, 36, 40, 44, 76, 80, 100} {
		require(u(p, o) == 1, fmt.Sprintf("lease flag %d", o))
	}
	for _, o := range []int{28, 32, 48, 52} {
		require(u(p, o) == 0, fmt.Sprintf("lease uncertainty %d", o))
	}
	require(u(p, 56) == 12 && u(p, 60) == 3 && u(p, 84) == 4 && u(p, 88) == 9 && u(p, 92) == 12 && u(p, 108) == 2, "lease budgets/order")
	require(u(p, 112) == 1800 && u(p, 116) == 7 && u(p, 120) == 0 && u(p, 124) == 1800 && u(p, 128) == 7 && u(p, 132) == 0x80000001 && u(p, 136) == 0x80000001 && u(p, 140) == 1800 && u(p, 144) == 7 && u(p, 148) == 0, "cold profile readbacks")
	require(bytes.Equal(p[152:184], p[184:216]) && bytes.Equal(p[152:184], p[216:248]) && bytes.Equal(p[152:184], p[248:280]), "pin guards changed")
	onWrites, offWrites := 0, 0
	for i := 0; i < 12; i++ {
		t := p[280+i*3264 : 280+(i+1)*3264]
		require(u(t, 0) == 0 && u(t, 4) == 0 && u(t, 8) == 1 && u(t, 12) == 0 && u(t, 16) <= 192 && u(t, 20) == 14 && u(t, 24) == u(t, 16)+u(t, 20) && u(t, 24) <= 256 && u(t, 48) == 1 && u(t, 52) == 1, "RSC transaction failure/budget")
		at, data, msg, c := u(t, 28), u(t, 32), u(t, 36), u(t, 40)
		switch msg {
		case 0x10108:
			require(at == 0x40804 && data == 1 && i == 3, "ON request")
			onWrites++
		case 0x10008:
			require(at == 0x40804 && data == 0 && i == 8 && c == 0x101, "OFF request")
			offWrites++
		case 0x108:
			require(data == 0 && (at == 0x40800 || at == 0x40804 || at == 0x40808), "read query")
		default:
			panic("unknown resource command")
		}
		if msg != 0x10008 {
			require(c&0x10100 == 0x10100, "response not completed")
		}
	}
	require(onWrites == 1 && offWrites == 1, "one ON and one OFF required")
	states := []any{}
	for i := 0; i < 3; i++ {
		require(u(p, 64+i*4) == uint32(i), "PMIC observation order")
		states = append(states, pmic(p[39448+i*1620:39448+(i+1)*1620], i == 1))
	}
	fixed(b[44412:44612])
	require(bytes.Equal(b[44412:44612], b[44612:44812]) && u(b, 44812) == 1 && u(b, 44816) == 1 && u(b, 44820) == 1, "post-run fixed baseline")
	result["PMIC"] = states
	freq := le.Uint64(b[44840:])
	require(freq != 0, "counter frequency")
	result["elapsed_ms"] = float64(le.Uint64(b[44832:])) * 1000 / float64(freq)
	return result
}
