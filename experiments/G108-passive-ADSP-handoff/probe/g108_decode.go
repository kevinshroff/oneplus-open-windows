package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

var le = binary.LittleEndian

const captureBytes = 5243232

func decodeStatus(b []byte) (map[string]any, error) {
	if len(b) != 80 || le.Uint32(b) != 80 || le.Uint32(b[4:]) != 1 || string(b[8:16]) != "OG108MR1" {
		return nil, errors.New("G108 status ABI")
	}
	v := map[string]any{}
	for i, n := range []string{"kernel_build", "processors", "IRQL", "firmware_bytes", "firmware_match", "firmware_status", "map_calls", "attempts", "ready", "fault"} {
		v[n] = le.Uint32(b[16+4*i:])
	}
	for i, n := range []string{"interrupt_time", "frequency", "sequence"} {
		v[n] = le.Uint64(b[56+8*i:])
	}
	return v, nil
}
func decodeCapture(b []byte, nonce uint64) (map[string]any, error) {
	if len(b) != captureBytes {
		return nil, errors.New("capture size")
	}
	s, e := decodeStatus(b[:80])
	if e != nil {
		return nil, e
	}
	if le.Uint64(b[80:]) != nonce {
		return nil, errors.New("nonce")
	}
	u := func(o int) uint32 { return le.Uint32(b[o:]) }
	code, mask, read, maps, n, payload := u(88), u(92), u(96), u(100), u(120), u(124)
	if n > 7 || payload > 0x500000 || maps > 14 || read > payload || mask&^uint32(127) != 0 || le.Uint64(b[112:]) < le.Uint64(b[104:]) {
		return nil, errors.New("capture counters")
	}
	rows := []map[string]any{}
	next := uint32(0)
	hosts := 0
	for i := uint32(0); i < n; i++ {
		at := 128 + 32*int(i)
		addr, size, offset, h0, h1, kind, status := le.Uint64(b[at:]), u(at+8), u(at+12), u(at+16), u(at+20), u(at+24), u(at+28)
		if size == 0 || size > 0x100000 || offset != next || offset > payload || 2*size > payload-offset || status > 2 {
			return nil, errors.New("region bounds")
		}
		if i < 5 {
			addresses := []uint64{0x81d00000, 0x81eff000, 0x81a00000, 0xa7605000, 0x146aa94c}
			sizes := []uint32{0x3000, 0x1000, 0x40000, 0x8000, 200}
			if addr != addresses[i] || size != sizes[i] || kind != i+1 || h0 != 0 || h1 != 0 {
				return nil, errors.New("fixed region")
			}
		} else {
			if kind != 6 || addr < 0x81d01000 || addr >= 0x81eff000 || uint64(size) > 0x81eff000-addr || addr&4095 != 0 || size&4095 != 0 {
				return nil, errors.New("SMEM extent")
			}
			h := 0
			if h0 == 0xfffe && h1 == 0xfffe {
				h = 1
			} else if (h0 == 0 && h1 == 2) || (h0 == 2 && h1 == 0) {
				h = 2
			} else {
				return nil, errors.New("SMEM hosts")
			}
			if hosts&h != 0 {
				return nil, errors.New("duplicate SMEM host pair")
			}
			hosts |= h
		}
		a, c := b[352+offset:352+offset+size], b[352+offset+size:352+offset+2*size]
		sa, sc := sha256.Sum256(a), sha256.Sum256(c)
		different := 0
		for j, v := range a {
			if v != c[j] {
				different++
			}
		}
		row := map[string]any{"kind": kind, "address": fmt.Sprintf("0x%x", addr), "bytes": size, "offset": offset, "host0": h0, "host1": h1, "status": status, "first_sha256": hex.EncodeToString(sa[:]), "second_sample_captured": mask&(1<<i) != 0}
		if mask&(1<<i) != 0 {
			row["second_sha256"] = hex.EncodeToString(sc[:])
			row["different_bytes"] = different
		}
		rows = append(rows, row)
		next += 2 * size
	}
	if next != payload {
		return nil, errors.New("payload total")
	}
	if code == 0 && (n != 7 || mask != 127 || read != payload || maps != 14 || hosts != 3 || s["attempts"] != uint32(1) || s["ready"] != uint32(1) || s["fault"] != uint32(0) || s["map_calls"] != maps) {
		return nil, errors.New("complete capture invariants")
	}
	return map[string]any{"operation_code": code, "complete_mask": mask, "read_bytes": read, "maps": maps, "region_count": n, "payload_bytes": payload, "begin_100ns": le.Uint64(b[104:]), "end_100ns": le.Uint64(b[112:]), "regions": rows, "physical_writes": 0}, nil
}
