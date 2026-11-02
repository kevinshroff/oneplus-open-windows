package main

import (
	"encoding/binary"
	"fmt"
)

var le = binary.LittleEndian

const captureBytes = 4864
const magic uint64 = 0x315044303131474f

func encodeRequest(nonce uint64) []byte {
	q := make([]byte, 32)
	le.PutUint32(q, 32)
	le.PutUint32(q[4:], 1)
	le.PutUint64(q[8:], magic)
	le.PutUint64(q[16:], nonce)
	return q
}

func decodeStatus(b []byte) (map[string]any, error) {
	if len(b) != 80 || le.Uint32(b) != 80 || le.Uint32(b[4:]) != 1 || le.Uint64(b[8:]) != magic {
		return nil, fmt.Errorf("status ABI")
	}
	s := map[string]any{}
	for i, k := range []string{"kernel_build", "processors", "IRQL", "firmware_bytes", "firmware_match", "firmware_status", "map_calls", "attempts", "ready", "fault"} {
		s[k] = le.Uint32(b[16+i*4:])
	}
	for i, k := range []string{"interrupt_time", "frequency", "sequence"} {
		s[k] = le.Uint64(b[56+i*8:])
	}
	return s, nil
}

var plan = []struct {
	page uint64
	off  []uint32
}{
	{0xaf08000, []uint32{0x0, 0xc, 0xa4}},
	{0xaf09000, []uint32{0x0, 0x4}},
	{0xaf0a000, []uint32{0x0, 0x4}},
	{0xaf0b000, []uint32{0x0, 0x4}},
	{0xae00000, []uint32{0x0}},
	{0xae05000, []uint32{0x0, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x30, 0x38, 0x16c, 0x170, 0x174, 0x17c}},
	{0xae07000, []uint32{0x0, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x30, 0x38, 0x16c, 0x170, 0x174, 0x17c}},
	{0xae09000, []uint32{0x0, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x30, 0x38, 0x16c, 0x170, 0x174, 0x17c}},
	{0xae0b000, []uint32{0x0, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x30, 0x38, 0x16c, 0x170, 0x174, 0x17c}},
	{0xae25000, []uint32{0x0, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x30, 0x38, 0x16c, 0x170, 0x174, 0x17c}},
	{0xae27000, []uint32{0x0, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x30, 0x38, 0x16c, 0x170, 0x174, 0x17c}},
	{0xae29000, []uint32{0x0, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x30, 0x38, 0x16c, 0x170, 0x174, 0x17c}},
	{0xae2b000, []uint32{0x0, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x30, 0x38, 0x16c, 0x170, 0x174, 0x17c}},
	{0xae2d000, []uint32{0x0, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x30, 0x38, 0x16c, 0x170, 0x174, 0x17c}},
	{0xae2f000, []uint32{0x0, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x30, 0x38, 0x16c, 0x170, 0x174, 0x17c}},
	{0xae6a000, []uint32{0x604}},
	{0xae6b000, []uint32{0x604}},
}

func decodeCapture(b []byte, nonce uint64) (map[string]any, error) {
	if len(b) != captureBytes || le.Uint64(b[80:]) != nonce {
		return nil, fmt.Errorf("capture ABI")
	}
	s, e := decodeStatus(b[:80])
	if e != nil {
		return nil, e
	}
	count, payload := le.Uint32(b[120:]), le.Uint32(b[124:])
	if count > 17 || payload > 4096 {
		return nil, fmt.Errorf("capture bounds")
	}
	var regions []map[string]any
	var nextOffset uint32
	var completed uint32
	for i := uint32(0); i < count; i++ {
		r := b[128+32*i:]
		address, n, off, kind, state := le.Uint64(r), le.Uint32(r[8:]), le.Uint32(r[12:]), le.Uint32(r[24:]), le.Uint32(r[28:])
		if address != plan[i].page || n != uint32(len(plan[i].off))*4 || kind != i || off != nextOffset || off > payload || 2*n > payload-off || state > 3 || state == 2 {
			return nil, fmt.Errorf("fixed region mismatch %d", i)
		}
		nextOffset += 2 * n
		if state == 3 {
			completed |= 1 << i
		}
		var words []map[string]any
		for j, offset := range plan[i].off {
			word := map[string]any{"address": fmt.Sprintf("0x%x", address+uint64(offset))}
			if state&1 != 0 {
				word["first"] = fmt.Sprintf("0x%08x", le.Uint32(b[768+int(off)+j*4:]))
			}
			if state&2 != 0 {
				word["second"] = fmt.Sprintf("0x%08x", le.Uint32(b[768+int(off+n)+j*4:]))
			}
			words = append(words, word)
		}
		region := map[string]any{"page": fmt.Sprintf("0x%x", address), "samples_mask": state, "words": words}
		if state == 3 {
			changed := 0
			for j := 0; j < int(n); j++ {
				if b[768+int(off)+j] != b[768+int(off+n)+j] {
					changed++
				}
			}
			region["changed_bytes"] = changed
		}
		regions = append(regions, region)
	}
	if nextOffset != payload || completed != le.Uint32(b[92:]) || (le.Uint32(b[88:]) == 0 && (count != 17 || completed != 0x1ffff)) || le.Uint64(b[112:]) < le.Uint64(b[104:]) {
		return nil, fmt.Errorf("completion or time bounds")
	}
	return map[string]any{"status": s, "capture_code": le.Uint32(b[88:]), "complete_mask": le.Uint32(b[92:]), "read_bytes_including_gate_rechecks": le.Uint32(b[96:]), "map_calls": le.Uint32(b[100:]), "begin": le.Uint64(b[104:]), "end": le.Uint64(b[112:]), "regions": regions, "configuration_writes": 0, "physical_address_ownership_qualified": false}, nil
}
