// SPDX-License-Identifier: MIT
package main

import (
	"encoding/binary"
	"fmt"
)

var le = binary.LittleEndian

const captureBytes = 136
const magic uint64 = 0x314f49313231474f

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
func decodeCapture(b []byte, nonce uint64) (map[string]any, error) {
	if len(b) != captureBytes || nonce == 0 || le.Uint64(b[80:]) != nonce {
		return nil, fmt.Errorf("capture ABI")
	}
	s, e := decodeStatus(b[:80])
	if e != nil {
		return nil, e
	}
	code, mask, reads, maps := le.Uint32(b[88:]), le.Uint32(b[92:]), le.Uint32(b[96:]), le.Uint32(b[100:])
	begin, end := le.Uint64(b[104:]), le.Uint64(b[112:])
	if maps > 1 || mask != 0 && mask != 1 && mask != 3 || reads > 16 || reads%4 != 0 || end < begin || s["attempts"] != uint32(1) || s["ready"] != uint32(1) || s["map_calls"] != maps || s["fault"] != uint32(boolInt(code != 0)) {
		return nil, fmt.Errorf("capture bounds/status")
	}
	first := [2]uint32{le.Uint32(b[120:]), le.Uint32(b[124:])}
	second := [2]uint32{le.Uint32(b[128:]), le.Uint32(b[132:])}
	switch code {
	case 0, 2001, 2002:
		if maps != 1 || mask != 3 || reads != 16 || s["kernel_build"] != uint32(26300) || s["processors"] != uint32(8) || s["IRQL"] != uint32(0) || s["firmware_bytes"] != uint32(576) || s["firmware_match"] != uint32(1) || s["firmware_status"] != uint32(0) {
			return nil, fmt.Errorf("completed capture identity")
		}
		unsuitable := first[0]&0x123c != 0 || second[0]&0x123c != 0
		expected := uint32(0)
		if unsuitable {
			expected = 2001
		} else if first != second {
			expected = 2002
		}
		if code != expected {
			return nil, fmt.Errorf("qualification/code mismatch")
		}
	case 1001, 1002:
		if maps != 0 || mask != 0 || reads != 0 {
			return nil, fmt.Errorf("refusal accessed MMIO")
		}
	case 1005:
		if maps != 1 || mask != 0 || reads != 0 {
			return nil, fmt.Errorf("failed map read data")
		}
	case 1004:
		if maps == 0 && (reads != 0 || mask != 0) || maps == 1 && !((mask == 0 && (reads == 0 || reads == 4)) || (mask == 1 && (reads == 8 || reads == 12))) {
			return nil, fmt.Errorf("cancellation progress")
		}
	default:
		return nil, fmt.Errorf("unknown capture code")
	}
	// Even partial reads are retained exactly, but never become a selector ID.
	if reads < 4 && first[0] != 0 || reads < 8 && first[1] != 0 || reads < 12 && second[0] != 0 || reads < 16 && second[1] != 0 {
		return nil, fmt.Errorf("unread word is nonzero")
	}
	r := map[string]any{"status": s, "capture_code": code, "complete_mask": mask, "read_bytes": reads, "map_calls": maps, "begin": begin, "end": end, "raw_words": [2][2]uint32{first, second}, "configuration_writes": 0, "source_selection_qualified": code == 0, "physical_PCI_identity_verified": false, "scope": "OEM GPIO selection; analog validity, endpoint identity and working PCIe remain unqualified"}
	if code == 0 {
		level := first[1] & 1
		r["GPIO"] = 83
		r["input_level"] = level
		if level == 0 {
			r["source_selected_device_id"] = "0x1107"
			r["source_selected_root_complex"] = 0
			r["family_alias"] = "Kiwi/HMT"
		} else {
			r["source_selected_device_id"] = "0x1103"
			r["source_selected_root_complex"] = 1
			r["family_alias"] = "QCA6490/HSP"
		}
	}
	return r, nil
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
