// SPDX-License-Identifier: MIT
package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

const reportBytes = 608
const resourceMagic uint64 = 0x315352333647504f

func decodeCapture(b []byte) (map[string]any, error) {
	if len(b) != reportBytes {
		return nil, errors.New("G63 report length differs")
	}
	u := func(o int) uint32 { return binary.LittleEndian.Uint32(b[o:]) }
	q := func(o int) uint64 { return binary.LittleEndian.Uint64(b[o:]) }
	if u(0) != reportBytes || u(4) != 1 || q(8) != resourceMagic || u(72) != 20 || u(76) != 8 || u(92) != 0 {
		return nil, errors.New("G63 ABI header differs")
	}
	if u(16) != 26100 || u(20) != 8 || u(24) != 0 || u(28) != 730 || u(32) != 1 || u(36) != 0 {
		return nil, errors.New("G63 platform or exact table identity failed")
	}
	if u(60) != 1 || u(64) != 2 || u(68) != 2 || u(80) != 2 || u(84) != 2 || u(88) != 0 {
		return nil, errors.New("G63 capture is incomplete or resource counts differ")
	}
	if u(40) == 0 || u(40) != u(44)+1 || u(48) == 0 || u(48) != u(52)+1 || u(56) != 1 {
		return nil, errors.New("G63 resource/D0 lifecycle is not currently prepared and active")
	}
	out := map[string]any{"size": u(0), "version": u(4), "magic": fmt.Sprintf("0x%x", q(8)), "kernel_build": u(16), "processors": u(20), "IRQL": u(24), "firmware_bytes": u(28), "firmware_match": u(32), "firmware_status": u(36), "prepare_calls": u(40), "release_calls": u(44), "D0_entries": u(48), "D0_exits": u(52), "D0": u(56), "capture_complete": u(60), "raw_count": u(64), "translated_count": u(68), "descriptor_bytes": u(72), "capacity": u(76), "stored_raw": u(80), "stored_translated": u(84), "capture_flags": u(88)}
	for k, off := range map[string]int{"raw": 96, "translated": 352} {
		rows := make([]map[string]any, 0, 2)
		for i := 0; i < 8; i++ {
			v := b[off+i*32 : off+(i+1)*32]
			if i >= 2 {
				for _, x := range v {
					if x != 0 {
						return nil, errors.New("unused descriptor slot is nonzero")
					}
				}
				continue
			}
			for _, x := range v[20:] {
				if x != 0 {
					return nil, errors.New("descriptor padding is nonzero")
				}
			}
			row := map[string]any{"type": v[0], "share_disposition": v[1], "flags": binary.LittleEndian.Uint16(v[2:]), "raw_hex": hex.EncodeToString(v[:20])}
			if i == 0 {
				if v[0] != 3 || v[1] != 1 || binary.LittleEndian.Uint16(v[2:]) != 0 || binary.LittleEndian.Uint64(v[4:]) != 0xa90000 || binary.LittleEndian.Uint32(v[12:]) != 0x4000 {
					return nil, errors.New("assigned GENI memory shape differs")
				}
				row["start"] = uint64(0xa90000)
				row["length"] = uint32(0x4000)
			} else {
				if v[0] != 2 || v[1] != 1 || binary.LittleEndian.Uint16(v[2:]) != 0 {
					return nil, errors.New("assigned GENI line interrupt shape differs")
				}
				level, group, vector, aff := binary.LittleEndian.Uint16(v[4:]), binary.LittleEndian.Uint16(v[6:]), binary.LittleEndian.Uint32(v[8:]), binary.LittleEndian.Uint64(v[12:])
				if k == "raw" && vector != 389 {
					return nil, errors.New("raw ACPI GENI interrupt number differs")
				}
				row["level"] = level
				row["group"] = group
				row["vector"] = vector
				row["affinity"] = aff
			}
			rows = append(rows, row)
		}
		out[k] = rows
	}
	out["resource_shape_matches_pilot"] = true
	out["native_resource_handoff_qualified_by_decode_alone"] = false
	out["actual_IRQ_delivery_qualified"] = false
	out["functional_SPI_controller_qualified"] = false
	return out, nil
}
func tokenOK(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
