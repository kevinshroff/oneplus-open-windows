// SPDX-License-Identifier: MIT
package main

import (
	"encoding/binary"
	"fmt"
)

var le = binary.LittleEndian

const captureBytes = 320
const magic uint64 = 0x314f49353231474f

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
