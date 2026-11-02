package main

import (
	"encoding/binary"
)

var le = binary.LittleEndian

func u(b []byte, o int) uint32 { return le.Uint32(b[o:]) }
func require(ok bool, why string) {
	if !ok {
		panic(why)
	}
}
func status(b []byte) map[string]any {
	require(len(b) >= 96 && u(b, 0) == 96 && u(b, 4) == 1 && le.Uint64(b[8:]) == 0x314c43303947504f, "status ABI")
	require(u(b, 16) == 26300 && u(b, 20) == 8 && u(b, 24) == 0 && u(b, 28) == 576 && u(b, 32) == 1 && u(b, 36) == 50 && u(b, 40) == 0, "platform status refusal")
	return map[string]any{"kernel_build": u(b, 16), "CPUs": u(b, 20), "map_calls": u(b, 44), "run_attempts": u(b, 80), "observer_captures": u(b, 84), "observer_fault": u(b, 88), "off_verified": u(b, 92)}
}
