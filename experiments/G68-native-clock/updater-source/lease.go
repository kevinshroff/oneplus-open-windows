package main

import (
	"encoding/hex"
	"fmt"
	"strings"
)

func validRAMDevice(device string) bool {
	s := strings.ToLower(device)
	const prefix = `\device\ramdisk{`
	if !strings.HasPrefix(s, prefix) || !strings.HasSuffix(s, "}") {
		return false
	}
	g := s[len(prefix) : len(s)-1]
	if len(g) != 36 || g[8] != '-' || g[13] != '-' || g[18] != '-' || g[23] != '-' {
		return false
	}
	b, e := hex.DecodeString(strings.ReplaceAll(g, "-", ""))
	return e == nil && len(b) == 16
}

// These independent volume queries must match the CRC-validated raw GPT target.
func verifySuperVolume(info, extents []byte, t Target, disk int, partition uint32) error {
	if t.Name != "super" || len(info) < 144 || u32(info, 0) != 1 || u64(info, 8) != t.Offset || u64(info, 16) != t.Bytes || u32(info, 24) != partition || guid(info[32:48]) != t.TypeGUID || guid(info[48:64]) != t.PartitionGUID || wstr(info[72:144]) != t.Name {
		return fmt.Errorf("super partition-volume identity mismatch")
	}
	if len(extents) < 32 || u32(extents, 0) != 1 || u32(extents, 8) != uint32(disk) || u64(extents, 16) != t.Offset || u64(extents, 24) != t.Bytes {
		return fmt.Errorf("super volume must have exactly one matching physical extent")
	}
	return nil
}
