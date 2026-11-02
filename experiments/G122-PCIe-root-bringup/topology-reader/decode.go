// SPDX-License-Identifier: MIT
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
)

var le = binary.LittleEndian

const dsdtSHA = "c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01"

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func tableSummary(sig string, b []byte) (map[string]any, error) {
	if len(sig) != 4 || len(b) < 36 || len(b) > 1<<20 || string(b[:4]) != sig || le.Uint32(b[4:]) != uint32(len(b)) {
		return nil, fmt.Errorf("ACPI header/bounds: %s", sig)
	}
	var sum byte
	for _, v := range b {
		sum += v
	}
	return map[string]any{"signature": sig, "bytes": len(b), "sha256": digest(b), "checksum_valid": sum == 0, "revision": b[8], "raw": b}, nil
}
func inventory(b []byte) ([]string, map[string]int, error) {
	if len(b) == 0 || len(b)%4 != 0 || len(b) > 65536 {
		return nil, nil, fmt.Errorf("ACPI enumeration bounds")
	}
	names := []string{}
	counts := map[string]int{}
	for i := 0; i < len(b); i += 4 {
		n := string(b[i : i+4])
		for _, v := range []byte(n) {
			if v < 0x20 || v > 0x7e {
				return nil, nil, fmt.Errorf("invalid ACPI table ID")
			}
		}
		names = append(names, n)
		counts[n]++
	}
	sort.Strings(names)
	return names, counts, nil
}
