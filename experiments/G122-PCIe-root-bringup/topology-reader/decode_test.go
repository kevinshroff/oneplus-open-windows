// SPDX-License-Identifier: MIT
package main

import (
	"testing"
)

func TestTableBoundsAndChecksum(t *testing.T) {
	b := make([]byte, 36)
	copy(b, "IORT")
	le.PutUint32(b[4:], 36)
	var sum byte
	for _, v := range b {
		sum += v
	}
	b[9] = 0 - sum
	r, e := tableSummary("IORT", b)
	if e != nil || r["checksum_valid"] != true {
		t.Fatal(r, e)
	}
	b[9]++
	r, e = tableSummary("IORT", b)
	if e != nil || r["checksum_valid"] != false {
		t.Fatal("must preserve bad checksum as evidence", r, e)
	}
	for _, n := range []int{0, 4, 35, 37, 1<<20 + 1} {
		c := make([]byte, n)
		copy(c, b)
		if _, e := tableSummary("IORT", c); e == nil {
			t.Fatal(n)
		}
	}
	if _, e := tableSummary("MCFG", b); e == nil {
		t.Fatal("wrong signature")
	}
}
func TestInventoryAndDuplicates(t *testing.T) {
	names, counts, e := inventory([]byte("DSDTSSDTIORTSSDTMCFG"))
	if e != nil || len(names) != 5 || counts["SSDT"] != 2 || names[0] != "DSDT" {
		t.Fatal(names, counts, e)
	}
	for _, b := range [][]byte{nil, []byte("IORTx"), []byte{'D', 'S', 'D', 0}, make([]byte, 65540)} {
		if _, _, e := inventory(b); e == nil {
			t.Fatal("invalid enumeration")
		}
	}
}
