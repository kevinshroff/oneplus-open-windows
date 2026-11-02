package main

// Exact G200 GCC/TLMM source addresses. No transient peripheral MMIO until this ACTIVE predicate passes.
var activeAddresses = []uint64{0x152020, 0x152000, 0x152008, 0x16b000, 0x16b004, 0x16b008, 0x16b01c, 0x16b020, 0x16b038, 0x16b03c, 0x16b054, 0x16c000, 0x16c004, 0x16c01c, 0xf15e000, 0xf15e004, 0xf150000, 0xf150004, 0xf153000, 0xf153004}

func allowed(a uint64, active bool) bool {
	if a&3 != 0 {
		return false
	}
	for _, v := range activeAddresses {
		if a == v {
			return true
		}
	}
	if !active {
		return false
	}
	for _, v := range []uint64{0x60000000, 0x6000000c, 0x60000080, 0x1c001b0, 0x60100000, 0x60100004, 0x6010000c, 0x60100010, 0x60100014, 0x60100040, 0x60100044} {
		if a == v {
			return true
		}
	}
	return false
}
func activeReady(v []uint32) bool {
	if len(v) != len(activeAddresses) {
		return false
	}
	for _, x := range v {
		if x == 0xffffffff {
			return false
		}
	}
	if v[0]&9 != 0 || v[4]&0x80000000 == 0 || v[11]&0x80000000 == 0 || v[5]&0x18000 != 0x10000 || v[12]&0x18000 != 0x10000 {
		return false
	}
	if v[3]&1 != 0 || v[13]&1 != 0 || v[1]&(1<<22) == 0 || v[2]&0x3f != 0x3f {
		return false
	}
	// Only HALT_VOTED branches: Q2A,SLV,CFG,Aux,rate-change. No MSTR or PIPE halt-bit predicate.
	for _, i := range []int{6, 7, 8, 9, 10} {
		if v[i]&0x80000000 != 0 {
			return false
		}
	}
	// Active stage: PERST94 and WLAN_EN80 GPIO outputs HIGH. Unlike early G200 PERST-low guard.
	if v[14]&0x123c != 0x200 || v[15]&3 != 3 || v[16]&0x123c != 0x200 || v[17]&3 != 3 {
		return false
	}
	// GPIO83 is an early CNSS device-identifier input, not a runtime power/access predicate.
	// Keep GPIO mux/input/EGPIO qualification; report either input level without a TLMM write.
	return v[18]&0x123c == 0
}
func equalWords(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		// Input status may change; its configuration and all access-safety fields must remain stable.
		if i == 19 {
			if (a[i]^b[i]) & ^uint32(1) != 0 {
				return false
			}
			continue
		}
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// No window, doorbell, interrupt, reset or error-clear register is addressable.
func faultAllowed(a uint64) bool {
	for _, v := range []uint64{0x63e00028, 0x63e00048, 0x63e00128, 0x63e0012c, 0x63e00130, 0x63e00134, 0x63e00138, 0x63e0013c} {
		if a == v {
			return true
		}
	}
	return false
}
