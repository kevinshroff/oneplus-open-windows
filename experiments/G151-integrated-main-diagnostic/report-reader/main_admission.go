package main

import (
	"encoding/binary"
	"fmt"
)

type MainAdmission struct {
	Initialized                                             bool `json:"initialized"`
	CopyAttempts, RefreshAttempts, AcceptedRefreshes, Fault uint32
	CopyGranted                                             bool        `json:"copy_granted"`
	CopyStatus                                              string      `json:"copy_status"`
	RefreshStatus                                           [2]string   `json:"refresh_status"`
	Checks                                                  [3]DtbCheck `json:"checks"`
	FiniteComplete                                          bool        `json:"finite_admission_complete"`
	GlobalDmaQualified                                      bool        `json:"global_DMA_ownership_qualified"`
	ProductionPowerLease                                    bool        `json:"production_power_lease_qualified"`
	copyStatus                                              uint64
	refreshStatus                                           [2]uint64
}

func zeroBytes(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
func decodeMainAdmission(d []byte) (MainAdmission, error) {
	var r MainAdmission
	if len(d) != 368 {
		return r, fmt.Errorf("G151 main admission size")
	}
	if zeroBytes(d) {
		return r, nil
	} // DTB init failed before main initialization.
	u := func(n int) uint32 { return binary.LittleEndian.Uint32(d[n:]) }
	q := func(n int) uint64 { return binary.LittleEndian.Uint64(d[n:]) }
	h := func(n int) string { return fmt.Sprintf("0x%016x", q(n)) }
	if u(0) != 368 || u(4) != 1 || u(28) != 0 {
		return r, fmt.Errorf("G151 main admission ABI")
	}
	r.Initialized = true
	r.CopyAttempts, r.RefreshAttempts = u(8), u(12)
	r.CopyGranted, r.AcceptedRefreshes, r.Fault = u(16) == 1, u(20), u(24)
	r.CopyStatus, r.copyStatus = h(32), q(32)
	r.RefreshStatus = [2]string{h(40), h(48)}
	r.refreshStatus = [2]uint64{q(40), q(48)}
	if r.CopyAttempts > 1 || r.RefreshAttempts > 2 || u(16) > 1 || r.AcceptedRefreshes > r.RefreshAttempts || r.Fault&^uint32(7) != 0 {
		return r, fmt.Errorf("G151 main admission counters")
	}
	for i := range r.Checks {
		n := 56 + 104*i
		c := &r.Checks[i]
		c.Status, c.CpuEL, c.CpuPages, c.AtQueries = h(n), q(n+8), q(n+16), q(n+24)
		c.FirstBad, c.ReadPar, c.WritePar = h(n+32), h(n+40), h(n+48)
		c.status, c.firstBad, c.readPar, c.writePar = q(n), q(n+32), q(n+40), q(n+48)
		c.Reason = u(n + 56)
		for j := range c.Clock {
			c.Clock[j] = u(n + 60 + 4*j)
		}
		c.HwVersion, c.Demura = u(n+80), [2]uint32{u(n + 84), u(n + 88)}
		c.MmioReads, c.MmioPages, c.Complete = u(n+92), u(n+96), u(n+100) == 1
		if c.CpuEL > 3 || c.CpuPages > 15851 || c.AtQueries > 31707 || c.MmioReads > 64 || c.MmioPages > 5 || u(n+100) > 1 || c.Reason&^uint32(2047) != 0 {
			return r, fmt.Errorf("G151 main check counters %d", i)
		}
		if c.Complete {
			if c.status != 0 || c.Reason != 0 || (c.CpuEL != 1 && c.CpuEL != 2) || c.CpuPages != 15851 || c.AtQueries != 31707 || c.firstBad != 0 || c.readPar&1 != 0 || c.writePar&1 != 0 || c.readPar>>56 != 0x44 || c.writePar>>56 != 0x44 || c.readPar&0x000ffffffffff000 != 0xa2836000 || c.writePar&0x000ffffffffff000 != 0xa2836000 || c.MmioReads != 43 || c.MmioPages != 5 || c.HwVersion != 0x90000001 || c.Demura != [2]uint32{} || c.Clock[0]&1 != 0 || c.Clock[1]&0x80000001 != 1 || c.Clock[2]&0x80000001 != 1 || c.Clock[3]&0x80000007 != 0x80000000 || c.Clock[4]&0x18000 != 0x10000 {
				return r, fmt.Errorf("G151 main check completion contradiction %d", i)
			}
		} else if c.status == 0 {
			return r, fmt.Errorf("G151 incomplete main check reports success %d", i)
		}
	}
	if r.CopyGranted != (r.CopyAttempts == 1 && r.copyStatus == 0 && r.Checks[0].Complete) {
		return r, fmt.Errorf("G151 main copy contradiction")
	}
	for i := uint32(0); i < 2; i++ {
		if (i < r.AcceptedRefreshes) != (r.refreshStatus[i] == 0 && r.Checks[i+1].Complete) {
			return r, fmt.Errorf("G151 main refresh contradiction")
		}
		if i >= r.RefreshAttempts && r.Checks[i+1].Complete {
			return r, fmt.Errorf("G151 unattempted main refresh complete")
		}
	}
	if r.RefreshAttempts > 0 && !r.CopyGranted && r.Fault&1 == 0 {
		return r, fmt.Errorf("G151 main refresh before copy")
	}
	r.FiniteComplete = r.CopyGranted && r.RefreshAttempts == 2 && r.AcceptedRefreshes == 2 && r.Fault == 0
	return r, nil
}
