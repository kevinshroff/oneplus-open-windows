package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const dtbDigest = "f71892ad4ff2ac1100a07f63b4a5ef246749a95937a797d50480e7c70b1b2f94"

type DtbCheck struct {
	Status                              string    `json:"status"`
	CpuEL                               uint64    `json:"CPU_EL"`
	CpuPages                            uint64    `json:"CPU_pages"`
	AtQueries                           uint64    `json:"AT_queries"`
	FirstBad                            string    `json:"first_bad"`
	ReadPar                             string    `json:"read_PAR"`
	WritePar                            string    `json:"write_PAR"`
	Reason                              uint32    `json:"reason"`
	Clock                               [5]uint32 `json:"clock_words"`
	HwVersion                           uint32    `json:"MDSS_version"`
	Demura                              [2]uint32 `json:"Demura_words"`
	MmioReads                           uint32    `json:"MMIO_reads"`
	MmioPages                           uint32    `json:"MMIO_pages"`
	Complete                            bool      `json:"complete"`
	status, firstBad, readPar, writePar uint64
}
type DtbAdmission struct {
	CopyAttempts              uint32      `json:"copy_attempts"`
	PayloadAttempts           uint32      `json:"payload_attempts"`
	CopyGranted               bool        `json:"copy_granted"`
	PayloadHashed             bool        `json:"payload_hashed"`
	PayloadMatched            bool        `json:"payload_matched"`
	HashOutcome               uint32      `json:"hash_outcome"`
	CopyStatus                string      `json:"copy_status"`
	PayloadStatus             string      `json:"payload_status"`
	Checks                    [3]DtbCheck `json:"checks"`
	Digest                    string      `json:"SHA256"`
	FiniteAdmissionComplete   bool        `json:"finite_DTB_admission_complete"`
	GlobalDmaQualified        bool        `json:"global_DMA_ownership_qualified"`
	ProductionPowerLease      bool        `json:"production_power_lease_qualified"`
	copyStatus, payloadStatus uint64
}

func decodeDtbAdmission(d []byte) (DtbAdmission, error) {
	var r DtbAdmission
	if len(d) != 392 {
		return r, fmt.Errorf("G146 DTB admission size")
	}
	u := func(n int) uint32 { return binary.LittleEndian.Uint32(d[n:]) }
	q := func(n int) uint64 { return binary.LittleEndian.Uint64(d[n:]) }
	h := func(n int) string { return fmt.Sprintf("0x%016x", q(n)) }
	if u(0) != 392 || u(4) != 1 {
		return r, fmt.Errorf("G146 DTB admission ABI")
	}
	r.CopyAttempts, r.PayloadAttempts = u(8), u(12)
	r.CopyGranted, r.PayloadHashed, r.PayloadMatched = u(16) == 1, u(20) == 1, u(24) == 1
	r.HashOutcome = u(28)
	r.CopyStatus, r.PayloadStatus = h(32), h(40)
	r.copyStatus, r.payloadStatus = q(32), q(40)
	r.Digest = hex.EncodeToString(d[360:392])
	if r.CopyAttempts > 1 || r.PayloadAttempts > 1 || u(16) > 1 || u(20) > 1 || u(24) > 1 || r.HashOutcome > 3 {
		return r, fmt.Errorf("G146 DTB admission counters")
	}
	for i := range r.Checks {
		n := 48 + 104*i
		c := &r.Checks[i]
		c.Status, c.CpuEL, c.CpuPages, c.AtQueries = h(n), q(n+8), q(n+16), q(n+24)
		c.FirstBad, c.ReadPar, c.WritePar = h(n+32), h(n+40), h(n+48)
		c.status, c.firstBad, c.readPar, c.writePar = q(n), q(n+32), q(n+40), q(n+48)
		c.Reason = u(n + 56)
		for j := range c.Clock {
			c.Clock[j] = u(n + 60 + 4*j)
		}
		c.HwVersion = u(n + 80)
		c.Demura = [2]uint32{u(n + 84), u(n + 88)}
		c.MmioReads, c.MmioPages, c.Complete = u(n+92), u(n+96), u(n+100) == 1
		if c.CpuEL > 3 || c.CpuPages > 3 || c.AtQueries > 11 || c.MmioReads > 64 || c.MmioPages > 5 || u(n+100) > 1 || c.Reason&^uint32(1023) != 0 {
			return r, fmt.Errorf("G146 DTB check counters %d", i)
		}
		if c.Complete {
			if c.status != 0 || c.Reason != 0 || (c.CpuEL != 1 && c.CpuEL != 2) || c.CpuPages != 3 || c.AtQueries != 11 || c.firstBad != 0 || c.readPar&1 != 0 || c.writePar&1 != 0 || c.readPar>>56 != 0x44 || c.writePar>>56 != 0x44 || c.readPar&0x000ffffffffff000 != 0x9e982000 || c.writePar&0x000ffffffffff000 != 0x9e982000 || c.MmioReads != 43 || c.MmioPages != 5 || c.HwVersion != 0x90000001 || c.Demura != [2]uint32{} || c.Clock[0]&1 != 0 || c.Clock[1]&0x80000001 != 1 || c.Clock[2]&0x80000001 != 1 || c.Clock[3]&0x80000007 != 0x80000000 || c.Clock[4]&0x18000 != 0x10000 {
				return r, fmt.Errorf("G146 DTB check completion contradiction %d", i)
			}
		} else if c.status == 0 {
			return r, fmt.Errorf("G146 incomplete DTB check reports success %d", i)
		}
	}
	if r.CopyGranted != (r.CopyAttempts == 1 && r.copyStatus == 0 && r.Checks[0].Complete) {
		return r, fmt.Errorf("G146 DTB copy completion contradiction")
	}
	if r.PayloadHashed != (r.HashOutcome == 2 || r.HashOutcome == 3) || r.PayloadMatched != (r.HashOutcome == 3) {
		return r, fmt.Errorf("G146 DTB hash outcome contradiction")
	}
	if r.HashOutcome != 0 && (!r.CopyGranted || r.PayloadAttempts != 1 || !r.Checks[1].Complete) {
		return r, fmt.Errorf("G146 DTB hash without prior admission")
	}
	if r.PayloadMatched && r.Digest != dtbDigest {
		return r, fmt.Errorf("G146 DTB digest differs")
	}
	if r.HashOutcome == 2 && r.Digest == dtbDigest {
		return r, fmt.Errorf("G146 DTB mismatch has expected digest")
	}
	if r.Checks[2].Complete && (!r.PayloadMatched || r.payloadStatus != 0) {
		return r, fmt.Errorf("G146 DTB final check without accepted hash")
	}
	r.FiniteAdmissionComplete = r.CopyGranted && r.PayloadAttempts == 1 && r.PayloadMatched && r.Checks[1].Complete && r.Checks[2].Complete && r.payloadStatus == 0
	if r.payloadStatus == 0 && !r.FiniteAdmissionComplete {
		return r, fmt.Errorf("G146 DTB payload status contradiction")
	}
	return r, nil
}
func bindDtbAdmission(r *Report, publicStatus uint64) error {
	enteredAuth := uint32(0)
	acceptedAuth := uint32(0)
	next := 0
	expected := [3]uint32{0x42000201, 0x42000202, 0x42000205}
	acceptedSequence := r.RecordCount == 3 && r.Fault == 0 && r.Phase == [2]uint32{3, 0}
	for _, v := range r.Records {
		if v.Entered == 1 {
			if v.Returned != 1 || next >= 3 || v.Command != expected[next] {
				return fmt.Errorf("G146 forwarded PAS order")
			}
			next++
			if v.Command == 0x42000205 {
				enteredAuth = 1
				if !r.Dtb.FiniteAdmissionComplete {
					return fmt.Errorf("G146 AUTH without finite payload admission")
				}
				if v.OriginalStatus == 0 && v.Results[0] == 1 && v.Results[1] == 0 && v.ReturnedStatus == 0 && v.Refusal == 0 {
					acceptedAuth = 1
				}
			}
		}
		acceptedSequence = acceptedSequence && v.Entered == 1 && v.Returned == 1 && v.OriginalStatus == 0 && v.Results[0] == 1 && v.Results[1] == 0 && v.ReturnedStatus == 0 && v.Refusal == 0
	}
	if r.AuthEntered != enteredAuth || r.AuthAccepted != acceptedAuth {
		return fmt.Errorf("G146 AUTH mask/ledger contradiction")
	}
	if (r.AuthAccepted == 1) != (r.Phase[0] == 3) || r.Phase[0] >= 2 && !r.MemorySetupAccepted {
		return fmt.Errorf("G146 phase/accepted stage contradiction")
	}
	if r.Dtb.CopyAttempts != 0 && !r.MemorySetupAccepted {
		return fmt.Errorf("G146 copy attempted before accepted MEM_SETUP")
	}
	if r.Dtb.PayloadAttempts != 0 && (!r.Dtb.CopyGranted || r.RecordCount < 3 || r.Records[2].Command != 0x42000205) {
		return fmt.Errorf("G146 payload check outside AUTH boundary")
	}
	r.SequenceAccepted = acceptedSequence && r.Dtb.FiniteAdmissionComplete && r.AuthAccepted == 1
	expectedPublic := r.LoadReturned && publicStatus == 0 && r.AuthAccepted == 1 && r.Phase == [2]uint32{3, 0} && r.Fault == 0
	if r.DtbPublicSuccess != expectedPublic || r.DtbPublicSuccess && !r.SequenceAccepted {
		return fmt.Errorf("G146 public loader success contradiction")
	}
	r.DiagnosticStop = r.StopBeforeMain && r.DtbPublicSuccess
	if r.LoadReturned != (r.PilRequests == 1) {
		return fmt.Errorf("G146 public loader return/request contradiction")
	}
	if r.FinalStatus == "0x8000000000000015" && (!r.DiagnosticStop || r.Flags&128 == 0) {
		return fmt.Errorf("G146 aborted status without completed DTB/restoration")
	}
	return nil
}
