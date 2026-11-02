package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

type MainExtentResult struct {
	Index, Kind               uint32
	Complete                  bool
	Status                    string
	ReadBytes, FailureAddress uint64
	Digest                    string
	status                    uint64
}
type MainPayload struct {
	Initialized, Attempted, Complete                                                                                         bool
	Status                                                                                                                   string
	ReadBytes, VerifiedBytes, LastAddress, LastRequest, LastActual, LastReadStatus, FailureAddress                           uint64
	Fault, ReadCalls, OwnerChecks, AdmissionCalls, CompletedExtents, CompletedFiles, CompletedZeroTails, CurrentIndex, Phase uint32
	Extents                                                                                                                  []MainExtentResult
	status                                                                                                                   uint64
}

func decodeMainPayload(d []byte) (MainPayload, error) {
	var r MainPayload
	if len(d) != 6536 {
		return r, fmt.Errorf("G155 payload size")
	}
	if zeroBytes(d) {
		return r, nil
	}
	u := func(n int) uint32 { return binary.LittleEndian.Uint32(d[n:]) }
	q := func(n int) uint64 { return binary.LittleEndian.Uint64(d[n:]) }
	if u(0) != 6536 || u(4) != 1 || u(8) > 1 || u(12) > 1 || u(116) != 0 || u(120) != 0 || u(124) != 0 {
		return r, fmt.Errorf("G155 payload ABI")
	}
	r.Initialized = true
	r.Attempted, r.Complete = u(8) == 1, u(12) == 1
	r.status = q(16)
	r.Status = fmt.Sprintf("0x%016x", r.status)
	r.ReadBytes, r.VerifiedBytes, r.LastAddress, r.LastRequest, r.LastActual, r.LastReadStatus, r.FailureAddress = q(24), q(32), q(40), q(48), q(56), q(64), q(72)
	r.Fault, r.ReadCalls, r.OwnerChecks, r.AdmissionCalls = u(80), u(84), u(88), u(92)
	r.CompletedExtents, r.CompletedFiles, r.CompletedZeroTails, r.CurrentIndex, r.Phase = u(96), u(100), u(104), u(108), u(112)
	if r.ReadBytes > 64910785 || r.VerifiedBytes > r.ReadBytes || r.LastRequest > 4096 || r.ReadCalls > 15888 || r.OwnerChecks > 31780 || r.AdmissionCalls > 2 || r.CompletedExtents > 89 || r.CompletedFiles > 54 || r.CompletedZeroTails > 35 || (r.CurrentIndex != ^uint32(0) && r.CurrentIndex >= 89) || r.Phase > 4 || r.Fault&^uint32(255) != 0 {
		return r, fmt.Errorf("G155 payload counters")
	}
	var read, verified uint64
	var files, zeros uint32
	for i, p := range mainPlan {
		n := 128 + 72*i
		v := MainExtentResult{Index: u(n), Kind: u(n + 4), Complete: u(n+8) == 1, status: q(n + 16), ReadBytes: q(n + 24), FailureAddress: q(n + 32), Digest: hex.EncodeToString(d[n+40 : n+72])}
		v.Status = fmt.Sprintf("0x%016x", v.status)
		if v.Index != uint32(i) || v.Kind != p.kind || u(n+8) > 1 || u(n+12) != 0 || v.ReadBytes > p.bytes || v.Complete != (uint32(i) < r.CompletedExtents) {
			return r, fmt.Errorf("G155 extent identity/count %d", i)
		}
		if v.Complete {
			if v.status != 0 || v.ReadBytes != p.bytes || v.FailureAddress != 0 || v.Digest != p.digest {
				return r, fmt.Errorf("G155 completed extent contradiction %d", i)
			}
			verified += p.bytes
			if p.kind == 1 {
				files++
			} else {
				zeros++
			}
		} else if v.status == 0 {
			return r, fmt.Errorf("G155 incomplete extent reports success %d", i)
		}
		if p.kind == 2 && v.Digest != p.digest {
			return r, fmt.Errorf("G155 zero-tail digest bytes %d", i)
		}
		read += v.ReadBytes
		r.Extents = append(r.Extents, v)
	}
	if read != r.ReadBytes || verified != r.VerifiedBytes || files != r.CompletedFiles || zeros != r.CompletedZeroTails {
		return r, fmt.Errorf("G155 payload aggregate contradiction")
	}
	if !r.Attempted && (r.Complete || r.Fault != 0 || r.Phase != 0 || r.ReadCalls != 0 || r.OwnerChecks != 0 || r.AdmissionCalls != 0 || r.ReadBytes != 0) {
		return r, fmt.Errorf("G155 unattempted payload activity")
	}
	if r.Complete {
		if !r.Attempted || r.status != 0 || r.Fault != 0 || r.Phase != 4 || r.CompletedExtents != 89 || r.VerifiedBytes != 64910785 || r.ReadCalls != 15888 || r.OwnerChecks != 31780 || r.AdmissionCalls != 2 || r.CurrentIndex != ^uint32(0) {
			return r, fmt.Errorf("G155 payload completion contradiction")
		}
	} else if r.status == 0 {
		return r, fmt.Errorf("G155 incomplete payload reports success")
	}
	return r, nil
}
