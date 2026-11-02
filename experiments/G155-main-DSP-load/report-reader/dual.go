package main

import "fmt"

func accepted(v Record) bool {
	return v.Entered == 1 && v.Returned == 1 && v.OriginalStatus == 0 && v.Results[0] == 1 && v.Results[1] == 0 && v.ReturnedStatus == 0 && v.Refusal == 0
}
func bindDualImage(r *Report, dtbPublic, mainPublic, marker uint64) error {
	if r.PilRequests > 0 {
		if r.Flags&127 != 127 {
			return fmt.Errorf("G155 original request without all source/protocol/GOP/CPU/hook admission")
		}
		for _, name := range []string{"source_admission", "protocol_binding", "GOP_exclusion", "CPU_admission", "hook"} {
			if r.RawStatus[name] != "0x0000000000000000" {
				return fmt.Errorf("G155 request contradicts prior admission status")
			}
		}
	}
	next := 0
	entered, auth := uint32(0), uint32(0)
	expected := [3]uint32{0x42000201, 0x42000202, 0x42000205}
	for _, v := range r.Records {
		if v.Entered != 1 {
			continue
		}
		image := uint32(36)
		if next >= 3 {
			image = 1
		}
		if next >= 6 || v.Returned != 1 || v.Command != expected[next%3] || v.Image != image {
			return fmt.Errorf("G155 forwarded image/stage order")
		}
		next++
		if v.Command == 0x42000205 {
			bit := uint32(1)
			if image == 1 {
				bit = 2
			}
			entered |= bit
			if accepted(v) {
				auth |= bit
			}
			if !r.Dtb.FiniteAdmissionComplete {
				return fmt.Errorf("G155 AUTH without DTB payload admission")
			}
			if image == 1 && (!r.DtbPublicComplete || !r.Main.FiniteComplete || !r.Payload.Complete) {
				return fmt.Errorf("G155 main AUTH without complete admission/payload")
			}
		}
	}
	if r.AuthEntered != entered || r.AuthAccepted != auth {
		return fmt.Errorf("G155 AUTH masks contradict ledger")
	}
	if (auth&1 != 0) != (r.Phase[0] == 3) || (auth&2 != 0) != (r.Phase[1] == 3) || r.Phase[0] >= 2 && !r.MemorySetupAccepted || r.Phase[1] >= 2 && !r.MainMemorySetupAccepted {
		return fmt.Errorf("G155 phase/accepted stage contradiction")
	}
	if r.Dtb.CopyAttempts > 0 && !r.MemorySetupAccepted {
		return fmt.Errorf("G155 DTB copy before accepted MEM_SETUP")
	}
	if r.Dtb.PayloadAttempts > 0 && (!r.Dtb.CopyGranted || len(r.Records) < 3 || r.Records[2].Command != 0x42000205) {
		return fmt.Errorf("G155 DTB payload outside AUTH")
	}
	if len(r.Records) >= 3 {
		r.DtbSequenceAccepted = accepted(r.Records[0]) && accepted(r.Records[1]) && accepted(r.Records[2]) && r.Dtb.FiniteAdmissionComplete && auth&1 != 0
	}
	expectedDtb := r.DtbLoadReturned && dtbPublic == 0 && r.DtbSequenceAccepted
	if r.DtbPublicSuccess != expectedDtb {
		return fmt.Errorf("G155 DTB public result contradiction")
	}
	if r.DtbPublicComplete != (marker == 0) || r.DtbPublicComplete && !r.DtbPublicSuccess {
		return fmt.Errorf("G155 DTB public marker contradiction")
	}
	if r.MainLoadReturned && (!r.DtbPublicComplete || !r.DtbPublicSuccess) || r.PilRequests != bool32(r.DtbLoadReturned)+bool32(r.MainLoadReturned) {
		return fmt.Errorf("G155 main request before DTB public completion")
	}
	if r.Main.CopyAttempts > 0 && (!r.MainLoadReturned || !r.MainMemorySetupAccepted || !r.DtbPublicComplete) {
		return fmt.Errorf("G155 main copy before accepted setup")
	}
	if r.Payload.Attempted && (!r.Main.CopyGranted || len(r.Records) < 6 || r.Records[5].Command != 0x42000205 || r.Records[5].Image != 1) {
		return fmt.Errorf("G155 main verifier outside AUTH boundary")
	}
	if r.Main.RefreshAttempts > r.Payload.AdmissionCalls {
		return fmt.Errorf("G155 main admission outside verifier")
	}
	if r.Payload.Complete && (!r.Main.FiniteComplete || !r.DtbPublicComplete) {
		return fmt.Errorf("G155 payload without final admission")
	}
	r.SequenceAccepted = len(r.Records) == 6 && r.Fault == 0 && r.Phase == [2]uint32{3, 3} && auth == 3 && r.DtbSequenceAccepted && r.Main.FiniteComplete && r.Payload.Complete
	for _, v := range r.Records {
		r.SequenceAccepted = r.SequenceAccepted && accepted(v)
	}
	expectedMain := r.MainLoadReturned && mainPublic == 0 && r.SequenceAccepted
	if r.MainPublicSuccess != expectedMain {
		return fmt.Errorf("G155 main public result contradiction")
	}
	r.DiagnosticStop = r.MainPublicSuccess
	if r.FinalStatus == "0x0000000000000000" {
		return fmt.Errorf("G155 outer diagnostic cannot report EFI_SUCCESS")
	}
	if r.FinalStatus == "0x8000000000000015" && (!r.MainPublicSuccess || r.Flags&128 == 0) {
		return fmt.Errorf("G155 aborted without complete main/restoration")
	}
	return nil
}
func bool32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}
