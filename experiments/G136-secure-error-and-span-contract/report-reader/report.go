package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const bodyBytes = 1744
const recordBytes = 96

type Record struct {
	Command, Param, Image, Entered uint32
	Arguments                      [3]uint64
	OriginalStatus                 uint64
	Results                        [4]uint64
	ReturnedStatus                 uint64
	Returned, Refusal              uint32
}
type Report struct {
	TableSHA256         string            `json:"table_sha256"`
	ReportValid         bool              `json:"report_valid"`
	FinalStatus         string            `json:"final_status"`
	RawStatus           map[string]string `json:"raw_status"`
	Flags               uint32            `json:"flags"`
	PilRequests         uint32            `json:"PIL_requests"`
	RecordCount         uint32            `json:"record_count"`
	Fault               uint32            `json:"fault"`
	Phase               [2]uint32         `json:"phase"`
	AuthEntered         uint32            `json:"auth_entered_mask"`
	AuthAccepted        uint32            `json:"auth_accepted_mask"`
	ScmSlot             string            `json:"SCM_slot"`
	OriginalMethod      string            `json:"original_method"`
	WrapperMethod       string            `json:"wrapper_method"`
	CpuEL               uint64            `json:"CPU_EL"`
	CpuPages            uint64            `json:"CPU_pages"`
	CpuQueries          uint64            `json:"CPU_queries"`
	CpuFirstBad         string            `json:"CPU_first_bad"`
	CpuReadPar          string            `json:"CPU_read_PAR"`
	CpuWritePar         string            `json:"CPU_write_PAR"`
	CpuRefusal          uint32            `json:"CPU_refusal"`
	GopCount            uint32            `json:"GOP_count"`
	HookStores          uint32            `json:"hook_stores"`
	FatalRestore        bool              `json:"fatal_restore"`
	EnteredStages       uint32            `json:"PAS_entered_stages"`
	ReturnedStages      uint32            `json:"PAS_returned_stages"`
	SequenceAccepted    bool              `json:"PAS_sequence_accepted"`
	DSPRunning          bool              `json:"DSP_running_qualified"`
	GlinkReady          bool              `json:"GLINK_ready_qualified"`
	ChargingQualified   bool              `json:"charging_qualified"`
	StableDoubleRead    bool              `json:"stable_double_read"`
	DiagnosticStop      bool              `json:"diagnostic_stop"`
	MemorySetupAccepted bool              `json:"memory_setup_accepted"`
	SCMError            *ScmLog           `json:"SCM_error,omitempty"`
	Records             []Record          `json:"records"`
	RawTableBase64      string            `json:"raw_table_base64"`
	Limits              string            `json:"limits"`
}

func decodeReport(b []byte) (Report, error) {
	var r Report
	if len(b) != bodyBytes+36 || string(b[:4]) != "OADP" || int(binary.LittleEndian.Uint32(b[4:8])) != len(b) {
		return r, fmt.Errorf("G136 ACPI signature/length")
	}
	if b[8] != 1 || string(b[10:16]) != "OPEN  " || string(b[16:24]) != "G136DSP1" || binary.LittleEndian.Uint32(b[24:28]) != 136 || string(b[28:32]) != "OPEN" || binary.LittleEndian.Uint32(b[32:36]) != 1 {
		return r, fmt.Errorf("G136 ACPI identity")
	}
	var sum byte
	for _, c := range b {
		sum += c
	}
	if sum != 0 {
		return r, fmt.Errorf("G136 ACPI checksum")
	}
	d := b[36:]
	u32 := func(n int) uint32 { return binary.LittleEndian.Uint32(d[n : n+4]) }
	u64 := func(n int) uint64 { return binary.LittleEndian.Uint64(d[n : n+8]) }
	hex64 := func(n int) string { return fmt.Sprintf("0x%016x", u64(n)) }
	if u32(0) != bodyBytes || u32(4) != 1 || string(d[8:16]) != "G136DSP1" {
		return r, fmt.Errorf("G136 body version/size")
	}
	r.RawStatus = make(map[string]string)
	for i, name := range []string{"source_admission", "protocol_binding", "GOP_exclusion", "CPU_admission", "hook", "DTB_PIL", "main_PIL", "restoration"} {
		r.RawStatus[name] = hex64(16 + i*8)
	}
	r.FinalStatus = hex64(80)
	r.ScmSlot, r.OriginalMethod, r.WrapperMethod, r.CpuEL = hex64(88), hex64(96), hex64(104), u64(112)
	r.CpuPages, r.CpuQueries, r.CpuFirstBad, r.CpuReadPar, r.CpuWritePar = u64(120), u64(128), hex64(136), hex64(144), hex64(152)
	r.Flags, r.PilRequests, r.RecordCount, r.Fault = u32(160), u32(164), u32(168), u32(172)
	r.Phase, r.AuthEntered, r.AuthAccepted = [2]uint32{u32(176), u32(180)}, u32(184), u32(188)
	r.CpuRefusal, r.GopCount, r.HookStores, r.FatalRestore = u32(192), u32(196), u32(200), u32(204) != 0
	if r.Flags & ^uint32(255) != 0 || r.PilRequests > 1 || r.RecordCount > 16 || r.Phase[0] > 2 || r.Phase[1] != 0 || r.AuthEntered != 0 || r.AuthAccepted != 0 || r.HookStores > 2 || u32(204) > 1 || r.GopCount > 8 || r.CpuPages > 18689 || r.CpuQueries > 37378 || r.Fault & ^uint32(1023) != 0 || r.CpuRefusal & ^uint32(63) != 0 {
		return r, fmt.Errorf("G136 counters/flags")
	}
	if r.Flags&32 != 0 && (u64(40) != 0 || (r.CpuEL != 1 && r.CpuEL != 2) || r.CpuPages != 18689 || r.CpuQueries != 37378 || r.CpuRefusal != 0) {
		return r, fmt.Errorf("G136 CPU completion contradiction")
	}
	if r.Flags&128 != 0 && (u64(72) != 0 || r.FatalRestore) {
		return r, fmt.Errorf("G136 restoration contradiction")
	}
	for i := uint32(0); i < r.RecordCount; i++ {
		n := 208 + int(i)*recordBytes
		v := Record{Command: u32(n), Param: u32(n + 4), Image: u32(n + 8), Entered: u32(n + 12), OriginalStatus: u64(n + 40), ReturnedStatus: u64(n + 80), Returned: u32(n + 88), Refusal: u32(n + 92)}
		for j := range v.Arguments {
			v.Arguments[j] = u64(n + 16 + 8*j)
		}
		for j := range v.Results {
			v.Results[j] = u64(n + 48 + 8*j)
		}
		if v.Entered > 1 || v.Returned > v.Entered {
			return r, fmt.Errorf("G136 record entry/return flags")
		}
		r.EnteredStages += v.Entered
		r.ReturnedStages += v.Returned
		r.Records = append(r.Records, v)
		if v.Entered == 1 {
			if v.Image != 36 || v.Arguments[0] != 36 {
				return r, fmt.Errorf("G136 forwarded non-DTB stage")
			}
			switch v.Command {
			case 0x42000201:
				if v.Param != 0x82 || v.Arguments[1] == 0 {
					return r, fmt.Errorf("G136 INIT arguments")
				}
			case 0x42000202:
				if v.Param != 3 || v.Arguments[1] != 0xa9f80000 || v.Arguments[2] != 0x80000 {
					return r, fmt.Errorf("G136 MEM_SETUP arguments")
				}
				r.MemorySetupAccepted = v.Returned == 1 && v.OriginalStatus == 0 && v.Results[0] == 1 && v.Results[1] == 0
			default:
				return r, fmt.Errorf("G136 diagnostic forwarded AUTH/shutdown/unknown stage")
			}
		}
	}
	for _, v := range d[208+int(r.RecordCount)*recordBytes:] {
		if v != 0 {
			return r, fmt.Errorf("G136 unused ledger bytes")
		}
	}
	r.SequenceAccepted = false
	r.DiagnosticStop = r.Fault&256 != 0
	if r.MemorySetupAccepted && (!r.DiagnosticStop || r.Phase[0] != 2) {
		return r, fmt.Errorf("G136 successful memory setup without diagnostic stop")
	}
	h := sha256.Sum256(b)
	r.TableSHA256 = hex.EncodeToString(h[:])
	r.ReportValid = true
	r.RawTableBase64 = base64.StdEncoding.EncodeToString(b)
	r.Limits = "One-use memory diagnostic. Original API results and routed32-bit error text do not establish full64-bit secureX0, DSP execution, GLINK readiness, charging or global memory ownership."
	return r, nil
}
