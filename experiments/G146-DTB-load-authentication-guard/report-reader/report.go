package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const bodyBytes = 2152
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
	Dtb                 DtbAdmission      `json:"DTB_admission"`
	StopBeforeMain      bool              `json:"stop_before_main"`
	LoadReturned        bool              `json:"DTB_load_returned"`
	DtbPublicSuccess    bool              `json:"DTB_public_success"`
	SCMError            *ScmLog           `json:"SCM_error,omitempty"`
	Records             []Record          `json:"records"`
	RawTableBase64      string            `json:"raw_table_base64"`
	Limits              string            `json:"limits"`
}

func decodeReport(b []byte) (Report, error) {
	var r Report
	if len(b) != bodyBytes+36 || string(b[:4]) != "OADP" || int(binary.LittleEndian.Uint32(b[4:8])) != len(b) {
		return r, fmt.Errorf("G146 ACPI signature/length")
	}
	if b[8] != 1 || string(b[10:16]) != "OPEN  " || string(b[16:24]) != "G146DSP1" || binary.LittleEndian.Uint32(b[24:28]) != 146 || string(b[28:32]) != "OPEN" || binary.LittleEndian.Uint32(b[32:36]) != 1 {
		return r, fmt.Errorf("G146 ACPI identity")
	}
	var sum byte
	for _, c := range b {
		sum += c
	}
	if sum != 0 {
		return r, fmt.Errorf("G146 ACPI checksum")
	}
	d := b[36:]
	u32 := func(n int) uint32 { return binary.LittleEndian.Uint32(d[n : n+4]) }
	u64 := func(n int) uint64 { return binary.LittleEndian.Uint64(d[n : n+8]) }
	hex64 := func(n int) string { return fmt.Sprintf("0x%016x", u64(n)) }
	if u32(0) != bodyBytes || u32(4) != 1 || string(d[8:16]) != "G146DSP1" {
		return r, fmt.Errorf("G146 body version/size")
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
	if r.Flags & ^uint32(255) != 0 || r.PilRequests > 1 || r.RecordCount > 16 || r.Phase[0] > 3 || r.Phase[1] != 0 || r.AuthEntered > 1 || r.AuthAccepted > 1 || r.HookStores > 2 || u32(204) > 1 || r.GopCount > 8 || r.CpuPages > 18689 || r.CpuQueries > 37378 || r.Fault & ^uint32(4095) != 0 || r.CpuRefusal & ^uint32(127) != 0 {
		return r, fmt.Errorf("G146 counters/flags")
	}
	if r.Flags&32 != 0 && (u64(40) != 0 || (r.CpuEL != 1 && r.CpuEL != 2) || r.CpuPages != 18689 || r.CpuQueries != 37378 || r.CpuRefusal != 0 || u64(144)>>56 != 0x44 || u64(152)>>56 != 0x44 || u64(144)&0x000ffffffffff000 != 0xa327f000 || u64(152)&0x000ffffffffff000 != 0xa327f000) {
		return r, fmt.Errorf("G146 CPU completion contradiction")
	}
	if r.Flags&128 != 0 && (u64(72) != 0 || r.FatalRestore) {
		return r, fmt.Errorf("G146 restoration contradiction")
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
			return r, fmt.Errorf("G146 record entry/return flags")
		}
		r.EnteredStages += v.Entered
		r.ReturnedStages += v.Returned
		r.Records = append(r.Records, v)
		if v.Entered == 1 {
			if v.Image != 36 || v.Arguments[0] != 36 {
				return r, fmt.Errorf("G146 forwarded non-DTB stage")
			}
			switch v.Command {
			case 0x42000201:
				if v.Param != 0x82 || v.Arguments[1] == 0 {
					return r, fmt.Errorf("G146 INIT arguments")
				}
			case 0x42000202:
				if v.Param != 3 || v.Arguments[1] != 0x9e980000 || v.Arguments[2] != 0x80000 {
					return r, fmt.Errorf("G146 MEM_SETUP arguments")
				}
				r.MemorySetupAccepted = v.Returned == 1 && v.OriginalStatus == 0 && v.Results[0] == 1 && v.Results[1] == 0
			case 0x42000205:
				if v.Param != 1 || v.Arguments[1] != 0 || v.Arguments[2] != 0 {
					return r, fmt.Errorf("G146 AUTH arguments")
				}
			default:
				return r, fmt.Errorf("G146 diagnostic forwarded shutdown/unknown stage")
			}
		}
	}
	for _, v := range d[208+int(r.RecordCount)*recordBytes : 1744] {
		if v != 0 {
			return r, fmt.Errorf("G146 unused ledger bytes")
		}
	}
	r.StopBeforeMain, r.LoadReturned, r.DtbPublicSuccess = u32(2136) == 1, u32(2140) == 1, u32(2144) == 1
	if u32(2136) != 1 || u32(2140) > 1 || u32(2144) > 1 || u32(2148) != 0 {
		return r, fmt.Errorf("G146 outer diagnostic flags")
	}
	var e error
	r.Dtb, e = decodeDtbAdmission(d[1744:2136])
	if e != nil {
		return r, e
	}
	if e = bindDtbAdmission(&r, u64(56)); e != nil {
		return r, e
	}
	h := sha256.Sum256(b)
	r.TableSHA256 = hex.EncodeToString(h[:])
	r.ReportValid = true
	r.RawTableBase64 = base64.StdEncoding.EncodeToString(b)
	r.Limits = "One-use DTB-only authentication diagnostic. Main is blocked. Finite source/reservation/CPU/display/hash checks and accepted DTB AUTH do not qualify full64-bit secureX0, main DSP execution, GLINK, charging, global DMA ownership or a production power lease. PRE/POST return values are not directly observed."
	return r, nil
}
