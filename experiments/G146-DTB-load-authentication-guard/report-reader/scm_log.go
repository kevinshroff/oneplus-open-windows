package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

type ScmLogRecord struct {
	Command           uint32 `json:"command"`
	Raw32             uint32 `json:"TzStatus32"`
	Signed32          int32  `json:"TzStatus_signed32"`
	Sequence          uint32 `json:"PAS_record_index"`
	TextBytes         uint32 `json:"text_bytes"`
	APIStatus         string `json:"original_API_status"`
	APIResult0        string `json:"original_API_result0"`
	MappingConsistent bool   `json:"OEM_mapping_consistent"`
	status, result0   uint64
}
type ScmLog struct {
	TableSHA256                                             string         `json:"table_sha256"`
	ReportValid                                             bool           `json:"report_valid"`
	ImageBase                                               string         `json:"SCM_image_base"`
	CacheSlot                                               string         `json:"cache_slot"`
	SavedCache                                              string         `json:"saved_cache"`
	Proxy                                                   string         `json:"diagnostic_proxy"`
	HookStatus                                              string         `json:"hook_status"`
	RestoreStatus                                           string         `json:"restore_status"`
	OriginalMethod                                          string         `json:"original_method"`
	StackLow                                                string         `json:"last_stack_low"`
	StackHigh                                               string         `json:"last_stack_high"`
	HookStores                                              uint32         `json:"hook_stores"`
	FatalRestore                                            bool           `json:"fatal_restore"`
	SinkCalls                                               uint32         `json:"sink_calls"`
	Ignored                                                 uint32         `json:"ignored"`
	Matched                                                 uint32         `json:"matched"`
	Rejected                                                uint32         `json:"rejected"`
	Count                                                   uint32         `json:"record_count"`
	DiagnosticStop                                          bool           `json:"diagnostic_stop"`
	ParserFault                                             uint32         `json:"parser_fault"`
	OtherCalls                                              uint32         `json:"other_serial_calls"`
	OriginalCalls                                           uint32         `json:"original_API_calls"`
	Raw32Qualified                                          bool           `json:"secure_error32_cross_bound"`
	FullX0Qualified                                         bool           `json:"full64_SMC_X0_qualified"`
	StableDoubleRead                                        bool           `json:"stable_double_read"`
	Records                                                 []ScmLogRecord `json:"records"`
	RawTableBase64                                          string         `json:"raw_table_base64"`
	Limits                                                  string         `json:"limits"`
	image, cache, original, proxy, low, high, hook, restore uint64
}

func decodeScmLog(b []byte) (ScmLog, error) {
	var r ScmLog
	if len(b) != 308 || string(b[:4]) != "OSER" || binary.LittleEndian.Uint32(b[4:]) != uint32(len(b)) {
		return r, fmt.Errorf("G146 serial table size/signature")
	}
	if b[8] != 1 || string(b[10:16]) != "OPEN  " || string(b[16:24]) != "G146SIP1" || binary.LittleEndian.Uint32(b[24:]) != 146 || string(b[28:32]) != "OPEN" || binary.LittleEndian.Uint32(b[32:]) != 1 {
		return r, fmt.Errorf("G146 serial table identity")
	}
	var sum byte
	for _, v := range b {
		sum += v
	}
	if sum != 0 {
		return r, fmt.Errorf("G146 serial checksum")
	}
	d := b[36:]
	u := func(at int) uint32 { return binary.LittleEndian.Uint32(d[at:]) }
	q := func(at int) uint64 { return binary.LittleEndian.Uint64(d[at:]) }
	h := func(at int) string { return fmt.Sprintf("0x%016x", q(at)) }
	if u(0) != 272 || u(4) != 1 || string(d[8:16]) != "G136LOG1" {
		return r, fmt.Errorf("G146 serial body ABI")
	}
	r.image, r.cache, r.original, r.proxy, r.low, r.high, r.hook, r.restore = q(16), q(24), q(64), q(40), q(72), q(80), q(48), q(56)
	r.ImageBase, r.CacheSlot, r.SavedCache, r.Proxy = h(16), h(24), h(32), h(40)
	r.HookStatus, r.RestoreStatus, r.OriginalMethod, r.StackLow, r.StackHigh = h(48), h(56), h(64), h(72), h(80)
	r.HookStores, r.FatalRestore, r.SinkCalls, r.Ignored = u(88), u(92) != 0, u(96), u(100)
	r.Matched, r.Rejected, r.Count, r.DiagnosticStop = u(104), u(108), u(120), u(124) != 0
	r.ParserFault, r.OtherCalls, r.OriginalCalls = u(128), u(132), u(136)
	if r.Count > 4 || r.Matched != r.Count || r.Matched > r.SinkCalls || r.HookStores > 2 || u(92) > 1 || u(124) > 1 || u(112) != 0 || u(116) != 0 || u(140) != 0 || r.ParserFault&^uint32(127) != 0 || r.OriginalCalls > 16 {
		return r, fmt.Errorf("G146 serial counters/flags")
	}
	if r.FatalRestore && r.restore == 0 {
		return r, fmt.Errorf("G146 serial fatal/restore contradiction")
	}
	if r.image != 0 {
		if r.image > ^uint64(0)-0xe580 || r.cache != r.image+0xe580 || r.original != r.image+0x3f94 || r.proxy == 0 {
			return r, fmt.Errorf("G146 serial binding addresses")
		}
	} else if r.cache != 0 || r.original != 0 || r.proxy != 0 || r.HookStores != 0 || r.OriginalCalls != 0 {
		return r, fmt.Errorf("G146 serial unbound activity")
	}
	if r.Count != 0 && (r.low < 0x80000000 || r.high < r.low || r.high-r.low != 0x4100) {
		return r, fmt.Errorf("G146 serial live-stack bounds")
	}
	seen := map[uint32]bool{}
	for i := uint32(0); i < r.Count; i++ {
		at := 144 + int(i)*32
		v := ScmLogRecord{Command: u(at), Raw32: u(at + 4), Signed32: int32(u(at + 4)), Sequence: u(at + 8), TextBytes: u(at + 12), APIStatus: h(at + 16), APIResult0: h(at + 24), status: q(at + 16), result0: q(at + 24)}
		if (v.Command != 0x42000201 && v.Command != 0x42000202 && v.Command != 0x42000205) || v.Sequence >= 16 || v.TextBytes < 58 || v.TextBytes > 512 || seen[v.Sequence] {
			return r, fmt.Errorf("G146 serial record identity/bounds")
		}
		seen[v.Sequence] = true
		expected := uint64(0)
		if v.Raw32 != 0 {
			expected = 0x8000000000000007
			if v.Raw32 == 0xffffffff {
				expected = 0x8000000000000003
			} else if v.Raw32 == 0xfffffffe && uint32(v.result0) == 0xfffffff3 {
				expected = 0x8000000000000014
			}
		}
		// With these valid argument counts the original SMC loop continues on
		// positive low32 returns; only a negative error reaches this print path.
		v.MappingConsistent = v.Raw32&0x80000000 != 0 && v.status == expected
		r.Records = append(r.Records, v)
	}
	for _, v := range d[144+int(r.Count)*32:] {
		if v != 0 {
			return r, fmt.Errorf("G146 serial unused record bytes")
		}
	}
	hash := sha256.Sum256(b)
	r.TableSHA256 = hex.EncodeToString(hash[:])
	r.ReportValid = true
	r.RawTableBase64 = base64.StdEncoding.EncodeToString(b)
	r.Limits = "Routed debug text captures the OEM32-bit error decision; full64-bit secureX0 is not retained. Original API result0 is paired separately. No DSP/GLINK/charging or production serial interface qualification."
	return r, nil
}
func bindScmLog(d Report, s ScmLog) (Report, error) {
	if s.image != 0 && (d.ScmSlot != fmt.Sprintf("0x%016x", s.image+0xe178) || d.OriginalMethod != s.OriginalMethod) {
		return d, fmt.Errorf("G146 DSP/serial source binding differs")
	}
	if s.OriginalCalls < d.EnteredStages {
		return d, fmt.Errorf("G146 original-call count below entered ledger")
	}
	if d.Flags&128 != 0 && (s.restore != 0 || s.FatalRestore) {
		return d, fmt.Errorf("G146 restored flag contradicts serial state")
	}
	if s.DiagnosticStop != d.DiagnosticStop {
		return d, fmt.Errorf("G146 diagnostic stop differs across reports")
	}
	qualified := s.Count > 0
	for _, v := range s.Records {
		if int(v.Sequence) >= len(d.Records) {
			return d, fmt.Errorf("G146 serial record index outside PAS ledger")
		}
		p := d.Records[v.Sequence]
		if p.Command != v.Command || p.Image != 36 || p.Entered != 1 || p.Returned != 1 || p.OriginalStatus != v.status || p.Results[0] != v.result0 {
			return d, fmt.Errorf("G146 serial record differs from original API ledger")
		}
		qualified = qualified && v.MappingConsistent
	}
	s.Raw32Qualified = qualified
	s.FullX0Qualified = false
	d.SCMError = &s
	return d, nil
}
