package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const bodyBytes = 1608
const tableBytes = 36 + bodyBytes
const inputSHA = "ba26f22b2ee03897148adaa7f34e1df350ef7f26bd24af6dbcd5878e8020e882"

var configSHA = [2]string{
	"b0dbed167e1ad77a411c409beb7cdec9204822356a8245982884f63d6f924ea1",
	"65913a28ec7082cacdaa1dca42719cdf1b748eac153d85c88cf3642961cfa992",
}
var metadataSHA = [2]string{
	"5476d25e617ebf2c51128fe1405d01f8731547ce14778a62893625dda7d0e0b1",
	"353c6cbb2f0f8782d3ce91818d25e195e8402d11942b8ba18ddf70f5fae2ffb8",
}
var statusNames = [16]string{
	"metadata_result", "preflight_ready", "PIL_locate", "SCM_locate",
	"PIL_code_bind", "SCM_code_bind", "DTB_config_getter", "ADSP_config_getter",
	"SCM_slot_attribute_query", "DTB_metadata", "ADSP_metadata", "DTB_CPU_header",
	"ADSP_CPU_header", "DTB_buffer_cleanup", "ADSP_buffer_cleanup", "memory_attribute_protocol",
}

type ImageReport struct {
	Name                 string `json:"name"`
	ConfigSHA256         string `json:"config_sha256"`
	ConfigMatches        bool   `json:"config_matches"`
	CachedSHA256         string `json:"cached_metadata_sha256"`
	UncachedSHA256       string `json:"uncached_metadata_sha256"`
	MetadataBytesMatch   bool   `json:"metadata_bytes_match"`
	CPUHeaderAccepted    bool   `json:"CPU_header_accepted"`
	CachedAddress        string `json:"cached_address"`
	UncachedAddress      string `json:"uncached_address"`
	UncachedReleaseBytes uint64 `json:"uncached_reuse_bytes"`
	CleanupAccepted      bool   `json:"cleanup_accepted"`
}
type Report struct {
	TableSHA256         string            `json:"table_sha256"`
	InputSHA256         string            `json:"input_sha256"`
	ReportValid         bool              `json:"report_valid"`
	MetadataVerified    bool              `json:"metadata_verified"`
	PILCodeVerified     bool              `json:"PIL_code_verified"`
	SCMCodeVerified     bool              `json:"SCM_code_verified"`
	PreflightReady      bool              `json:"preflight_ready"`
	Status              map[string]string `json:"raw_status"`
	PILImageBase        string            `json:"PIL_image_base"`
	SCMImageBase        string            `json:"SCM_image_base"`
	SCMABI              string            `json:"SCM_ABI"`
	SCMTableRVA         string            `json:"SCM_table_RVA"`
	SCMFunctionRVA      string            `json:"SCM_function_RVA"`
	SlotAttributes      string            `json:"SCM_slot_attributes"`
	SlotAttributesKnown bool              `json:"SCM_slot_attributes_known"`
	Flags               uint32            `json:"flags"`
	ImagesAttempted     uint32            `json:"images_attempted"`
	RequestedPasStages  uint32            `json:"diagnostic_requested_PAS_stages"`
	Images              [2]ImageReport    `json:"images"`
	Limits              string            `json:"limits"`
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func hx(v uint64) string     { return fmt.Sprintf("0x%016x", v) }

func decodeReport(b []byte) (Report, error) {
	var r Report
	if len(b) != tableBytes || string(b[:4]) != "OPAS" || binary.LittleEndian.Uint32(b[4:8]) != tableBytes {
		return r, fmt.Errorf("OPAS length/signature")
	}
	if b[8] != 1 || string(b[10:16]) != "OPEN  " || string(b[16:24]) != "G128META" || binary.LittleEndian.Uint32(b[24:28]) != 128 || string(b[28:32]) != "OPEN" || binary.LittleEndian.Uint32(b[32:36]) != 1 {
		return r, fmt.Errorf("OPAS identity/version")
	}
	var sum byte
	for _, v := range b {
		sum += v
	}
	if sum != 0 {
		return r, fmt.Errorf("OPAS checksum")
	}
	d := b[36:]
	u32 := func(o int) uint32 { return binary.LittleEndian.Uint32(d[o : o+4]) }
	u64 := func(o int) uint64 { return binary.LittleEndian.Uint64(d[o : o+8]) }
	if u32(0) != bodyBytes || u32(4) != 1 || u64(8) != 0x314154454d383231 {
		return r, fmt.Errorf("G128 body ABI")
	}
	r.InputSHA256 = hex.EncodeToString(d[248:280])
	if r.InputSHA256 != inputSHA {
		return r, fmt.Errorf("input identity")
	}
	r.Flags, r.ImagesAttempted, r.RequestedPasStages = u32(184), u32(192), u32(196)
	if r.Flags & ^uint32(0xfff) != 0 || r.ImagesAttempted > 2 || r.RequestedPasStages != 0 {
		return r, fmt.Errorf("flags/counter guard")
	}
	flag := func(n uint) bool { return r.Flags&(1<<n) != 0 }
	r.Status = make(map[string]string)
	var status [16]uint64
	for i, n := range statusNames {
		status[i] = u64(16 + 8*i)
		r.Status[n] = hx(status[i])
	}
	r.PILCodeVerified, r.SCMCodeVerified, r.PreflightReady = flag(0), flag(1), flag(4)
	if r.PILCodeVerified && (status[2] != 0 || status[4] != 0 || u64(144) == 0) || r.SCMCodeVerified && (status[3] != 0 || status[5] != 0 || u64(152) == 0) || r.PreflightReady != (status[1] == 0) {
		return r, fmt.Errorf("bound/preflight flag contradiction")
	}
	r.PILImageBase, r.SCMImageBase = hx(u64(144)), hx(u64(152))
	r.SCMTableRVA, r.SCMFunctionRVA, r.SlotAttributes = hx(u64(160)), hx(u64(168)), hx(u64(176))
	r.SlotAttributesKnown = flag(11)
	if r.SlotAttributesKnown && (!r.SCMCodeVerified || status[8] != 0 || status[15] != 0) {
		return r, fmt.Errorf("attribute flag contradiction")
	}
	switch u32(188) {
	case 0:
		r.SCMABI = "unidentified"
	case 1:
		r.SCMABI = "legacy"
		if u64(160) != 0xe0e8 || u64(168) != 0x185c {
			return r, fmt.Errorf("legacy binding")
		}
	case 2:
		r.SCMABI = "ARMv8"
		if u64(160) != 0xe140 || u64(168) != 0x3f94 {
			return r, fmt.Errorf("ARMv8 binding")
		}
	default:
		return r, fmt.Errorf("SCM ABI")
	}
	if r.SCMCodeVerified && u32(188) == 0 {
		return r, fmt.Errorf("bound SCM without ABI")
	}
	all := r.PILCodeVerified && r.PreflightReady && r.ImagesAttempted == 2
	for i, name := range []string{"FULL_ADSP_DTB", "FULL_ADSP"} {
		im := &r.Images[i]
		im.Name = name
		im.ConfigSHA256 = digest(d[344+i*568 : 344+(i+1)*568])
		im.ConfigMatches = status[6+i] == 0 && im.ConfigSHA256 == configSHA[i] && hex.EncodeToString(d[280+i*32:312+i*32]) == configSHA[i]
		if flag(uint(2+i)) != im.ConfigMatches {
			return r, fmt.Errorf("%s config flag/hash", name)
		}
		im.CachedSHA256 = hex.EncodeToString(d[1480+i*32 : 1512+i*32])
		im.UncachedSHA256 = hex.EncodeToString(d[1544+i*32 : 1576+i*32])
		im.CachedAddress, im.UncachedAddress = hx(u64(200+i*8)), hx(u64(216+i*8))
		im.MetadataBytesMatch = flag(uint(5 + i))
		im.CPUHeaderAccepted = flag(uint(7 + i))
		im.CleanupAccepted = flag(uint(9 + i))
		im.UncachedReleaseBytes = u64(232 + i*8)
		if im.MetadataBytesMatch && (status[9+i] != 0 || im.CachedSHA256 != metadataSHA[i] || im.UncachedSHA256 != metadataSHA[i] || u64(200+i*8) == 0 || u64(216+i*8) == 0 || !im.ConfigMatches || !r.PILCodeVerified || !r.PreflightReady) {
			return r, fmt.Errorf("%s metadata flag/hash", name)
		}
		if im.CPUHeaderAccepted && (!im.MetadataBytesMatch || status[11+i] != 0) || im.CleanupAccepted && status[13+i] != 0 {
			return r, fmt.Errorf("%s header/cleanup flag", name)
		}
		all = all && im.ConfigMatches && im.MetadataBytesMatch && im.CPUHeaderAccepted && im.CleanupAccepted && im.UncachedReleaseBytes >= uint64([]int{4096, 12288}[i])
	}
	if (status[0] == 0) != all {
		return r, fmt.Errorf("overall result contradiction")
	}
	r.MetadataVerified, r.ReportValid, r.TableSHA256 = all, true, digest(b)
	r.Limits = "Metadata parsing and buffer reuse only. No PAS request, DSP state/ownership/authentication, GLINK readiness or charging result is established. Heap/cache/MMU services were exercised; this is not a hardware-read-only probe."
	return r, nil
}
