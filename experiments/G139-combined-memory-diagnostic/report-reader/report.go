package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const maxTable = 32*1024 + 36
const pages = uint64(18688)

type Tag struct {
	Value  uint64 `json:"value"`
	Reads  uint64 `json:"reads"`
	Writes uint64 `json:"writes"`
}
type Framebuffer struct {
	Index   uint64 `json:"index"`
	Base    uint64 `json:"base"`
	Bytes   uint64 `json:"bytes"`
	Overlap bool   `json:"overlap"`
}
type Sample struct {
	Address  uint64 `json:"address"`
	ReadPar  uint64 `json:"read_PAR"`
	WritePar uint64 `json:"write_PAR"`
}
type Report struct {
	TableSHA256        string        `json:"table_sha256"`
	ReportValid        bool          `json:"report_valid"`
	QueriesComplete    bool          `json:"memory_queries_complete"`
	CpuAllocated       bool          `json:"CPU_allocated"`
	CpuComplete        bool          `json:"CPU_queries_complete"`
	El                 uint64        `json:"EL"`
	Refusal            uint64        `json:"CPU_refusal"`
	Pages              uint64        `json:"pages"`
	Queries            uint64        `json:"AT_queries"`
	ReadFaults         uint64        `json:"read_faults"`
	WriteFaults        uint64        `json:"write_faults"`
	ReadAliases        uint64        `json:"read_aliases"`
	WriteAliases       uint64        `json:"write_aliases"`
	TagDifferences     uint64        `json:"tag_differences"`
	FirstFault         Sample        `json:"first_fault"`
	FirstAlias         Sample        `json:"first_alias"`
	FirstTagDifference Sample        `json:"first_tag_difference"`
	Tags               []Tag         `json:"raw_PAR_attribute_tags"`
	Framebuffers       []Framebuffer `json:"framebuffers"`
	MemoryEligible     bool          `json:"memory_eligible"`
	DmaOwnership       bool          `json:"DMA_ownership_proved"`
	DspStarted         bool          `json:"DSP_started"`
	Text               string        `json:"text"`
}

func number(s string, base int) (uint64, error) { return strconv.ParseUint(s, base, 64) }
func decodeReport(b []byte) (Report, error) {
	var r Report
	if len(b) < 136 || len(b) > maxTable || string(b[:4]) != "OPIL" || int(binary.LittleEndian.Uint32(b[4:8])) != len(b) {
		return r, fmt.Errorf("OPIL length/signature")
	}
	if b[8] != 1 || string(b[10:16]) != "OPEN  " || string(b[16:24]) != "G139PIL1" || binary.LittleEndian.Uint32(b[24:28]) != 139 || string(b[28:32]) != "OPEN" || binary.LittleEndian.Uint32(b[32:36]) != 1 {
		return r, fmt.Errorf("OPIL identity")
	}
	var sum byte
	for _, c := range b {
		sum += c
	}
	if sum != 0 {
		return r, fmt.Errorf("OPIL checksum")
	}
	text := strings.ReplaceAll(string(b[36:]), "\r\n", "\n")
	for _, c := range []byte(text) {
		if !(c >= 32 && c <= 126) && c != '\n' {
			return r, fmt.Errorf("OPIL encoding")
		}
	}
	prefix := "OPEN-PIL-INVENTORY G139 version=1\npolicy_start=8A800000 policy_end=A3280000 source=G138-shipped-devcfg\n"
	trailer := "\nG139_FINAL truncated=0 PAS_requests=0 target_data_accesses=0 mappings_changed=0 ownership=not_proved\n"
	if !strings.HasPrefix(text, prefix) || !strings.HasSuffix(text, trailer) || strings.Count(text, "G139_FINAL ") != 1 || strings.Count(text, "OPEN-PIL-FOOTPRINT G139 version=1\n") != 1 || strings.Contains(text, "P139_ERROR") {
		return r, fmt.Errorf("OPIL report version/truncation")
	}
	one := func(pattern string) ([]string, error) {
		v := regexp.MustCompile(`(?m)^`+pattern+`$`).FindAllStringSubmatch(text, -1)
		if len(v) != 1 {
			return nil, fmt.Errorf("OPIL row identity: %s", pattern)
		}
		return v[0], nil
	}
	if _, e := one(`P139_proposed dtb=9E980000:80000 main=9EA00000:4880000 region_writes=0 PAS_requests=0`); e != nil {
		return r, e
	}
	done, e := one(`P139_DONE queries_complete=([01]) PAS_allowed=0 DMA_ownership=not_proved region_writes=0`)
	if e != nil {
		return r, e
	}
	r.QueriesComplete = done[1] == "1"
	cpu := regexp.MustCompile(`(?m)^P139_cpu el=([0-9]+) complete=([01]) refusal=([0-9]+) pages=([0-9]+) queries=([0-9]+)$`).FindAllStringSubmatch(text, -1)
	alloc := strings.Count(text, "P139_cpu allocation_failed=1 queries=0\n")
	if alloc == 1 && len(cpu) == 0 {
		r.CpuAllocated = false
		if strings.Contains(text, "P139_cpu_faults ") || strings.Contains(text, "P139_cpu_first_") {
			return r, fmt.Errorf("unallocated CPU result has sample rows")
		}
	} else {
		if alloc != 0 || len(cpu) != 1 {
			return r, fmt.Errorf("CPU row identity")
		}
		r.CpuAllocated = true
		vals := make([]uint64, 5)
		for i, s := range []string{cpu[0][1], cpu[0][2], cpu[0][3], cpu[0][4], cpu[0][5]} {
			v, e := number(s, 10)
			if e != nil {
				return r, e
			}
			vals[i] = v
		}
		r.El, r.Refusal, r.Pages, r.Queries = vals[0], vals[2], vals[3], vals[4]
		r.CpuComplete = vals[1] == 1
		if r.El > 3 || r.Refusal > 2 || r.Pages > pages || r.Queries != 2*r.Pages || r.CpuComplete != (r.Refusal == 0 && (r.El == 1 || r.El == 2) && r.Pages == pages) {
			return r, fmt.Errorf("CPU collection consistency")
		}
		if !r.CpuComplete && (r.Pages != 0 || r.Queries != 0 || r.Refusal != 1) {
			return r, fmt.Errorf("unsupported partial CPU collection")
		}
		counts, e := one(`P139_cpu_faults reads=([0-9]+) writes=([0-9]+) read_aliases=([0-9]+) write_aliases=([0-9]+) tag_differences=([0-9]+)`)
		if e != nil {
			return r, e
		}
		ptrs := []*uint64{&r.ReadFaults, &r.WriteFaults, &r.ReadAliases, &r.WriteAliases, &r.TagDifferences}
		for i, p := range ptrs {
			v, e := number(counts[i+1], 10)
			if e != nil || v > r.Pages {
				return r, fmt.Errorf("CPU counter bounds")
			}
			*p = v
		}
		if r.ReadAliases+r.ReadFaults > r.Pages || r.WriteAliases+r.WriteFaults > r.Pages || r.TagDifferences > r.Pages-r.ReadFaults || r.TagDifferences > r.Pages-r.WriteFaults {
			return r, fmt.Errorf("CPU counters contradict page classes")
		}
		samples := []*Sample{&r.FirstFault, &r.FirstAlias, &r.FirstTagDifference}
		countsPresent := []bool{r.ReadFaults+r.WriteFaults != 0, r.ReadAliases+r.WriteAliases != 0, r.TagDifferences != 0}
		for i, kind := range []string{"fault", "alias", "tag_difference"} {
			row, e := one(`P139_cpu_first_` + kind + ` address=([0-9A-Fa-f]{1,16}) read_par=([0-9A-Fa-f]{1,16}) write_par=([0-9A-Fa-f]{1,16})`)
			if e != nil {
				return r, e
			}
			a, e0 := number(row[1], 16)
			rd, e1 := number(row[2], 16)
			wr, e2 := number(row[3], 16)
			if e0 != nil || e1 != nil || e2 != nil {
				return r, fmt.Errorf("CPU sample value")
			}
			*samples[i] = Sample{a, rd, wr}
			if !countsPresent[i] {
				if a != 0 || rd != 0 || wr != 0 {
					return r, fmt.Errorf("CPU empty sample contradiction")
				}
				continue
			}
			if a < 0x9e980000 || a >= 0xa3280000 || a%4096 != 0 {
				return r, fmt.Errorf("CPU sample outside fixed pages")
			}
			valid := false
			if i == 0 {
				valid = rd&1 != 0 || wr&1 != 0
			}
			if i == 1 {
				valid = rd&1 == 0 && rd&0x000ffffffffff000 != a || wr&1 == 0 && wr&0x000ffffffffff000 != a
			}
			if i == 2 {
				valid = rd&1 == 0 && wr&1 == 0 && rd>>56 != wr>>56
			}
			if !valid {
				return r, fmt.Errorf("CPU sample does not match its class")
			}
		}
	}
	tagRows := regexp.MustCompile(`(?m)^P139_cpu_tag value=([0-9A-Fa-f]{2}) reads=([0-9]+) writes=([0-9]+)$`).FindAllStringSubmatch(text, -1)
	var rt, wt uint64
	for i, row := range tagRows {
		v, e := number(row[1], 16)
		if e != nil {
			return r, e
		}
		rd, e1 := number(row[2], 10)
		wr, e2 := number(row[3], 10)
		if e1 != nil || e2 != nil || rd > pages || wr > pages || rd+wr == 0 || i > 0 && v <= r.Tags[i-1].Value {
			return r, fmt.Errorf("CPU tag bounds/order")
		}
		rt += rd
		wt += wr
		r.Tags = append(r.Tags, Tag{v, rd, wr})
	}
	if strings.Count(text, "P139_cpu_tag ") != len(tagRows) || rt+r.ReadFaults != r.Pages || wt+r.WriteFaults != r.Pages {
		return r, fmt.Errorf("CPU histogram totals")
	}
	gops := regexp.MustCompile(`(?m)^P139_gop index=([0-9]+) base=([0-9A-Fa-f]{1,16}) bytes=([0-9A-Fa-f]{1,16}) overlap=([01])$`).FindAllStringSubmatch(text, -1)
	for i, row := range gops {
		idx, e0 := number(row[1], 10)
		base, e1 := number(row[2], 16)
		n, e2 := number(row[3], 16)
		if e0 != nil || e1 != nil || e2 != nil || idx > 7 || n == 0 || base > ^uint64(0)-n || i > 0 && idx <= r.Framebuffers[i-1].Index {
			return r, fmt.Errorf("GOP range/order")
		}
		overlap := base < 0xa3280000 && base+n > 0x9e980000
		if overlap != (row[4] == "1") {
			return r, fmt.Errorf("GOP overlap inconsistency")
		}
		r.Framebuffers = append(r.Framebuffers, Framebuffer{idx, base, n, overlap})
	}
	gr, e := one(`P139_gop_valid_rows=([0-9]+)`)
	if e != nil {
		return r, e
	}
	nr, e := number(gr[1], 10)
	if e != nil || nr > 8 || nr != uint64(len(gops)) {
		return r, fmt.Errorf("GOP row count")
	}
	gs, e := one(`P139_gop_status=(.*?) count=([0-9]+)`)
	if e != nil {
		return r, e
	}
	gn, e := number(gs[2], 10)
	if e != nil || gn > 4096 {
		return r, fmt.Errorf("GOP handle count")
	}
	if r.QueriesComplete && (gn == 0 || gn > 8 || nr != gn || (gs[1] != "Success" && gs[1] != "0") || strings.Contains(text, "valid_range=0\n")) {
		return r, fmt.Errorf("complete query has incomplete GOP")
	}
	digest := sha256.Sum256(b)
	r.TableSHA256 = hex.EncodeToString(digest[:])
	r.Text = text
	r.ReportValid = true
	// Observations remain observations even if all counters look favorable.
	r.MemoryEligible = false
	r.DmaOwnership = false
	r.DspStarted = false
	return r, nil
}
