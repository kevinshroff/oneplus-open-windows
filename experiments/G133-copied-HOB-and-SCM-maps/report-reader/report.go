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

const inputSHA = "ba26f22b2ee03897148adaa7f34e1df350ef7f26bd24af6dbcd5878e8020e882"

var finalLine = regexp.MustCompile(`(?m)^FINAL file_status=(.*?) memory_status=(.*?) cleanup_status=(.*?) truncated=([01])$`)
var fileLine = regexp.MustCompile(`(?m)^file ([0-9]+) ([a-z0-9_.]+) bytes=([0-9]+) read=([0-9]+) status=(.*?)$`)
var completedLine = regexp.MustCompile(`(?m)^files_completed=([0-9]+) total=64 status=(.*?)$`)
var countersLine = regexp.MustCompile(`(?m)^read_calls=([0-9]+) read_bytes=([0-9]+) requested_bytes=([0-9]+) denied_writes=([0-9]+) failures=([0-9]+) kept_facade=([01])$`)

type Report struct {
	TableSHA256               string `json:"table_sha256"`
	InputSHA256               string `json:"input_sha256"`
	ReportValid               bool   `json:"report_valid"`
	FilesVerified             bool   `json:"files_verified"`
	ReservationVerified       bool   `json:"reservation_verified"`
	CleanupComplete           bool   `json:"cleanup_complete"`
	DisplayOwnershipQualified bool   `json:"display_ownership_qualified"`
	DSPStarted                bool   `json:"DSP_started"`
	FileRows                  int    `json:"file_rows"`
	FileStatus                string `json:"file_status"`
	MemoryStatus              string `json:"memory_status"`
	CleanupStatus             string `json:"cleanup_status"`
	Text                      string `json:"text"`
	KernelQueriesComplete     bool   `json:"kernel_queries_complete"`
	KernelImageOverlaps       uint64 `json:"kernel_image_overlaps"`
	KernelMemoryEligible      bool   `json:"kernel_memory_eligible"`
	HobStorageMatches         uint64 `json:"HOB_storage_matches"`
	HobCopiedBase             string `json:"HOB_copied_base"`
	HobLimit                  string `json:"HOB_limit"`
	HobCount                  uint64 `json:"HOB_count"`
	HobWalkedBytes            uint64 `json:"HOB_walked_bytes"`
	HobStorageBounded         bool   `json:"HOB_storage_bounded"`
	ScmTable                  string `json:"SCM_table"`
	ScmSlot                   string `json:"SCM_slot"`
	ScmMapsObserved           bool   `json:"SCM_maps_observed"`
	ScmGCDAttributes          string `json:"SCM_GCD_attributes"`
	ScmEFIAttributes          string `json:"SCM_EFI_attributes"`
	ScmHookEligible           bool   `json:"SCM_hook_eligible"`
}

func success(s string) bool { return s == "Success" || s == "0" }
func statusLine(text, prefix string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, prefix) {
			return success(strings.TrimPrefix(line, prefix))
		}
	}
	return false
}

func decodeReport(b []byte) (Report, error) {
	var r Report
	if len(b) < 136 || len(b) > 32*1024+36 || string(b[:4]) != "OAPF" || int(binary.LittleEndian.Uint32(b[4:8])) != len(b) {
		return r, fmt.Errorf("ACPI report signature/length")
	}
	if b[8] != 1 || string(b[10:16]) != "OPEN  " || string(b[16:24]) != "G119PFLT" || binary.LittleEndian.Uint32(b[24:28]) != 119 || string(b[28:32]) != "OPEN" || binary.LittleEndian.Uint32(b[32:36]) != 1 {
		return r, fmt.Errorf("ACPI report identity")
	}
	var checksum byte
	for _, c := range b {
		checksum += c
	}
	if checksum != 0 {
		return r, fmt.Errorf("ACPI report checksum")
	}
	// Preserve the raw header, length, checksum and hash. EDK II emits CRLF;
	// normalize only complete pairs for the line grammar, rejecting bare CR.
	text := strings.ReplaceAll(string(b[36:]), "\r\n", "\n")
	for _, c := range []byte(text) {
		if !(c >= 32 && c <= 126) && c != '\n' {
			return r, fmt.Errorf("unexpected report encoding")
		}
	}
	prefix := "OPEN-ADSP-PREFLIGHT G119 version=1\ninput_sha256=" + inputSHA + "\nDSP_start=not_armed source_writes=blocked\n"
	if !strings.HasPrefix(text, prefix) || !strings.HasSuffix(text, "DSP_start=not_armed request_count=0\n") {
		return r, fmt.Errorf("report version/input/start guard")
	}
	finals := finalLine.FindAllStringSubmatch(text, -1)
	if len(finals) != 1 || finals[0][4] != "0" {
		return r, fmt.Errorf("missing/duplicate/truncated final result")
	}
	r.FileStatus, r.MemoryStatus, r.CleanupStatus = finals[0][1], finals[0][2], finals[0][3]
	rows := fileLine.FindAllStringSubmatch(text, -1)
	allFiles := len(rows) == len(expectedFiles)
	for i, row := range rows {
		index, e := strconv.Atoi(row[1])
		if e != nil || index != i || index >= len(expectedFiles) || row[2] != expectedFiles[index].Name {
			return r, fmt.Errorf("file report order/identity")
		}
		n, e1 := strconv.ParseUint(row[3], 10, 64)
		done, e2 := strconv.ParseUint(row[4], 10, 64)
		if e1 != nil || e2 != nil || n != expectedFiles[index].Bytes || done > n {
			return r, fmt.Errorf("file report size")
		}
		if !success(row[5]) || done != n {
			allFiles = false
		}
	}
	completed := completedLine.FindAllStringSubmatch(text, -1)
	complete := len(completed) == 1 && completed[0][1] == "64" && success(completed[0][2])
	counters := countersLine.FindAllStringSubmatch(text, -1)
	if len(counters) == 1 {
		for _, val := range counters[0][1:] {
			if _, err := strconv.ParseUint(val, 10, 64); err != nil {
				return r, fmt.Errorf("counter range")
			}
		}
		req, _ := strconv.ParseUint(counters[0][3], 10, 64)
		read, _ := strconv.ParseUint(counters[0][2], 10, 64)
		if req > 128*1024*1024 || read > req {
			return r, fmt.Errorf("read budget counters")
		}
	}
	clean := len(counters) == 1 && counters[0][4] == "0" && counters[0][5] == "0" && counters[0][6] == "0"
	r.FilesVerified = allFiles && complete && success(r.FileStatus) && statusLine(text, "metadata_before status=") && statusLine(text, "metadata_after status=")
	r.ReservationVerified = success(r.MemoryStatus) && strings.Contains(text, "hardware_display_ownership=not_tested\n")
	r.CleanupComplete = success(r.CleanupStatus) && clean && statusLine(text, "disconnect status=") && statusLine(text, "uninstall status=")
	h := sha256.Sum256(b)
	r.TableSHA256 = hex.EncodeToString(h[:])
	r.InputSHA256 = inputSHA
	r.ReportValid = true
	r.FileRows = len(rows)
	r.Text = text
	const marker = "OPEN-KERNEL-FOOTPRINT G133 version=1\n"
	if strings.Count(text, marker) != 1 || strings.Contains(text, "K133_ERROR") {
		return r, fmt.Errorf("missing/duplicate G133 footprint report")
	}
	done := regexp.MustCompile(`(?m)^K133_DONE queries_complete=([01]) PAS_allowed=0 DMA_ownership=not_proved region_writes=0$`).FindAllStringSubmatch(text, -1)
	images := regexp.MustCompile(`(?m)^K133_image_overlaps=([0-9]+) failures=([0-9]+)$`).FindAllStringSubmatch(text, -1)
	if len(done) != 1 || len(images) != 1 {
		return r, fmt.Errorf("G133 completion/counter identity")
	}
	n, err := strconv.ParseUint(images[0][1], 10, 64)
	fail, e2 := strconv.ParseUint(images[0][2], 10, 64)
	if err != nil || e2 != nil || n > 512 || fail > 512 {
		return r, fmt.Errorf("G133 image counter range")
	}
	r.KernelQueriesComplete = done[0][1] == "1"
	r.KernelImageOverlaps = n
	if err := decodeCopyAndSlot(text, &r); err != nil {
		return r, err
	}
	// This is a footprint inventory, never a global DMA/ownership or PAS grant.
	r.KernelMemoryEligible = false
	return r, nil
}

func decodeCopyAndSlot(text string, r *Report) error {
	one := func(pattern string) ([]string, error) {
		rows := regexp.MustCompile(`(?m)^`+pattern+`$`).FindAllStringSubmatch(text, -1)
		if len(rows) != 1 {
			return nil, fmt.Errorf("G133 copy/slot row identity")
		}
		return rows[0], nil
	}
	hb, e := one(`K133_hob_storage_matches=([0-9]+) base=([0-9A-Fa-f]{1,16}) limit=([0-9A-Fa-f]{1,16})`)
	if e != nil {
		return e
	}
	hc, e := one(`K133_hob_count=([0-9]+) walked_bytes=([0-9]+) overlaps=([0-9]+) end=([01])`)
	if e != nil {
		return e
	}
	sc, e := one(`K133_scm locate=(.*?) table=([0-9A-Fa-f]{1,16}) slot=([0-9A-Fa-f]{1,16}) table_reads=0 hook_writes=0`)
	if e != nil {
		return e
	}
	se, e := one(`K133_scm_efi_matches=([0-9]+)`)
	if e != nil {
		return e
	}
	parse := func(s string, base int) uint64 {
		v, err := strconv.ParseUint(s, base, 64)
		if err != nil {
			return ^uint64(0)
		}
		return v
	}
	base, limit := parse(hb[2], 16), parse(hb[3], 16)
	r.HobStorageMatches, r.HobCount, r.HobWalkedBytes = parse(hb[1], 10), parse(hc[1], 10), parse(hc[2], 10)
	if r.HobStorageMatches > 4096 || r.HobCount > 4096 || r.HobWalkedBytes > 1024*1024 || parse(hc[3], 10) > 4096 {
		return fmt.Errorf("G133 HOB counter range")
	}
	r.HobCopiedBase, r.HobLimit = fmt.Sprintf("0x%016x", base), fmt.Sprintf("0x%016x", limit)
	r.HobStorageBounded = r.HobStorageMatches == 1 && base != 0 && limit >= base && limit-base >= 56 && limit-base <= 1024*1024 && hc[4] == "1" && r.HobCount >= 2 && r.HobWalkedBytes+8 <= limit-base
	table, slot := parse(sc[2], 16), parse(sc[3], 16)
	r.ScmTable, r.ScmSlot = fmt.Sprintf("0x%016x", table), fmt.Sprintf("0x%016x", slot)
	gd := regexp.MustCompile(`(?m)^K133_scm_gcd base=([0-9A-Fa-f]{1,16}) bytes=([0-9A-Fa-f]{1,16}) type=([0-9]+) cap=([0-9A-Fa-f]{1,16}) attr=([0-9A-Fa-f]{1,16})$`).FindAllStringSubmatch(text, -1)
	ed := regexp.MustCompile(`(?m)^K133_scm_efi base=([0-9A-Fa-f]{1,16}) pages=([0-9A-Fa-f]{1,16}) type=([0-9]+) attr=([0-9A-Fa-f]{1,16})$`).FindAllStringSubmatch(text, -1)
	if len(gd) > 1 || len(ed) > 1 {
		return fmt.Errorf("G133 duplicate SCM map row")
	}
	covers := func(base, bytes uint64) bool {
		return bytes >= 8 && base <= slot && bytes <= ^uint64(0)-base && slot-base <= bytes-8
	}
	if len(gd) == 1 && len(ed) == 1 {
		g, d := gd[0], ed[0]
		pages, typ := parse(d[2], 16), parse(d[3], 10)
		r.ScmGCDAttributes, r.ScmEFIAttributes = "0x"+g[5], "0x"+d[4]
		r.ScmMapsObserved = success(sc[1]) && table != 0 && table <= ^uint64(0)-64 && slot == table+56 && se[1] == "1" && statusLine(text, "K133_scm_gcd_status=") && parse(g[3], 10) == 2 && typ >= 3 && typ <= 6 && pages <= ^uint64(0)/4096 && covers(parse(g[1], 16), parse(g[2], 16)) && covers(parse(d[1], 16), pages*4096)
	}
	if r.KernelQueriesComplete && (!r.HobStorageBounded || !r.ScmMapsObserved) {
		return fmt.Errorf("G133 completion contradicts copy/slot bounds")
	}
	// Published map attributes are observations, not CPU permission/DMA proof or
	// authorization to replace this shared table. SCM_hook_eligible remains false.
	return nil
}
