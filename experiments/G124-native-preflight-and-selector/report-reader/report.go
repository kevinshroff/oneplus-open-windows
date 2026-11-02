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
	if len(b) < 136 || len(b) > 24*1024+36 || string(b[:4]) != "OAPF" || int(binary.LittleEndian.Uint32(b[4:8])) != len(b) {
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
	// EDK II AsciiVSPrint emits CRLF for the firmware's newline format. Keep
	// the original bytes for the ACPI checksum and table identity; normalize
	// only complete CRLF pairs for the line-oriented grammar below. Bare CR,
	// NUL and all other control/non-ASCII bytes still fail validation.
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
	return r, nil
}
