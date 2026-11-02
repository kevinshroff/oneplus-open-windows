// Read a quiescent NTFS image/device and preserve setup evidence in a new ZIP.
// The source is opened read-only. There are no filesystem mounts or source writes.
package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"www.velocidex.com/golang/go-ntfs/parser"
)

var trace = flag.Bool("trace", false, "print bounded diagnostic stages")

func stage(s string) {
	if *trace {
		fmt.Fprintln(os.Stderr, "stage:", s)
	}
}

type item struct {
	Path       string `json:"path"`
	Status     string `json:"status"`
	Bytes      int64  `json:"bytes,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Error      string `json:"error,omitempty"`
	Entries    int    `json:"entries,omitempty"`
	ReparseTag string `json:"reparse_tag,omitempty"`
}
type manifest struct {
	Version      string `json:"version"`
	UTC          string `json:"utc"`
	Source       string `json:"source"`
	SourceInfo   any    `json:"source_info"`
	SourceBytes  int64  `json:"source_bytes"`
	SourceAccess string `json:"source_access"`
	BootSHA256   string `json:"boot_sha256"`
	SectorBytes  uint16 `json:"sector_bytes"`
	ClusterBytes int64  `json:"cluster_bytes"`
	Records      []item `json:"records"`
}
type pathFlags []string

func (p *pathFlags) String() string     { return strings.Join(*p, ",") }
func (p *pathFlags) Set(s string) error { *p = append(*p, s); return nil }

// Bounds and sector alignment are enforced independently of the NTFS parser.
type alignedReader struct {
	f    io.ReaderAt
	size int64
}

func (a *alignedReader) ReadAt(dst []byte, off int64) (int, error) {
	if off < 0 || off > a.size || int64(len(dst)) > a.size-off {
		return 0, io.EOF
	}
	if len(dst) == 0 {
		return 0, nil
	}
	if len(dst) > 16<<20 {
		return 0, errors.New("parser read exceeds 16 MiB cap")
	}
	start := off &^ int64(4095)
	end := (off + int64(len(dst)) + 4095) &^ int64(4095)
	if end > a.size {
		return 0, io.EOF
	}
	b := make([]byte, end-start)
	n, e := a.f.ReadAt(b, start)
	if int64(n) < end-start {
		if e == nil {
			e = io.ErrUnexpectedEOF
		}
		return 0, e
	}
	copy(dst, b[off-start:])
	return len(dst), nil
}

func safePath(p string) bool {
	return p != "" && p != "." && p == path.Clean(p) && !strings.HasPrefix(p, "/") &&
		!strings.HasPrefix(p, "../") && !strings.ContainsAny(p, "\\:\x00")
}

func run() error {
	image := flag.String("source", "", "regular NTFS image or canonical Windows PhysicalDrive path")
	size := flag.Int64("expected-size", 0, "required exact source length")
	out := flag.String("out", "", "new ZIP output path")
	var paths pathFlags
	flag.Var(&paths, "path", "collect a specific path (repeatable; replaces default evidence paths)")
	flag.Parse()
	if *size <= 0 || *size%4096 != 0 || *out == "" || *image == "" {
		return errors.New("source, sector-aligned expected-size and out are required")
	}
	stage("opening read-only source")
	src, e := os.Open(*image)
	if e != nil {
		return e
	}
	defer src.Close()
	stage("source opened")
	length, info, e := sourceInfo(src, *image)
	if e != nil {
		return e
	}
	if length != *size {
		return fmt.Errorf("source size mismatch: got %d expected %d", length, *size)
	}
	stage("source identity and length accepted")
	reader := &alignedReader{src, length}
	boot := make([]byte, 4096)
	if _, e = reader.ReadAt(boot, 0); e != nil {
		return e
	}
	if string(boot[3:11]) != "NTFS    " || binary.LittleEndian.Uint16(boot[11:13]) != 4096 {
		return errors.New("expected NTFS with 4096-byte sectors")
	}
	if binary.LittleEndian.Uint64(boot[40:48]) > uint64(*size/4096) {
		return errors.New("NTFS geometry exceeds source")
	}
	h := sha256.Sum256(boot)
	m := manifest{Version: "G79-readonly-ntfs-4", UTC: time.Now().UTC().Format(time.RFC3339Nano), Source: *image, SourceInfo: info, SourceBytes: length, SourceAccess: "read-only; no mount; no source write APIs", BootSHA256: hex.EncodeToString(h[:]), SectorBytes: 4096}
	cache, e := parser.NewPagedReader(reader, 4096, 8192)
	if e != nil {
		return e
	}
	stage("boot sector accepted; bootstrapping NTFS")
	ntfs, e := parser.GetNTFSContext(cache, 0)
	if e != nil {
		return fmt.Errorf("NTFS bootstrap: %w", e)
	}
	defer ntfs.Close()
	m.ClusterBytes = ntfs.ClusterSize
	stage("NTFS bootstrap complete")
	root, e := ntfs.GetMFT(5)
	if e != nil {
		return e
	}
	if len(paths) == 0 {
		paths = []string{
			"Windows/Panther", "Windows/System32/Sysprep/Panther", "$WINDOWS.~BT/Sources/Panther", "$WINDOWS.~BT/Sources/Rollback",
			"Windows/INF/setupapi.dev.log", "Windows/INF/setupapi.offline.log", "Windows/Logs/DISM/dism.log", "Windows/Logs/CBS/CBS.log",
			"Windows/System32/config/SYSTEM", "Windows/System32/config/SOFTWARE", "Windows/System32/config/SYSTEM.LOG1", "Windows/System32/config/SYSTEM.LOG2",
			"Windows/System32/config/SOFTWARE.LOG1", "Windows/System32/config/SOFTWARE.LOG2", "Windows/Setup/State/State.ini",
		}
	}
	for _, p := range paths {
		if !safePath(p) {
			return fmt.Errorf("unsafe collection path %q", p)
		}
	}
	of, e := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	complete := false
	defer func() {
		of.Close()
		if !complete {
			os.Remove(*out)
		}
	}()
	z := zip.NewWriter(of)
	seen := map[string]bool{}
	var total int64
	recordError := func(p, s string, e error) { m.Records = append(m.Records, item{Path: p, Status: s, Error: e.Error()}) }
	var collect func(string, int)
	collect = func(p string, depth int) {
		if !safePath(p) {
			recordError(p, "refused", errors.New("unsafe NTFS name"))
			return
		}
		key := strings.ToLower(p)
		if seen[key] {
			return
		}
		seen[key] = true
		if len(seen) > 500 || depth > 5 {
			recordError(p, "refused", errors.New("collection count/depth cap"))
			return
		}
		entry, err := root.Open(ntfs, p)
		if err != nil {
			recordError(p, "missing_or_unreadable", err)
			return
		}
		// CompactOS/WOF files can have a zero-filled sparse unnamed DATA
		// stream and their real content in a provider-specific named stream.
		// The pinned parser does not materialize reparse providers. Never
		// label those unnamed bytes as the logical file's captured contents.
		for _, attr := range entry.EnumerateAttributes(ntfs) {
			if attr.Type().Value != 0xc0 {
				continue
			}
			var tag [4]byte
			_, tagErr := attr.Data(ntfs).ReadAt(tag[:], 0)
			record := item{Path: p, Status: "unsupported_reparse", Error: "reparse provider is not materialized; no logical file bytes captured"}
			if tagErr == nil {
				record.ReparseTag = fmt.Sprintf("0x%08x", binary.LittleEndian.Uint32(tag[:]))
			} else {
				record.Error += "; unreadable tag: " + tagErr.Error()
			}
			m.Records = append(m.Records, record)
			return
		}
		if entry.Flags().IsSet("DIRECTORY") {
			children := parser.ListDir(ntfs, entry)
			m.Records = append(m.Records, item{Path: p, Status: "directory", Entries: len(children)})
			for _, child := range children {
				if child.Name == "." || child.Name == ".." {
					continue
				}
				if strings.ContainsAny(child.Name, "/\\:\x00") {
					continue
				}
				collect(p+"/"+child.Name, depth+1)
			}
			return
		}
		stream, err := parser.GetDataForPath(ntfs, p)
		if err != nil {
			recordError(p, "stream_error", err)
			return
		}
		n := parser.RangeSize(stream)
		for _, declared := range parser.Stat(ntfs, entry) {
			if !declared.IsDir && !strings.Contains(declared.Name, ":") && declared.Size != n {
				recordError(p, "stream_size_mismatch", fmt.Errorf("declared %d, readable %d", declared.Size, n))
				return
			}
		}
		if n < 0 || n > 256<<20 || total+n > 512<<20 {
			recordError(p, "refused", fmt.Errorf("evidence size cap: %d bytes", n))
			return
		}
		w, err := z.Create("files/" + p)
		if err != nil {
			recordError(p, "zip_error", err)
			return
		}
		digest := sha256.New()
		w = io.MultiWriter(w, digest)
		actual, err := io.Copy(w, io.NewSectionReader(stream, 0, n))
		if err != nil || actual != n {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			recordError(p, "incomplete", err)
			return
		}
		total += n
		m.Records = append(m.Records, item{Path: p, Status: "captured", Bytes: actual, SHA256: hex.EncodeToString(digest.Sum(nil))})
		fmt.Printf("captured %s %d bytes\n", p, n)
	}
	for _, p := range paths {
		collect(p, 0)
	}
	last := make([]byte, 4096)
	if _, e = reader.ReadAt(last, 0); e != nil {
		return e
	}
	if sha256.Sum256(last) != h {
		return errors.New("boot sector changed during collection")
	}
	w, e := z.Create("manifest.json")
	if e != nil {
		return e
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if e = enc.Encode(m); e != nil {
		return e
	}
	if e = z.Close(); e != nil {
		return e
	}
	if e = of.Sync(); e != nil {
		return e
	}
	if e = of.Close(); e != nil {
		return e
	}
	complete = true
	abs, _ := filepath.Abs(*out)
	fmt.Printf("Evidence saved %s; %d records; %d file bytes. Inspect manifest for missing/incomplete paths.\n", abs, len(m.Records), total)
	return nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

func rawPhysicalName(s string) bool {
	prefix := string([]byte{92, 92, 46, 92}) + "PhysicalDrive"
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	rest := s[len(prefix):]
	if len(rest) == 0 {
		return false
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
