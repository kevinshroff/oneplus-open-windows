package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

var safeADSP = regexp.MustCompile(`^(adsp(_dtbs?)?\.(mdt|b[0-9]{2})|adspr\.jsn|adsps\.jsn|adspua\.jsn)$`)

func checkDirectory(entries []FATEntry) ([]FATEntry, error) {
	var want []FATEntry
	if e := json.Unmarshal([]byte(expectedDirectoryJSON), &want); e != nil {
		return nil, e
	}
	selectByName := func(in []FATEntry) ([]FATEntry, error) {
		out := []FATEntry{}
		seen := map[string]bool{}
		for _, x := range in {
			if len(x.Name) < 4 || x.Name[:4] != "adsp" {
				continue
			}
			if x.Attr&0x10 != 0 || !safeADSP.MatchString(x.Name) || seen[x.Name] {
				return nil, fmt.Errorf("unexpected ADSP directory record")
			}
			seen[x.Name] = true
			out = append(out, x)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out, nil
	}
	a, e := selectByName(entries)
	if e != nil {
		return nil, e
	}
	b, e := selectByName(want)
	if e != nil {
		return nil, e
	}
	aa, e := json.Marshal(a)
	if e != nil {
		return nil, e
	}
	bb, e := json.Marshal(b)
	if e != nil {
		return nil, e
	}
	if !bytes.Equal(aa, bb) || len(a) != 64 {
		return nil, fmt.Errorf("ADSP directory differs from retained G107")
	}
	return a, nil
}

type FileCapture struct {
	Name    string
	Bytes   uint64
	SHA256  string
	Extents [][2]uint64
}

func streamFile(fs *FAT, entry FATEntry, read FATRead, out io.Writer) (FileCapture, error) {
	var result FileCapture
	result.Name = entry.Name
	spans, e := fs.Extents(entry)
	if e != nil {
		return result, e
	}
	result.Extents = spans
	h := sha256.New()
	var merged [][2]uint64
	for _, span := range spans {
		if len(merged) > 0 {
			last := &merged[len(merged)-1]
			if last[0]+last[1] == span[0] && last[1]+span[1] <= 1<<20 {
				last[1] += span[1]
				continue
			}
		}
		merged = append(merged, span)
	}
	for _, span := range merged {
		b, e := read(span[0], span[1])
		if e != nil {
			return result, e
		}
		if uint64(len(b)) != span[1] {
			return result, io.ErrUnexpectedEOF
		}
		n, e := out.Write(b)
		if e != nil {
			return result, e
		}
		if n != len(b) {
			return result, io.ErrShortWrite
		}
		h.Write(b)
		result.Bytes += uint64(len(b))
	}
	if result.Bytes != uint64(entry.Size) {
		return result, fmt.Errorf("file size changed")
	}
	result.SHA256 = hex.EncodeToString(h.Sum(nil))
	return result, nil
}

type PartCapture struct {
	Name   string
	Bytes  int64
	SHA256 string
}
type splitWriter struct {
	dir         string
	limit       int64
	file        *os.File
	partHash    hash.Hash
	totalHash   hash.Hash
	size, total int64
	parts       []PartCapture
	closed      bool
}

func newSplitWriter(dir string, limit int64) (*splitWriter, error) {
	if limit <= 0 || limit > 24<<20 {
		return nil, fmt.Errorf("part limit")
	}
	return &splitWriter{dir: dir, limit: limit, totalHash: sha256.New()}, nil
}
func (s *splitWriter) finishPart() error {
	if s.file == nil {
		return nil
	}
	if e := s.file.Sync(); e != nil {
		return e
	}
	if e := s.file.Close(); e != nil {
		return e
	}
	s.parts = append(s.parts, PartCapture{filepath.Base(s.file.Name()), s.size, hex.EncodeToString(s.partHash.Sum(nil))})
	s.file = nil
	s.size = 0
	return nil
}
func (s *splitWriter) Write(b []byte) (int, error) {
	if s.closed {
		return 0, fmt.Errorf("archive already closed")
	}
	done := 0
	for len(b) > 0 {
		if s.file == nil {
			if len(s.parts) >= 4 {
				return done, fmt.Errorf("archive part count")
			}
			f, e := os.OpenFile(filepath.Join(s.dir, fmt.Sprintf("bundle-%02d.bin", len(s.parts))), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				return done, e
			}
			s.file = f
			s.partHash = sha256.New()
		}
		take := int64(len(b))
		if take > s.limit-s.size {
			take = s.limit - s.size
		}
		n, e := s.file.Write(b[:int(take)])
		if n > 0 {
			s.partHash.Write(b[:n])
			s.totalHash.Write(b[:n])
			s.size += int64(n)
			s.total += int64(n)
			done += n
			b = b[n:]
		}
		if e != nil {
			return done, e
		}
		if n != int(take) {
			return done, io.ErrShortWrite
		}
		if s.size == s.limit {
			if e := s.finishPart(); e != nil {
				return done, e
			}
		}
	}
	return done, nil
}
func (s *splitWriter) Close() error {
	if s.closed {
		return fmt.Errorf("archive already closed")
	}
	s.closed = true
	return s.finishPart()
}
