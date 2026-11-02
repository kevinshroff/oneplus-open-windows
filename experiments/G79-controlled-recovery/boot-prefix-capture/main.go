// Preserve an explicitly bounded prefix from the read-only G79 USB facade.
// No source write, mount, filesystem repair, or volume state IOCTL is used.
package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

func stage(s string) { fmt.Fprintln(os.Stderr, "stage:", s) }

func rawPhysicalName(s string) bool {
	p := string([]byte{92, 92, 46, 92}) + "PhysicalDrive"
	if !strings.HasPrefix(s, p) || len(s) == len(p) {
		return false
	}
	for _, c := range s[len(p):] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func checkBounds(length, expected, count int64) error {
	if expected != 1<<30 || length != expected || count < 4096 || count > length || count%4096 != 0 {
		return errors.New("require exact 1 GiB G79 facade and an aligned prefix of 4 KiB..1 GiB")
	}
	return nil
}

func copyPrefix(w io.Writer, r io.ReaderAt, count int64) (string, error) {
	if count < 4096 || count > 1<<30 || count%4096 != 0 {
		return "", errors.New("invalid prefix size")
	}
	h := sha256.New()
	b := make([]byte, 1<<20)
	for off := int64(0); off < count; {
		n := int64(len(b))
		if n > count-off {
			n = count - off
		}
		if _, e := r.ReadAt(b[:n], off); e != nil {
			return "", e
		}
		if _, e := io.MultiWriter(w, h).Write(b[:n]); e != nil {
			return "", e
		}
		off += n
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func run() error {
	source := flag.String("source", "", "canonical PhysicalDrive path or test image")
	expected := flag.Int64("expected-size", 0, "must be 1073741824")
	count := flag.Int64("bytes", 0, "explicit aligned prefix byte count")
	out := flag.String("out", "", "new evidence ZIP, never replaced")
	flag.Parse()
	if *source == "" || *out == "" {
		return errors.New("source and out are required")
	}
	if e := checkBounds(*expected, *expected, *count); e != nil {
		return e
	}
	src, e := os.Open(*source)
	if e != nil {
		return e
	}
	defer src.Close()
	length, info, e := sourceInfo(src, *source)
	if e != nil {
		return e
	}
	if e = checkBounds(length, *expected, *count); e != nil {
		return e
	}
	boot := make([]byte, 4096)
	if _, e = src.ReadAt(boot, 0); e != nil {
		return e
	}
	before := sha256.Sum256(boot)
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
	w, e := z.Create("prefix.bin")
	if e != nil {
		return e
	}
	digest, e := copyPrefix(w, src, *count)
	if e != nil {
		return e
	}
	if _, e = src.ReadAt(boot, 0); e != nil {
		return e
	}
	after := sha256.Sum256(boot)
	if before != after {
		return errors.New("boot sector changed during capture")
	}
	m := map[string]any{"version": "G79-boot-prefix-1", "utc": time.Now().UTC().Format(time.RFC3339Nano),
		"source": *source, "source_info": info, "source_bytes": length,
		"source_access": "read-only; no source write or mount APIs", "prefix_bytes": *count,
		"prefix_sha256": digest, "boot_before_sha256": hex.EncodeToString(before[:]), "boot_after_sha256": hex.EncodeToString(after[:])}
	w, e = z.Create("manifest.json")
	if e != nil {
		return e
	}
	if e = json.NewEncoder(w).Encode(m); e != nil {
		return e
	}
	if e = z.Close(); e != nil {
		return e
	}
	if e = of.Close(); e != nil {
		return e
	}
	complete = true
	return json.NewEncoder(os.Stdout).Encode(m)
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
