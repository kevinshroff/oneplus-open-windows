package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

// This patch format never expresses an absolute disk address. The Windows
// adapter supplies the already matched partition handle. Version1 is userdata
// FAT; version2 is the backed-up16MiB boot_a prefix. No absolute disk addresses.
type Change struct {
	Offset uint64 `json:"offset"`
	Before []byte `json:"before"`
	After  []byte `json:"after"`
}
type Patch struct {
	Version     int      `json:"version"`
	Target      string   `json:"target"`
	PrefixBytes uint64   `json:"prefix_bytes"`
	BeforeSHA   string   `json:"before_sha256"`
	AfterSHA    string   `json:"after_sha256"`
	Changes     []Change `json:"changes"`
}
type patchFile interface {
	io.ReaderAt
	io.WriterAt
	Sync() error
}

func validatePatch(p Patch) error {
	fat := p.Version == 1 && p.Target == "userdata" && p.PrefixBytes > 0 && p.PrefixBytes <= 256<<20
	boot := p.Version == 2 && p.Target == "boot_a" && p.PrefixBytes == 16<<20
	if (!fat && !boot) || p.PrefixBytes%sector != 0 || len(p.Changes) == 0 || len(p.Changes) > 1024 {
		return fmt.Errorf("patch scope/version")
	}
	for _, h := range []string{p.BeforeSHA, p.AfterSHA} {
		b, e := hex.DecodeString(h)
		if e != nil || len(b) != 32 {
			return fmt.Errorf("patch whole-prefix hash")
		}
	}
	var end uint64
	for i, c := range p.Changes {
		if len(c.Before) != 4096 || len(c.After) != 4096 || c.Offset%sector != 0 || c.Offset >= p.PrefixBytes || sector > p.PrefixBytes-c.Offset || (i > 0 && c.Offset < end) {
			return fmt.Errorf("patch sector bounds/order")
		}
		if p.Target == "userdata" && c.Offset == 0 && !bytes.Equal(c.Before[:512], c.After[:512]) {
			return fmt.Errorf("FAT boot sector modification refused")
		}
		end = c.Offset + sector
	}
	return nil
}
func regionHash(f io.ReaderAt, start, n uint64) (string, error) {
	h := sha256.New()
	b := make([]byte, 1<<20)
	for done := uint64(0); done < n; {
		size := uint64(len(b))
		if size > n-done {
			size = n - done
		}
		if _, e := f.ReadAt(b[:size], int64(start+done)); e != nil {
			return "", e
		}
		h.Write(b[:size])
		done += size
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func applyPatch(f patchFile, start uint64, p Patch, checkpoint func(string, []uint64) error) (err error) {
	if e := validatePatch(p); e != nil {
		return e
	}
	if start > 1<<50 || p.PrefixBytes > 1<<50-start {
		return fmt.Errorf("absolute extent overflow")
	}
	for pass := 0; pass < 2; pass++ {
		h, e := regionHash(f, start, p.PrefixBytes)
		if e != nil {
			return e
		}
		if h != p.BeforeSHA {
			return fmt.Errorf("whole-prefix preimage mismatch on pass %d", pass)
		}
	}
	// Check every individual before-image before creating the durable journal.
	for _, c := range p.Changes {
		b := make([]byte, 4096)
		if _, e := f.ReadAt(b, int64(start+c.Offset)); e != nil {
			return e
		}
		if !bytes.Equal(b, c.Before) {
			return fmt.Errorf("sector preimage mismatch at %x", c.Offset)
		}
	}
	// Establish the complete proposed postimage before enabling any write.
	hypothetical := sha256.New()
	buffer := make([]byte, 1<<20)
	for done := uint64(0); done < p.PrefixBytes; {
		size := uint64(len(buffer))
		if size > p.PrefixBytes-done {
			size = p.PrefixBytes - done
		}
		if _, e := f.ReadAt(buffer[:size], int64(start+done)); e != nil {
			return e
		}
		for _, c := range p.Changes {
			if c.Offset >= done && c.Offset < done+size {
				copy(buffer[c.Offset-done:c.Offset-done+sector], c.After)
			}
		}
		hypothetical.Write(buffer[:size])
		done += size
	}
	if hex.EncodeToString(hypothetical.Sum(nil)) != p.AfterSHA {
		return fmt.Errorf("declared postimage does not match proposed sectors")
	}
	written := []uint64{}
	if e := checkpoint("prepared", written); e != nil {
		return e
	}
	defer func() {
		if err == nil {
			return
		}
		// Treat a failed/short write as potentially modifying its whole sector.
		var rollbackError error
		for i := len(written) - 1; i >= 0; i-- {
			var c *Change
			for j := range p.Changes {
				if p.Changes[j].Offset == written[i] {
					c = &p.Changes[j]
					break
				}
			}
			if c == nil {
				rollbackError = fmt.Errorf("rollback journal inconsistency")
				continue
			}
			n, e := f.WriteAt(c.Before, int64(start+c.Offset))
			if e != nil || n != len(c.Before) {
				rollbackError = fmt.Errorf("rollback write %x: %v", c.Offset, e)
			}
		}
		if e := f.Sync(); e != nil {
			rollbackError = e
		}
		h, e := regionHash(f, start, p.PrefixBytes)
		if e != nil || h != p.BeforeSHA {
			rollbackError = fmt.Errorf("rollback readback mismatch: %v", e)
		}
		state := "rolled_back"
		if rollbackError != nil {
			state = "rollback_incomplete"
		}
		if e := checkpoint(state, written); e != nil {
			rollbackError = e
		}
		if rollbackError != nil {
			err = fmt.Errorf("%v; rollback: %v", err, rollbackError)
		}
	}()
	for _, c := range p.Changes {
		written = append(written, c.Offset)
		n, e := f.WriteAt(c.After, int64(start+c.Offset))
		if e != nil || n != len(c.After) {
			return fmt.Errorf("write %x count=%d: %v", c.Offset, n, e)
		}
		if e = f.Sync(); e != nil {
			return fmt.Errorf("flush %x: %w", c.Offset, e)
		}
		b := make([]byte, 4096)
		if _, e = f.ReadAt(b, int64(start+c.Offset)); e != nil {
			return e
		}
		if !bytes.Equal(b, c.After) {
			return fmt.Errorf("readback mismatch at %x", c.Offset)
		}
		if e = checkpoint("writing", written); e != nil {
			return e
		}
	}
	h, e := regionHash(f, start, p.PrefixBytes)
	if e != nil {
		return e
	}
	if h != p.AfterSHA {
		return fmt.Errorf("whole-prefix final readback mismatch")
	}
	if e = checkpoint("verified", written); e != nil {
		return e
	}
	return nil
}
