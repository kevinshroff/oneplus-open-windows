package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

const trialWIMName = `G20-acpi-canary.wim`

// This format addresses byte ranges of one regular, inactive trial WIM.
// It cannot describe a partition, an original G18 image, or a boot image.
type WIMChange struct {
	Offset uint64 `json:"offset"`
	Before []byte `json:"before"`
	After  []byte `json:"after"`
}
type WIMPlan struct {
	Version     string      `json:"version"`
	Name        string      `json:"name"`
	BeforeBytes uint64      `json:"before_bytes"`
	AfterBytes  uint64      `json:"after_bytes"`
	BeforeSHA   string      `json:"before_sha256"`
	AfterSHA    string      `json:"after_sha256"`
	Changes     []WIMChange `json:"changes"`
	// Tail is the appended postimage for growth, or the retained preimage
	// backup for an inverse update that truncates the file.
	Tail []byte `json:"tail"`
}
type wimFile interface {
	io.ReaderAt
	io.WriterAt
	Sync() error
	Truncate(int64) error
}

func validateWIMPlan(p WIMPlan) error {
	common, delta := wimExtents(p)
	if p.Version != "G21-trial-wim-v1" || p.Name != trialWIMName || common < 4096 || p.BeforeBytes > 1<<30 || p.AfterBytes > 1<<30 || delta != uint64(len(p.Tail)) || len(p.Changes) == 0 || len(p.Changes) > 512 {
		return fmt.Errorf("trial WIM scope/size/version")
	}
	for _, h := range []string{p.BeforeSHA, p.AfterSHA} {
		b, e := hex.DecodeString(h)
		if e != nil || len(b) != 32 || h != hex.EncodeToString(b) {
			return fmt.Errorf("trial WIM hash encoding")
		}
	}
	var end, payload uint64
	payload = uint64(len(p.Tail))
	for i, c := range p.Changes {
		n := uint64(len(c.Before))
		if n == 0 || n > 65536 || len(c.After) != len(c.Before) || c.Offset >= common || n > common-c.Offset || (i > 0 && c.Offset < end) {
			return fmt.Errorf("trial WIM change bounds/order")
		}
		end = c.Offset + n
		payload += n * 2
	}
	if payload > 16<<20 {
		return fmt.Errorf("trial WIM change payload exceeds16MiB")
	}
	// The original and proposed headers must describe single-image boot WIMs.
	if p.Changes[0].Offset != 0 || len(p.Changes[0].Before) < 128 || !bootWIMHeader(p.Changes[0].Before) || !bootWIMHeader(p.Changes[0].After) {
		return fmt.Errorf("trial WIM header guard")
	}
	return nil
}
func wimExtents(p WIMPlan) (common, delta uint64) {
	if p.AfterBytes >= p.BeforeBytes {
		return p.BeforeBytes, p.AfterBytes - p.BeforeBytes
	}
	return p.AfterBytes, p.BeforeBytes - p.AfterBytes
}
func bootWIMHeader(b []byte) bool {
	return len(b) >= 128 && bytes.Equal(b[:8], []byte{'M', 'S', 'W', 'I', 'M', 0, 0, 0}) && u32(b, 8) == 208 && u32(b, 44) == 1 && u32(b, 120) == 1
}

// Compute the entire proposed image before the first write, including all
// unchanged data. Range hashes alone cannot establish a coherent postimage.
func proposedWIMHash(f io.ReaderAt, p WIMPlan) (string, error) {
	h := sha256.New()
	common, _ := wimExtents(p)
	var pos uint64
	for _, c := range p.Changes {
		if _, e := io.Copy(h, io.NewSectionReader(f, int64(pos), int64(c.Offset-pos))); e != nil {
			return "", e
		}
		h.Write(c.After)
		pos = c.Offset + uint64(len(c.Before))
	}
	if _, e := io.Copy(h, io.NewSectionReader(f, int64(pos), int64(common-pos))); e != nil {
		return "", e
	}
	if p.AfterBytes > p.BeforeBytes {
		h.Write(p.Tail)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func applyWIMPlan(f wimFile, p WIMPlan, checkpoint func(string, []uint64) error) (err error) {
	if e := validateWIMPlan(p); e != nil {
		return e
	}
	for pass := 0; pass < 2; pass++ {
		h, e := regionHash(f, 0, p.BeforeBytes)
		if e != nil || h != p.BeforeSHA {
			return fmt.Errorf("trial WIM preimage pass%d: %v", pass, e)
		}
	}
	for _, c := range p.Changes {
		b := make([]byte, len(c.Before))
		if _, e := f.ReadAt(b, int64(c.Offset)); e != nil || !bytes.Equal(b, c.Before) {
			return fmt.Errorf("trial WIM range preimage%x: %v", c.Offset, e)
		}
	}
	if p.AfterBytes < p.BeforeBytes {
		b := make([]byte, len(p.Tail))
		if _, e := f.ReadAt(b, int64(p.AfterBytes)); e != nil || !bytes.Equal(b, p.Tail) {
			return fmt.Errorf("trial WIM truncation preimage: %v", e)
		}
	}
	h, e := proposedWIMHash(f, p)
	if e != nil || h != p.AfterSHA {
		return fmt.Errorf("trial WIM proposed full postimage mismatch: %v", e)
	}
	written := []uint64{}
	if e := checkpoint("prepared", written); e != nil {
		return e
	}
	defer func() {
		if err == nil {
			return
		}
		var re error
		// For an inverse update, restore the removed resource tail before
		// restoring its referring header. A failed truncation may be partial.
		if p.AfterBytes < p.BeforeBytes {
			n, e := f.WriteAt(p.Tail, int64(p.AfterBytes))
			if e != nil || n != len(p.Tail) {
				re = fmt.Errorf("trial WIM rollback tail: %v", e)
			}
			if e := f.Sync(); e != nil {
				re = e
			}
		}
		for _, off := range written {
			for _, c := range p.Changes {
				if c.Offset == off {
					n, e := f.WriteAt(c.Before, int64(off))
					if e != nil || n != len(c.Before) {
						re = fmt.Errorf("trial WIM rollback range%x: %v", off, e)
					}
				}
			}
		}
		if e := f.Truncate(int64(p.BeforeBytes)); e != nil {
			re = e
		}
		if e := f.Sync(); e != nil {
			re = e
		}
		h, e := regionHash(f, 0, p.BeforeBytes)
		if e != nil || h != p.BeforeSHA {
			re = fmt.Errorf("trial WIM rollback full hash: %v", e)
		}
		phase := "rolled_back"
		if re != nil {
			phase = "rollback_incomplete"
		}
		if e := checkpoint(phase, written); e != nil {
			re = e
		}
		if re != nil {
			err = fmt.Errorf("%v; rollback: %v", err, re)
		}
	}()
	if p.AfterBytes > p.BeforeBytes {
		n, e := f.WriteAt(p.Tail, int64(p.BeforeBytes))
		if e != nil || n != len(p.Tail) {
			return fmt.Errorf("trial WIM append count%d: %v", n, e)
		}
		if e = f.Sync(); e != nil {
			return e
		}
		b := make([]byte, len(p.Tail))
		if _, e := f.ReadAt(b, int64(p.BeforeBytes)); e != nil || !bytes.Equal(b, p.Tail) {
			return fmt.Errorf("trial WIM appended resource readback: %v", e)
		}
	}
	if e := checkpoint("resources_prepared", written); e != nil {
		return e
	}
	// Publish the new header last, after the new compressed resources and
	// metadata have been flushed and read back through the exclusive handle.
	for i := len(p.Changes) - 1; i >= 0; i-- {
		c := p.Changes[i]
		written = append(written, c.Offset)
		n, e := f.WriteAt(c.After, int64(c.Offset))
		if e != nil || n != len(c.After) {
			return fmt.Errorf("trial WIM write%x count%d: %v", c.Offset, n, e)
		}
		if e = f.Sync(); e != nil {
			return e
		}
		b := make([]byte, len(c.After))
		if _, e := f.ReadAt(b, int64(c.Offset)); e != nil || !bytes.Equal(b, c.After) {
			return fmt.Errorf("trial WIM range readback%x: %v", c.Offset, e)
		}
		if e := checkpoint("writing_header_last", written); e != nil {
			return e
		}
	}
	if p.AfterBytes < p.BeforeBytes {
		if e := f.Truncate(int64(p.AfterBytes)); e != nil {
			return e
		}
		if e := f.Sync(); e != nil {
			return e
		}
	}
	h, e = regionHash(f, 0, p.AfterBytes)
	if e != nil || h != p.AfterSHA {
		return fmt.Errorf("trial WIM full final readback: %v", e)
	}
	return checkpoint("verified", written)
}
