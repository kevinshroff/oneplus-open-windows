package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

func immutableJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}

// Store the complete before/after sector data once, then atomically checkpoint
// bounded progress records. Avoid serializing a multi-MiB plan for each sector.
func bootJournal(path string, p Patch, witness any) (func(string, []uint64) error, error) {
	if e := pathGuard(path); e != nil {
		return nil, e
	}
	planFile := path + ".plan.json"
	for _, f := range []string{path, path + ".new", planFile} {
		if _, e := os.Stat(f); !os.IsNotExist(e) {
			return nil, fmt.Errorf("preserve existing boot journal/plan")
		}
	}
	prepared := false
	planSHA := ""
	return func(phase string, attempted []uint64) error {
		if !prepared {
			if phase != "prepared" {
				return fmt.Errorf("boot journal must start prepared")
			}
			if e := immutableJSON(planFile, p); e != nil {
				return e
			}
			var e error
			planSHA, _, e = fileHash(planFile)
			if e != nil {
				return e
			}
			prepared = true
		}
		r := map[string]any{"version": "G18-boot-a-r4", "phase": phase, "identity": witness, "plan_file": planFile, "plan_sha256": planSHA, "before_sha256": p.BeforeSHA, "after_sha256": p.AfterSHA, "prefix_bytes": p.PrefixBytes, "write_attempted_offsets": append([]uint64{}, attempted...), "utc": time.Now().UTC().Format(time.RFC3339Nano)}
		return leaseJournal(path, r)
	}, nil
}
func applyBootA(planPath, journalPath string) error {
	x, boot, e := requireRAM()
	if e != nil {
		return e
	}
	p, e := readPlan(planPath)
	if e != nil {
		return e
	}
	if p.Version != 2 || p.Target != "boot_a" || p.PrefixBytes != 16<<20 {
		return fmt.Errorf("only version2 backed-up boot_a16MiB prefix is writable")
	}
	release, e := writerMutex()
	if e != nil {
		return e
	}
	defer release()
	d, e := discover(targets["boot_a"])
	if e != nil {
		return e
	}
	defer d.f.Close()
	header, e := stable(d.f, d.Target.Offset, 4096)
	if e != nil {
		return e
	}
	if e = validateBootHeader(header, p.PrefixBytes); e != nil {
		return e
	}
	proposed := bytes.Clone(header)
	for _, c := range p.Changes {
		if c.Offset == 0 {
			copy(proposed, c.After)
		}
	}
	if e = validateBootHeader(proposed, p.PrefixBytes); e != nil {
		return e
	}
	f, e := partitionHandle(d, true)
	if e != nil {
		return e
	}
	defer f.Close()
	current, e := stable(f, 0, 4096)
	if e != nil || !bytes.Equal(header, current) {
		return fmt.Errorf("partition header changed before write: %v", e)
	}
	g, e := ioctl(f, 0x700a0, 1024)
	if e != nil || len(g) < 32 || u32(g, 20) != 4096 {
		return fmt.Errorf("boot_a sector-size guard: %v", e)
	}
	witness := map[string]any{"target": d.Target, "partition_path": partitionPath(d), "disk_index": d.Index, "partition_number": d.Partition, "gpt_header_sha256": d.HeaderSHA, "gpt_array_sha256": d.ArraySHA, "x_device": x, "SystemBootDevice": boot, "writable_handle": "exact boot_a partition; FILE_FLAG_WRITE_THROUGH"}
	checkpoint, e := bootJournal(journalPath, p, witness)
	if e != nil {
		return e
	}
	if e = applyPatch(f, 0, p, checkpoint); e != nil {
		return e
	}
	emit(map[string]any{"version": "G18-boot-a-r4", "phase": "verified", "identity": witness, "prefix_bytes": p.PrefixBytes, "before_sha256": p.BeforeSHA, "after_sha256": p.AfterSHA, "sectors_written": len(p.Changes), "journal": journalPath, "plan_copy": journalPath + ".plan.json"})
	return nil
}
