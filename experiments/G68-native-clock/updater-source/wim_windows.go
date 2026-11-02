package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func readWIMPlan(path string) (WIMPlan, error) {
	var p WIMPlan
	if e := pathGuard(path); e != nil {
		return p, e
	}
	f, e := os.Open(path)
	if e != nil {
		return p, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || st.Size() > 24<<20 {
		return p, fmt.Errorf("trial WIM plan file size")
	}
	dec := json.NewDecoder(io.LimitReader(f, 24<<20))
	dec.DisallowUnknownFields()
	if e = dec.Decode(&p); e != nil {
		return p, e
	}
	var extra any
	if e = dec.Decode(&extra); e != io.EOF {
		return p, fmt.Errorf("trailing trial WIM plan")
	}
	return p, validateWIMPlan(p)
}

func inactiveTrialHandle(path, xDevice string) (*os.File, error) {
	p, e := syscall.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, e := syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, 0x80000000|0x00200000, 0)
	if e != nil {
		return nil, fmt.Errorf("exclusive trial WIM open: %w", e)
	}
	f := os.NewFile(uintptr(h), path)
	var info syscall.ByHandleFileInformation
	if e = syscall.GetFileInformationByHandle(h, &info); e != nil || info.FileAttributes&(0x10|0x400) != 0 || info.NumberOfLinks != 1 {
		f.Close()
		return nil, fmt.Errorf("trial WIM regular nonreparse single-link guard: %v", e)
	}
	buf := make([]uint16, 32768)
	n, _, e := syscall.NewLazyDLL("kernel32.dll").NewProc("GetFinalPathNameByHandleW").Call(uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 2)
	if n == 0 || n >= uintptr(len(buf)) || !strings.EqualFold(syscall.UTF16ToString(buf[:n]), xDevice+`\OpenG18\`+trialWIMName) {
		f.Close()
		return nil, fmt.Errorf("trial WIM final path identity guard: %v", e)
	}
	return f, nil
}

// Only the already matched physical G17 X: filesystem is accepted. Every
// disk/partition/volume handle is read-only; only one fixed regular file is
// writable. The G17 boot, original RAM WIM, GPT and protected boot slots are
// outside this command's write interface.
func updateTrialWIM(planPath, journalPath string) error {
	if e := pathGuard(journalPath); e != nil {
		return e
	}
	if strings.EqualFold(filepath.Clean(planPath), filepath.Clean(journalPath)) {
		return fmt.Errorf("distinct WIM plan and journal required")
	}
	if _, e := os.Stat(journalPath); !os.IsNotExist(e) {
		return fmt.Errorf("preserve existing WIM journal")
	}
	p, e := readWIMPlan(planPath)
	if e != nil {
		return e
	}
	if p.BeforeBytes < 500<<20 || p.AfterBytes < 500<<20 {
		return fmt.Errorf("native trial WIM extent guard")
	}
	release, e := writerMutex()
	if e != nil {
		return e
	}
	defer release()
	d, e := discover(targets["super"])
	if e != nil {
		return e
	}
	defer d.f.Close()
	x, e := dosDevice("X:")
	if e != nil || !strings.HasPrefix(strings.ToLower(x), `\device\harddiskvolume`) {
		return fmt.Errorf("requires physical G17 X: root: %v", e)
	}
	v, e := volumeOpen("X:", false)
	if e != nil {
		return e
	}
	e = matchingVolume(v, d)
	v.Close()
	if e != nil {
		return fmt.Errorf("physical X: super-volume identity: %w", e)
	}
	path := `X:\OpenG18\` + trialWIMName
	for _, other := range []string{planPath, journalPath} {
		if strings.EqualFold(filepath.Clean(path), filepath.Clean(other)) {
			return fmt.Errorf("trial file/plan/journal alias")
		}
	}
	f, e := inactiveTrialHandle(path, x)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || uint64(st.Size()) != p.BeforeBytes {
		return fmt.Errorf("trial WIM exact preimage size: %v", e)
	}
	identity := map[string]any{"target": d.Target, "file": path, "x_device": x, "disk_index": d.Index, "partition_number": d.Partition, "gpt_header_sha256": d.HeaderSHA, "gpt_array_sha256": d.ArraySHA, "access": "exclusive regular file; FILE_FLAG_WRITE_THROUGH; final NT path verified", "raw_writes": 0}
	checkpoint := func(phase string, written []uint64) error {
		return leaseJournal(journalPath, map[string]any{"version": "G21-trial-wim-v1", "phase": phase, "identity": identity, "plan": p, "write_attempted_offsets": append([]uint64{}, written...), "utc": time.Now().UTC().Format(time.RFC3339Nano)})
	}
	if e = applyWIMPlan(f, p, checkpoint); e != nil {
		return e
	}
	st, e = f.Stat()
	if e != nil || uint64(st.Size()) != p.AfterBytes {
		return fmt.Errorf("trial WIM final size: %v", e)
	}
	emit(map[string]any{"phase": "verified", "identity": identity, "before_sha256": p.BeforeSHA, "after_sha256": p.AfterSHA, "before_bytes": p.BeforeBytes, "after_bytes": p.AfterBytes, "changed_ranges": len(p.Changes), "tail_bytes": len(p.Tail), "journal": journalPath})
	return nil
}
