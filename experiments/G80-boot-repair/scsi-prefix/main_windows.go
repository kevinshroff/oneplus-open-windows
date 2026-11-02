package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
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

type scsiDevice struct {
	f       *os.File
	address uintptr
}

func (d *scsiDevice) transfer(op byte, lba uint32, data []byte, group byte) error {
	c, e := makeCDB(op, lba, len(data), group)
	if e != nil {
		return e
	}
	b := make([]byte, 96)
	binary.LittleEndian.PutUint16(b, 56)
	b[6] = 10
	b[7] = 40
	if op == 0x28 {
		b[8] = 1
	}
	binary.LittleEndian.PutUint32(b[12:], uint32(len(data)))
	binary.LittleEndian.PutUint32(b[16:], 15)
	binary.LittleEndian.PutUint64(b[24:], uint64(d.address))
	binary.LittleEndian.PutUint32(b[32:], 56)
	copy(b[36:], c[:])
	memory := unsafe.Slice((*byte)(unsafe.Pointer(d.address)), len(data))
	if op == 0x2a {
		copy(memory, data)
	}
	var n uint32
	ok, _, e := k32.NewProc("DeviceIoControl").Call(d.f.Fd(), 0x4d014, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&n)), 0)
	if ok == 0 {
		return fmt.Errorf("SCSI%#x lba%#x: %w", op, lba, e)
	}
	if n < 56 || b[2] != 0 || binary.LittleEndian.Uint32(b[12:]) != uint32(len(data)) {
		return fmt.Errorf("SCSI incomplete: op=%#x lba=%#x returned=%d status=%#x transfer=%d sense=%x", op, lba, n, b[2], binary.LittleEndian.Uint32(b[12:]), b[56:])
	}
	if op == 0x28 {
		copy(data, memory)
	}
	return nil
}
func (d *scsiDevice) read(l uint32, b []byte) error  { return d.transfer(0x28, l, b, 0) }
func (d *scsiDevice) write(l uint32, b []byte) error { return d.transfer(0x2a, l, b, 0) }
func checkpoint(path string, v any) error {
	b, e := json.Marshal(v)
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
func run() error {
	source := flag.String("source", "", "canonical Qualcomm USB PhysicalDrive")
	mode := flag.String("mode", "inspect", "inspect,apply,commit")
	planFile := flag.String("plan", "", "immutable pinned plan")
	image := flag.String("image", "", "exact1GiB target image")
	journal := flag.String("journal", "", "new durable laptop journal")
	start := flag.Int("start", 0, "first64KiB chunk")
	seconds := flag.Int("seconds", 90, "bounded updater work deadline,1..110")
	undo := flag.Bool("undo", false, "use independently built inverse firmware and original image")
	flag.Parse()
	if !rawPhysicalName(*source) || *start < 0 || *start > chunkCount || *seconds < 1 || *seconds > 110 {
		return fmt.Errorf("source/range/deadline guard")
	}
	if *mode != "inspect" && *mode != "apply" && *mode != "commit" {
		return fmt.Errorf("mode guard")
	}
	b, e := os.ReadFile(*planFile)
	if e != nil {
		return e
	}
	plan, e := parsePlan(b)
	if e != nil {
		return e
	}
	if *mode == "apply" && *journal == "" {
		return fmt.Errorf("durable journal required")
	}
	var input *os.File
	if *mode == "apply" {
		input, e = os.Open(*image)
		if e != nil {
			return e
		}
		defer input.Close()
		stat, e := input.Stat()
		if e != nil || !stat.Mode().IsRegular() || stat.Size() != 1<<30 {
			return fmt.Errorf("regular target image size guard")
		}
		h := sha256.New()
		if _, e = io.Copy(h, input); e != nil {
			return e
		}
		if !bytes.Equal(h.Sum(nil), plan.imageHash(*undo)) {
			return fmt.Errorf("whole proposed image hash")
		}
	}
	f, e := os.OpenFile(*source, os.O_RDWR, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	length, info, e := sourceInfo(f, *source)
	if e != nil {
		return e
	}
	if length != 1<<30 {
		return fmt.Errorf("only1GiB facade")
	}
	if info.(map[string]any)["serial"] != "20388561" {
		return fmt.Errorf("USB LUN serial guard")
	}
	addr, _, e := k32.NewProc("VirtualAlloc").Call(0, chunkBytes, 0x3000, 4)
	if addr == 0 {
		return e
	}
	defer k32.NewProc("VirtualFree").Call(addr, 0, 0x8000)
	d := &scsiDevice{f, addr}
	if *mode == "inspect" {
		data := make([]byte, chunkBytes)
		if e = d.read(0, data); e != nil {
			return e
		}
		h := sha256.Sum256(data)
		old, new := plan.hashes(0, *undo)
		if !bytes.Equal(h[:], old) && !bytes.Equal(h[:], new) {
			return fmt.Errorf("unknown first chunk")
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": "64KiB SCSI read qualified", "source_info": info, "chunk0_sha256": hex.EncodeToString(h[:]), "source_writes": 0})
	}
	if *mode == "commit" {
		data := make([]byte, 4096)
		if e = d.transfer(0x28, 0, data, 31); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": "read-only commit marker delivered; firmware must still verify whole prefix and GPT", "plan_sha256": planSHA, "undo": *undo})
	}
	// One host writer at a time; a killed job closes this mutex handle.
	name, _ := syscall.UTF16PtrFromString("Local\\OnePlusOpenG80PinnedWriter")
	mutex, _, me := k32.NewProc("CreateMutexW").Call(0, 0, uintptr(unsafe.Pointer(name)))
	if mutex == 0 {
		return me
	}
	defer k32.NewProc("CloseHandle").Call(mutex)
	if me == syscall.ERROR_ALREADY_EXISTS {
		return fmt.Errorf("another G80 writer exists")
	}
	if e = os.MkdirAll(filepath.Dir(*journal), 0700); e != nil {
		return e
	}
	record := map[string]any{"phase": "prepared", "plan_sha256": planSHA, "source_info": info, "start_chunk": *start, "undo": *undo, "utc": time.Now().UTC().Format(time.RFC3339Nano)}
	if e = checkpoint(*journal, record); e != nil {
		return e
	}
	limit := time.Now().Add(time.Duration(*seconds) * time.Second)
	next := *start
	written, skipped := 0, 0
	data := make([]byte, chunkBytes)
	for next < chunkCount && time.Now().Before(limit) {
		if _, e = input.ReadAt(data, int64(next)*chunkBytes); e != nil {
			return e
		}
		a, b := plan.hashes(next, *undo)
		did, e := applyChunk(d, next, data, a, b)
		if e != nil {
			return e
		}
		if did {
			written++
		} else {
			skipped++
		}
		next++
		if next%256 == 0 {
			fmt.Printf("verified through chunk%d/%d; writes%d unchanged%d\n", next, chunkCount, written, skipped)
		}
	}
	record["phase"] = "range_verified"
	record["next_chunk"] = next
	record["written_chunks"] = written
	record["skipped_chunks"] = skipped
	if e = checkpoint(*journal+".verified", record); e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(record)
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
