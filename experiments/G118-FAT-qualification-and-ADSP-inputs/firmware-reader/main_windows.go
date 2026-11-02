package main

import (
	"archive/zip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

func run(result map[string]any) error {
	if len(os.Args) != 1 {
		return fmt.Errorf("fixed collector takes no arguments")
	}
	if e := fullOSGuard(); e != nil {
		return e
	}
	var ver struct {
		Size, Major, Minor, Build, Platform uint32
		CSD                                 [128]uint16
	}
	ver.Size = uint32(unsafe.Sizeof(ver))
	status, _, _ := syscall.NewLazyDLL("ntdll.dll").NewProc("RtlGetVersion").Call(uintptr(unsafe.Pointer(&ver)))
	if status != 0 || ver.Build != 26300 {
		return fmt.Errorf("kernel build identity")
	}
	fw := syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemFirmwareTable")
	n, _, _ := fw.Call(0x41435049, 0x54445344, 0, 0)
	if n != 576 {
		return fmt.Errorf("DSDT length")
	}
	dsdt := make([]byte, n)
	got, _, _ := fw.Call(0x41435049, 0x54445344, uintptr(unsafe.Pointer(&dsdt[0])), n)
	if got != n || sum(dsdt) != "c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01" {
		return fmt.Errorf("DSDT identity")
	}
	d, e := discover(targets["modem_a"])
	if e != nil {
		return e
	}
	defer d.f.Close()
	result["target"] = d.Target
	result["disk_index"] = d.Index
	result["GPT_header_sha256"] = d.HeaderSHA
	result["GPT_array_sha256"] = d.ArraySHA
	var bytesRead uint64
	calls := 0
	read := func(off, n uint64) ([]byte, error) {
		if n == 0 || n > 4<<20 || off > d.Target.Bytes || n > d.Target.Bytes-off {
			return nil, fmt.Errorf("partition read bounds")
		}
		start, end := off&^uint64(4095), (off+n+4095)&^uint64(4095)
		if end > d.Target.Bytes || calls >= 8192 || bytesRead+2*(end-start) > 160<<20 {
			return nil, fmt.Errorf("FAT read budget")
		}
		calls++
		bytesRead += 2 * (end - start)
		result["FAT_read_calls"] = calls
		result["FAT_double_read_bytes"] = bytesRead
		b, e := stable(d.f, d.Target.Offset+start, end-start)
		if e != nil {
			return nil, e
		}
		return b[off-start : off-start+n], nil
	}
	fs, e := OpenFATForensic(read, d.Target.Bytes)
	if e != nil {
		return e
	}
	root, e := fs.Directory(0, true)
	if e != nil {
		return e
	}
	var image *FATEntry
	for _, r := range root {
		if r.Name == "image" && r.Attr&0x10 != 0 {
			if image != nil {
				return fmt.Errorf("duplicate image directory")
			}
			v := r
			image = &v
		}
	}
	if image == nil {
		return fmt.Errorf("configured image directory absent")
	}
	entries, e := fs.Directory(image.Cluster, false)
	if e != nil {
		return e
	}
	selected, e := checkDirectory(entries)
	if e != nil {
		return e
	}
	result["FAT_geometry"] = map[string]any{"sector": fs.Sector, "cluster_bytes": fs.ClusterBytes, "declared_bytes": fs.DeclaredBytes, "physical_bytes": fs.PhysicalBytes, "logical_clusters": fs.LogicalClusters, "physical_clusters": fs.Clusters, "bits": fs.Bits}
	base := `C:\OpenG81\payloads`
	dir := filepath.Join(base, "G118-firmware")
	for _, component := range []string{`C:\`, `C:\OpenG81`, base} {
		name, err := syscall.UTF16PtrFromString(component)
		if err != nil {
			return err
		}
		attrs, err := syscall.GetFileAttributes(name)
		if err != nil || attrs&syscall.FILE_ATTRIBUTE_DIRECTORY == 0 || attrs&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("output path must remain an ordinary project directory")
		}
	}
	if e := os.Mkdir(dir, 0700); e != nil {
		return fmt.Errorf("exclusive output directory: %w", e)
	}
	result["output_directory"] = dir
	sw, e := newSplitWriter(dir, 24<<20)
	if e != nil {
		return e
	}
	zw := zip.NewWriter(sw)
	closed := false
	defer func() {
		if !closed {
			zw.Close()
			sw.Close()
		}
	}()
	manifest := map[string]any{"target": d.Target, "GPT_header_sha256": d.HeaderSHA, "GPT_array_sha256": d.ArraySHA, "FAT_geometry": result["FAT_geometry"], "boot_sector_512": fs.Metadata[0].Bytes, "source_directory": "image", "source_directory_metadata": selected, "native_source_writes": 0}
	captures := []FileCapture{}
	known := map[string]string{"adsp.mdt": "353c6cbb2f0f8782d3ce91818d25e195e8402d11942b8ba18ddf70f5fae2ffb8", "adsp_dtb.mdt": "5476d25e617ebf2c51128fe1405d01f8731547ce14778a62893625dda7d0e0b1", "adsp_dtb.b01": "f71892ad4ff2ac1100a07f63b4a5ef246749a95937a797d50480e7c70b1b2f94"}
	for _, entry := range selected {
		out, e := zw.Create("firmware/image/" + entry.Name)
		if e != nil {
			return e
		}
		cap, e := streamFile(fs, entry, read, out)
		if e != nil {
			return e
		}
		if h, ok := known[entry.Name]; ok && cap.SHA256 != h {
			return fmt.Errorf("retained MDT/config identity changed")
		}
		captures = append(captures, cap)
	}
	if e := fs.VerifyMetadata(); e != nil {
		return e
	}
	p, e := stable(d.f, sector, sector)
	if e != nil {
		return e
	}
	h, e := header(p, d.Target.DiskBytes, 1)
	if e != nil {
		return e
	}
	ar, e := stable(d.f, h.ArrayLBA*sector, uint64(h.Count)*uint64(h.Stride))
	if e != nil {
		return e
	}
	if sum(p) != d.HeaderSHA || sum(ar) != d.ArraySHA {
		return fmt.Errorf("source GPT changed")
	}
	backup, e := stable(d.f, d.Target.DiskBytes-sector, sector)
	if e != nil {
		return e
	}
	bh, e := header(backup, d.Target.DiskBytes, d.Target.DiskBytes/sector-1)
	if e != nil {
		return e
	}
	ba, e := stable(d.f, bh.ArrayLBA*sector, uint64(bh.Count)*uint64(bh.Stride))
	if e != nil {
		return e
	}
	part, e := matchArrays(d.Target, h, bh, ar, ba)
	if e != nil || part != d.Partition {
		return fmt.Errorf("source GPT copies changed")
	}
	result["GPT_copies_revalidated"] = true
	manifest["GPT_copies_revalidated"] = true
	manifest["files"] = captures
	metadata := []map[string]any{}
	for i, r := range fs.Metadata {
		name := fmt.Sprintf("metadata/%03d.bin", i)
		out, e := zw.Create(name)
		if e != nil {
			return e
		}
		if _, e = out.Write(r.Bytes); e != nil {
			return e
		}
		metadata = append(metadata, map[string]any{"name": name, "offset": r.Offset, "bytes": len(r.Bytes), "sha256": sum(r.Bytes)})
	}
	manifest["metadata"] = metadata
	manifest["FAT_metadata_unchanged"] = true
	manifest["GPT_primary_header_array_unchanged"] = true
	out, e := zw.Create("capture.json")
	if e != nil {
		return e
	}
	if e = json.NewEncoder(out).Encode(manifest); e != nil {
		return e
	}
	if e = zw.Close(); e != nil {
		return e
	}
	if e = sw.Close(); e != nil {
		return e
	}
	closed = true

	result["files"] = captures
	result["file_count"] = len(captures)
	result["FAT_metadata_unchanged"] = true
	result["GPT_primary_header_array_unchanged"] = true
	result["parts"] = sw.parts
	result["archive_bytes"] = sw.total
	result["archive_sha256"] = hex.EncodeToString(sw.totalHash.Sum(nil))
	result["firmware_file_bytes"] = func() uint64 {
		var n uint64
		for _, r := range captures {
			n += r.Bytes
		}
		return n
	}()
	result["metadata_regions"] = len(fs.Metadata)
	result["boot_sector_sha256"] = sum(fs.Metadata[0].Bytes)
	saved := map[string]any{}
	for k, v := range result {
		saved[k] = v
	}
	saved["ok"] = true
	report, e := json.MarshalIndent(saved, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "capture-result.json"), report, 0600); e != nil {
		return e
	}
	return nil
}
func main() {
	began := time.Now()
	result := map[string]any{"ok": false, "tool": "G118-readonly-firmware-input-collector", "source_access": "GENERIC_READ physical disk only", "source_Windows_D_access": false, "source_writes": 0, "scope": "copy64fixedADSPfilesandFATmetadata to exclusive project C directory; no boot-FAT deployment"}
	e := run(result)
	if e != nil {
		result["error"] = e.Error()
	} else {
		result["ok"] = true
	}
	result["duration_ms"] = time.Since(began).Milliseconds()
	json.NewEncoder(os.Stdout).Encode(result)
	if e != nil {
		os.Exit(1)
	}
}
