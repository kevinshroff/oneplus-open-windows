package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var fixedImageMetadata = []string{"adsp.mdt", "adsp_dtb.mdt", "adsp_dtb.b01"}

func runHeaders(result map[string]any) error {
	if len(os.Args) != 1 {
		return fmt.Errorf("fixed read-only helper accepts no arguments")
	}
	if e := fullOSGuard(); e != nil {
		return e
	}
	firmware := syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemFirmwareTable")
	n, _, _ := firmware.Call(0x41435049, 0x54445344, 0, 0)
	if n != 576 {
		return fmt.Errorf("DSDT length")
	}
	table := make([]byte, n)
	got, _, _ := firmware.Call(0x41435049, 0x54445344, uintptr(unsafe.Pointer(&table[0])), n)
	if got != n || sum(table) != "c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01" {
		return fmt.Errorf("DSDT identity")
	}
	d, e := discover(targets["modem_a"])
	if e != nil {
		return e
	}
	defer d.f.Close()
	result["target"] = d.Target
	result["disk_index"] = d.Index
	result["partition_number"] = d.Partition
	result["GPT_header_sha256"] = d.HeaderSHA
	result["GPT_array_sha256"] = d.ArraySHA
	var physicalBytes uint64
	calls := 0
	read := func(off, n uint64) ([]byte, error) {
		if n == 0 || n > 4<<20 || off > d.Target.Bytes || n > d.Target.Bytes-off {
			return nil, fmt.Errorf("partition read range")
		}
		begin := off &^ uint64(4095)
		end := (off + n + 4095) &^ uint64(4095)
		if end > d.Target.Bytes || calls >= 4096 || physicalBytes+(end-begin)*2 > 32<<20 {
			return nil, fmt.Errorf("read budget")
		}
		calls++
		physicalBytes += (end - begin) * 2
		result["FAT_physical_double_read_bytes"] = physicalBytes
		result["FAT_read_calls"] = calls
		b, e := stable(d.f, d.Target.Offset+begin, end-begin)
		if e != nil {
			return nil, e
		}
		return b[off-begin : off-begin+n], nil
	}
	fs, e := OpenFATForensic(read, d.Target.Bytes)
	if e != nil {
		return e
	}
	result["FAT_geometry"] = map[string]any{"bits": fs.Bits, "sector_bytes": fs.Sector, "cluster_bytes": fs.ClusterBytes, "physical_data_clusters": fs.Clusters, "logical_data_clusters": fs.LogicalClusters, "declared_bytes": fs.DeclaredBytes, "physical_partition_bytes": fs.PhysicalBytes, "declared_volume_fits_partition": fs.DeclaredBytes <= fs.PhysicalBytes, "forensic_read_only": true}
	root, e := fs.Directory(0, true)
	if e != nil {
		return e
	}
	result["FAT_root_entries"] = root
	result["VFAT_long_names_validated"] = true
	var image *FATEntry
	for _, entry := range root {
		if entry.Name == "image" && entry.Attr&0x10 != 0 {
			x := entry
			image = &x
		}
	}
	entries := root
	result["configured_IMAGE_directory_present"] = image != nil
	result["metadata_location"] = "FAT root (forensic lookup; configured IMAGE path absent)"
	if image != nil {
		entries, e = fs.Directory(image.Cluster, false)
		if e != nil {
			return e
		}
		result["metadata_location"] = "IMAGE directory"
	}
	selected := map[string]FATEntry{}
	eligible := []FATEntry{}
	for _, entry := range entries {
		if entry.Attr&0x10 == 0 && strings.HasPrefix(entry.Name, "adsp") {
			eligible = append(eligible, entry)
		}
		for _, name := range fixedImageMetadata {
			if entry.Name == name {
				selected[name] = entry
			}
		}
	}
	result["ADSP_directory_metadata"] = eligible
	spans := map[string]any{}
	for _, entry := range eligible {
		ranges, err := fs.Extents(entry)
		if err != nil {
			spans[entry.Name] = map[string]any{"error": err.Error()}
			continue
		}
		end := uint64(0)
		digest := sha256.New()
		for _, span := range ranges {
			if span[0]+span[1] > end {
				end = span[0] + span[1]
			}
			fmt.Fprintf(digest, "%d:%d;", span[0], span[1])
		}
		spans[entry.Name] = map[string]any{"physical_extents_in_bounds": true, "file_bytes": entry.Size, "cluster_count": len(ranges), "max_relative_data_end": end, "extent_list_sha256": hex.EncodeToString(digest.Sum(nil))}
	}
	result["ADSP_extent_proofs"] = spans
	for _, name := range fixedImageMetadata {
		if _, ok := selected[name]; !ok {
			if e := fs.VerifyMetadata(); e != nil {
				return e
			}
			result["FAT_metadata_unchanged"] = true
			return fmt.Errorf("fixed metadata file missing: %s", name)
		}
	}
	captures := map[string]any{}
	result["fixed_metadata_files"] = captures
	for _, name := range fixedImageMetadata {
		entry, ok := selected[name]
		if !ok {
			return fmt.Errorf("fixed metadata file missing: %s", name)
		}
		data, e := fs.File(entry)
		if e != nil {
			return e
		}
		digest := sha256.Sum256(data)
		captures[name] = map[string]any{"bytes": len(data), "sha256": hex.EncodeToString(digest[:]), "data_base64": data}
	}
	for _, directory := range root {
		if directory.Name != "verinfo" || directory.Attr&0x10 == 0 {
			continue
		}
		versionEntries, err := fs.Directory(directory.Cluster, false)
		if err != nil {
			result["verinfo_error"] = err.Error()
			break
		}
		result["verinfo_entries"] = versionEntries
		for _, entry := range versionEntries {
			if (entry.Name != "ver_info.txt" && entry.Name != "ver_info.json") || entry.Attr&0x10 != 0 || entry.Size > 65536 {
				continue
			}
			data, err := fs.File(entry)
			if err != nil {
				result["verinfo_error"] = err.Error()
				continue
			}
			digest := sha256.Sum256(data)
			captures["verinfo/"+entry.Name] = map[string]any{"bytes": len(data), "sha256": hex.EncodeToString(digest[:]), "data_base64": data}
		}
	}
	if e := fs.VerifyMetadata(); e != nil {
		return e
	}
	result["FAT_metadata_unchanged"] = true
	result["ok"] = true
	return nil
}
func main() {
	started := time.Now()
	result := map[string]any{"ok": false, "tool": "G107-fixed-readonly-ADSP-MDT", "access": "GENERIC_READ", "raw_writes": 0, "Windows_filesystem_D_access": false}
	e := runHeaders(result)
	if e != nil {
		result["error"] = e.Error()
	}
	result["duration_ms"] = time.Since(started).Milliseconds()
	json.NewEncoder(os.Stdout).Encode(result)
	if e != nil {
		os.Exit(1)
	}
}
