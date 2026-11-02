package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

type FATRead func(uint64, uint64) ([]byte, error)
type FATEntry struct {
	Name          string
	ShortName     string
	Attr          byte
	Cluster, Size uint32
}
type FATRegion struct {
	Offset uint64
	Bytes  []byte
}
type FAT struct {
	read                                                    FATRead
	Sector, ClusterBytes, DataOffset, RootOffset, RootBytes uint64
	Clusters, RootCluster                                   uint32
	Bits                                                    int
	Table                                                   []byte
	Metadata                                                []FATRegion
	DeclaredBytes, PhysicalBytes                            uint64
	LogicalClusters                                         uint32
}

func fatError(s string) error { return fmt.Errorf("FAT: %s", s) }
func (f *FAT) metadata(off, n uint64) ([]byte, error) {
	b, e := f.read(off, n)
	if e != nil {
		return nil, e
	}
	if uint64(len(b)) != n {
		return nil, fatError("short metadata")
	}
	f.Metadata = append(f.Metadata, FATRegion{off, append([]byte(nil), b...)})
	return b, nil
}
func OpenFAT(read FATRead, partitionBytes uint64) (*FAT, error) {
	return openFAT(read, partitionBytes, false)
}

// Forensic inspection permits an oversized BPB while restricting every chain
// to physically backed GPT clusters. It neither repairs nor qualifies a mount.
func OpenFATForensic(read FATRead, partitionBytes uint64) (*FAT, error) {
	return openFAT(read, partitionBytes, true)
}
func openFAT(read FATRead, partitionBytes uint64, forensic bool) (*FAT, error) {
	f := &FAT{read: read}
	b, e := f.metadata(0, 512)
	if e != nil {
		return nil, e
	}
	if b[510] != 0x55 || b[511] != 0xaa {
		return nil, fatError("boot signature")
	}
	f.Sector = uint64(binary.LittleEndian.Uint16(b[11:]))
	spc := uint64(b[13])
	reserved := uint64(binary.LittleEndian.Uint16(b[14:]))
	copies := uint64(b[16])
	rootEntries := uint64(binary.LittleEndian.Uint16(b[17:]))
	total := uint64(binary.LittleEndian.Uint16(b[19:]))
	if total == 0 {
		total = uint64(binary.LittleEndian.Uint32(b[32:]))
	}
	fatSectors := uint64(binary.LittleEndian.Uint16(b[22:]))
	if fatSectors == 0 {
		fatSectors = uint64(binary.LittleEndian.Uint32(b[36:]))
	}
	if f.Sector < 512 || f.Sector > 4096 || f.Sector&(f.Sector-1) != 0 || spc == 0 || spc > 128 || spc&(spc-1) != 0 || reserved == 0 || copies < 1 || copies > 2 || fatSectors == 0 || total == 0 || (!forensic && total*f.Sector > partitionBytes) {
		return nil, fatError(fmt.Sprintf("BPB geometry: OEM=%q bps=%d spc=%d reserved=%d copies=%d root_entries=%d fat_sectors=%d total_sectors=%d volume_bytes=%d partition_bytes=%d", string(b[3:11]), f.Sector, spc, reserved, copies, rootEntries, fatSectors, total, total*f.Sector, partitionBytes))
	}
	rootSectors := (rootEntries*32 + f.Sector - 1) / f.Sector
	overhead := reserved + copies*fatSectors + rootSectors
	if overhead >= total || overhead*f.Sector >= partitionBytes {
		return nil, fatError("overhead")
	}
	clusters := (total - overhead) / spc
	if clusters < 4085 {
		return nil, fatError("FAT12 unsupported")
	}
	f.Bits = 16
	if clusters >= 65525 {
		f.Bits = 32
	}
	if clusters > 0x0fffffed {
		return nil, fatError("cluster count")
	}
	f.LogicalClusters = uint32(clusters)
	f.DeclaredBytes = total * f.Sector
	f.PhysicalBytes = partitionBytes
	backed := (partitionBytes - overhead*f.Sector) / (spc * f.Sector)
	if backed < clusters {
		clusters = backed
	}
	f.Clusters = uint32(clusters)
	f.ClusterBytes = spc * f.Sector
	f.RootOffset = (reserved + copies*fatSectors) * f.Sector
	f.RootBytes = rootSectors * f.Sector
	f.DataOffset = overhead * f.Sector
	if f.RootBytes > 1<<20 {
		return nil, fatError("root directory limit")
	}
	selected := uint64(0)
	mirrored := true
	if f.Bits == 32 {
		if rootEntries != 0 || binary.LittleEndian.Uint16(b[22:]) != 0 || binary.LittleEndian.Uint16(b[42:]) != 0 {
			return nil, fatError("FAT32 fields")
		}
		f.RootCluster = binary.LittleEndian.Uint32(b[44:])
		flags := binary.LittleEndian.Uint16(b[40:])
		mirrored = flags&0x80 == 0
		if !mirrored {
			selected = uint64(flags & 15)
		}
		if f.RootCluster < 2 || f.RootCluster > f.Clusters+1 {
			return nil, fatError("root cluster")
		}
	} else if rootEntries == 0 || binary.LittleEndian.Uint16(b[22:]) == 0 {
		return nil, fatError("FAT16 fields")
	}
	tableBytes := fatSectors * f.Sector
	if selected >= copies || tableBytes > 4<<20 || tableBytes < uint64(f.LogicalClusters+2)*uint64(f.Bits/8) {
		return nil, fatError("table capacity")
	}
	var previous []byte
	for i := uint64(0); i < copies; i++ {
		table, e := f.metadata((reserved+i*fatSectors)*f.Sector, tableBytes)
		if e != nil {
			return nil, e
		}
		if mirrored && i > 0 && !bytes.Equal(previous, table) {
			return nil, fatError("FAT mirrors differ")
		}
		if i == selected {
			f.Table = table
		}
		previous = table
	}
	return f, nil
}
func (f *FAT) next(cluster uint32) (uint32, bool, error) {
	if cluster < 2 || cluster > f.Clusters+1 {
		return 0, false, fatError("cluster outside data")
	}
	offset := uint64(cluster) * uint64(f.Bits/8)
	var value uint32
	if f.Bits == 16 {
		value = uint32(binary.LittleEndian.Uint16(f.Table[offset:]))
		if value >= 0xfff8 {
			return 0, true, nil
		}
		if value >= 0xfff0 {
			return 0, false, fatError("reserved/bad cluster")
		}
	} else {
		value = binary.LittleEndian.Uint32(f.Table[offset:]) & 0x0fffffff
		if value >= 0x0ffffff8 {
			return 0, true, nil
		}
		if value >= 0x0ffffff0 {
			return 0, false, fatError("reserved/bad cluster")
		}
	}
	if value < 2 || value > f.Clusters+1 {
		return 0, false, fatError("broken chain")
	}
	return value, false, nil
}
func (f *FAT) chain(cluster uint32, size uint32, directory bool) ([]byte, error) {
	if !directory && (size == 0 || size > 1<<20) {
		return nil, fatError("fixed file size limit")
	}
	visited := map[uint32]bool{}
	var out []byte
	for {
		if cluster < 2 || cluster > f.Clusters+1 || visited[cluster] {
			return nil, fatError("invalid/cyclic chain")
		}
		visited[cluster] = true
		if uint64(len(out))+f.ClusterBytes > 1<<20 {
			return nil, fatError("chain limit")
		}
		offset := f.DataOffset + uint64(cluster-2)*f.ClusterBytes
		var b []byte
		var e error
		if directory {
			b, e = f.metadata(offset, f.ClusterBytes)
		} else {
			b, e = f.read(offset, f.ClusterBytes)
		}
		if e != nil {
			return nil, e
		}
		if uint64(len(b)) != f.ClusterBytes {
			return nil, fatError("short cluster")
		}
		out = append(out, b...)
		next, end, e := f.next(cluster)
		if e != nil {
			return nil, e
		}
		if !directory && len(out) >= int(size) {
			if !end {
				return nil, fatError("overallocated file chain")
			}
			return out[:size], nil
		}
		if end {
			if !directory {
				return nil, fatError("short file chain")
			}
			return out, nil
		}
		cluster = next
	}
}
func lfnChecksum(name []byte) byte {
	var sum byte
	for _, value := range name {
		sum = (sum >> 1) | ((sum & 1) << 7)
		sum += value
	}
	return sum
}
func (f *FAT) Directory(cluster uint32, root bool) ([]FATEntry, error) {
	var b []byte
	var e error
	if root && f.Bits == 16 {
		b, e = f.metadata(f.RootOffset, f.RootBytes)
	} else {
		if root {
			cluster = f.RootCluster
		}
		b, e = f.chain(cluster, 0, true)
	}
	if e != nil {
		return nil, e
	}
	result := []FATEntry{}
	names := map[string]bool{}
	shortNames := map[string]bool{}
	var long []uint16
	expected := 0
	checksum := byte(0)
	positions := []int{1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30}
	for i := 0; i+32 <= len(b); i += 32 {
		v := b[i : i+32]
		if v[0] == 0 {
			break
		}
		if v[0] == 0xe5 {
			long = nil
			expected = 0
			continue
		}
		if v[11] == 15 {
			ordinal := int(v[0] & 31)
			if v[0]&0xa0 != 0 || ordinal == 0 || ordinal > 20 || v[12] != 0 || binary.LittleEndian.Uint16(v[26:]) != 0 {
				return nil, fatError("invalid LFN header")
			}
			if v[0]&0x40 != 0 {
				long = make([]uint16, ordinal*13)
				expected = ordinal
				checksum = v[13]
			}
			if long == nil || ordinal != expected || v[13] != checksum {
				return nil, fatError("LFN sequence/checksum")
			}
			for j, at := range positions {
				long[(ordinal-1)*13+j] = binary.LittleEndian.Uint16(v[at:])
			}
			expected--
			continue
		}
		if v[11]&8 != 0 {
			long = nil
			expected = 0
			continue
		}
		base := strings.TrimRight(string(v[:8]), " ")
		extension := strings.TrimRight(string(v[8:11]), " ")
		short := base
		if extension != "" {
			short += "." + extension
		}
		short = strings.ToLower(short)
		name := short
		if long != nil {
			if expected != 0 || checksum != lfnChecksum(v[:11]) {
				return nil, fatError("LFN does not bind short entry")
			}
			used := []uint16{}
			terminated := false
			for _, unit := range long {
				if terminated {
					if unit != 0xffff && unit != 0 {
						return nil, fatError("LFN padding")
					}
					continue
				}
				if unit == 0 {
					terminated = true
					continue
				}
				if unit == 0xffff {
					return nil, fatError("LFN premature padding")
				}
				used = append(used, unit)
			}
			if len(used) == 0 || len(used) > 255 {
				return nil, fatError("LFN length")
			}
			decoded := utf16.Decode(used)
			encoded := utf16.Encode(decoded)
			if len(encoded) != len(used) {
				return nil, fatError("LFN Unicode")
			}
			for j := range used {
				if encoded[j] != used[j] {
					return nil, fatError("LFN Unicode")
				}
			}
			name = strings.ToLower(string(decoded))
			if strings.ContainsAny(name, "/\\\x00") {
				return nil, fatError("LFN path separator")
			}
		}
		long = nil
		expected = 0
		if name == "." || name == ".." {
			continue
		}
		if name == "" || short == "" || names[name] || shortNames[short] {
			return nil, fatError("empty/duplicate directory name")
		}
		names[name] = true
		shortNames[short] = true
		cluster := uint32(binary.LittleEndian.Uint16(v[26:]))
		if f.Bits == 32 {
			cluster |= uint32(binary.LittleEndian.Uint16(v[20:])) << 16
		}
		result = append(result, FATEntry{Name: name, ShortName: short, Attr: v[11], Cluster: cluster, Size: binary.LittleEndian.Uint32(v[28:])})
	}
	return result, nil
}
func (f *FAT) File(entry FATEntry) ([]byte, error) {
	if entry.Attr&0x10 != 0 {
		return nil, fatError("directory passed as file")
	}
	return f.chain(entry.Cluster, entry.Size, false)
}
func (f *FAT) VerifyMetadata() error {
	for _, region := range f.Metadata {
		b, e := f.read(region.Offset, uint64(len(region.Bytes)))
		if e != nil {
			return e
		}
		if !bytes.Equal(b, region.Bytes) {
			return fatError("metadata changed during read")
		}
	}
	return nil
}

// Extents checks the captured FAT without reading any segment data.
func (f *FAT) Extents(entry FATEntry) ([][2]uint64, error) {
	if entry.Attr&0x10 != 0 || uint64(entry.Size) > f.PhysicalBytes {
		return nil, fatError("extent file size/type")
	}
	if entry.Size == 0 {
		return [][2]uint64{}, nil
	}
	left := uint64(entry.Size)
	cluster := entry.Cluster
	seen := map[uint32]bool{}
	ranges := [][2]uint64{}
	for left > 0 {
		if cluster < 2 || cluster > f.Clusters+1 || seen[cluster] {
			return nil, fatError("extent invalid/cyclic cluster")
		}
		seen[cluster] = true
		start := f.DataOffset + uint64(cluster-2)*f.ClusterBytes
		n := f.ClusterBytes
		if n > left {
			n = left
		}
		if start > f.PhysicalBytes || n > f.PhysicalBytes-start {
			return nil, fatError("extent outside physical partition")
		}
		ranges = append(ranges, [2]uint64{start, n})
		left -= n
		next, end, e := f.next(cluster)
		if e != nil {
			return nil, e
		}
		if left == 0 {
			if !end {
				return nil, fatError("extent overallocated chain")
			}
			break
		}
		if end {
			return nil, fatError("extent short chain")
		}
		cluster = next
	}
	return ranges, nil
}
