package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"unicode/utf16"
)

type fixture struct {
	data     []byte
	fat      int
	fatBytes int
	root     int
	image    int
	file     int
	bits     int
}

func putLongEntry(data []byte, at int, long, short string, sfn []byte) int {
	units := utf16.Encode([]rune(long))
	count := (len(units) + 12) / 13
	checksum := lfnChecksum([]byte(short))
	positions := []int{1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30}
	for ordinal := count; ordinal >= 1; ordinal-- {
		v := data[at : at+32]
		for j := range v {
			v[j] = 0
		}
		v[0] = byte(ordinal)
		if ordinal == count {
			v[0] |= 0x40
		}
		v[11] = 15
		v[13] = checksum
		for j, pos := range positions {
			index := (ordinal-1)*13 + j
			value := uint16(0xffff)
			if index < len(units) {
				value = units[index]
			} else if index == len(units) {
				value = 0
			}
			binary.LittleEndian.PutUint16(v[pos:], value)
		}
		at += 32
	}
	copy(data[at:at+32], sfn)
	copy(data[at:at+11], []byte(short))
	return at + 32
}
func TestVFATRandomAliasesResolveFixedNames(t *testing.T) {
	v := makeFixture(16)
	root := append([]byte(nil), v.data[v.root:v.root+32]...)
	first := append([]byte(nil), v.data[v.image:v.image+32]...)
	second := append([]byte(nil), v.data[v.image+32:v.image+64]...)
	for i := 0; i < 512; i++ {
		v.data[v.root+i] = 0
		v.data[v.image+i] = 0
	}
	putLongEntry(v.data, v.root, "image", "PCAFUI~2   ", root)
	n := putLongEntry(v.data, v.image, "adsp.mdt", "MDTZXY~2MDT", first)
	putLongEntry(v.data, n, "adsp_dtb.mdt", "DTBZXY~2MDT", second)
	f, e := OpenFATForensic(v.read, uint64(len(v.data)))
	if e != nil {
		t.Fatal(e)
	}
	r, e := f.Directory(0, true)
	if e != nil || len(r) != 1 || r[0].Name != "image" || r[0].ShortName != "pcafui~2" {
		t.Fatalf("root: %+v %v", r, e)
	}
	d, e := f.Directory(r[0].Cluster, false)
	if e != nil || len(d) != 2 || d[0].Name != "adsp.mdt" || d[1].Name != "adsp_dtb.mdt" {
		t.Fatalf("files: %+v %v", d, e)
	}
	b, e := f.File(d[0])
	if e != nil || !bytes.Equal(b, []byte("primary-MDT!")) {
		t.Fatalf("data: %v", e)
	}
}
func TestVFATMultiEntryAndRefusals(t *testing.T) {
	for _, test := range []string{"valid", "checksum", "ordinal", "unicode", "padding"} {
		t.Run(test, func(t *testing.T) {
			v := makeFixture(16)
			sfn := append([]byte(nil), v.data[v.root:v.root+32]...)
			for i := 0; i < 512; i++ {
				v.data[v.root+i] = 0
			}
			putLongEntry(v.data, v.root, "long-directory-name", "LONGDI~2   ", sfn)
			switch test {
			case "checksum":
				v.data[v.root+13] ^= 1
			case "ordinal":
				v.data[v.root+32] = 2
			case "unicode":
				binary.LittleEndian.PutUint16(v.data[v.root+33:], 0xd800)
			case "padding":
				binary.LittleEndian.PutUint16(v.data[v.root+30:], 1)
			}
			f, e := OpenFAT(v.read, uint64(len(v.data)))
			if e != nil {
				t.Fatal(e)
			}
			r, e := f.Directory(0, true)
			if test == "valid" {
				if e != nil || len(r) != 1 || r[0].Name != "long-directory-name" {
					t.Fatalf("%+v %v", r, e)
				}
			} else if e == nil {
				t.Fatal("accepted malformed LFN")
			}
		})
	}
}

func makeFixture(bits int) fixture {
	sectors, reserved, fatSectors, rootEntries, clusters := 0, 1, 17, 128, 4090
	if bits == 32 {
		reserved = 32
		fatSectors = 512
		rootEntries = 0
		clusters = 65525
	}
	rootSectors := (rootEntries*32 + 511) / 512
	sectors = reserved + 2*fatSectors + rootSectors + clusters
	v := fixture{data: make([]byte, sectors*512), fat: reserved * 512, fatBytes: fatSectors * 512, bits: bits}
	b := v.data
	b[510] = 0x55
	b[511] = 0xaa
	binary.LittleEndian.PutUint16(b[11:], 512)
	b[13] = 1
	binary.LittleEndian.PutUint16(b[14:], uint16(reserved))
	b[16] = 2
	binary.LittleEndian.PutUint16(b[17:], uint16(rootEntries))
	binary.LittleEndian.PutUint32(b[32:], uint32(sectors))
	dataOffset := (reserved + 2*fatSectors + rootSectors) * 512
	v.root = (reserved + 2*fatSectors) * 512
	v.image = dataOffset
	v.file = dataOffset + 512
	if bits == 16 {
		binary.LittleEndian.PutUint16(b[22:], uint16(fatSectors))
		for _, c := range []int{0, 1, 2, 3, 4} {
			v.setFat(c, 0xffff)
		}
	} else {
		binary.LittleEndian.PutUint32(b[36:], uint32(fatSectors))
		binary.LittleEndian.PutUint32(b[44:], 2)
		v.root = dataOffset
		v.image = dataOffset + 512
		v.file = dataOffset + 1024
		for _, c := range []int{0, 1, 2, 3, 4, 5} {
			v.setFat(c, 0x0fffffff)
		}
	}
	imageCluster, fileCluster := uint32(2), uint32(3)
	if bits == 32 {
		imageCluster = 3
		fileCluster = 4
	}
	writeEntry := func(at int, name string, attr byte, cluster, size uint32) {
		copy(b[at:at+11], []byte(name))
		b[at+11] = attr
		binary.LittleEndian.PutUint16(b[at+26:], uint16(cluster))
		binary.LittleEndian.PutUint16(b[at+20:], uint16(cluster>>16))
		binary.LittleEndian.PutUint32(b[at+28:], size)
	}
	writeEntry(v.root, "IMAGE      ", 0x10, imageCluster, 0)
	writeEntry(v.image, "ADSP    MDT", 0x20, fileCluster, 12)
	writeEntry(v.image+32, "ADSP_DTBMDT", 0x20, fileCluster+1, 11)
	copy(b[v.file:], []byte("primary-MDT!"))
	copy(b[v.file+512:], []byte("dtb-header!"))
	return v
}
func (v fixture) setFat(cluster int, value uint32) {
	for n := 0; n < 2; n++ {
		off := v.fat + n*v.fatBytes + cluster*(v.bits/8)
		if v.bits == 16 {
			binary.LittleEndian.PutUint16(v.data[off:], uint16(value))
		} else {
			binary.LittleEndian.PutUint32(v.data[off:], value)
		}
	}
}
func (v fixture) read(off, n uint64) ([]byte, error) {
	if off > uint64(len(v.data)) || n > uint64(len(v.data))-off {
		return nil, fmt.Errorf("fixture range")
	}
	return append([]byte(nil), v.data[off:off+n]...), nil
}
func collect(v fixture) (*FAT, error) {
	f, e := OpenFAT(v.read, uint64(len(v.data)))
	if e != nil {
		return nil, e
	}
	r, e := f.Directory(0, true)
	if e != nil {
		return nil, e
	}
	if len(r) != 1 {
		return nil, fmt.Errorf("root")
	}
	d, e := f.Directory(r[0].Cluster, false)
	if e != nil {
		return nil, e
	}
	if len(d) != 2 {
		return nil, fmt.Errorf("image")
	}
	a, e := f.File(d[0])
	if e != nil {
		return nil, e
	}
	b, e := f.File(d[1])
	if e != nil {
		return nil, e
	}
	if !bytes.Equal(a, []byte("primary-MDT!")) || !bytes.Equal(b, []byte("dtb-header!")) {
		return nil, fmt.Errorf("payload")
	}
	return f, f.VerifyMetadata()
}
func TestActualFAT16And32Paths(t *testing.T) {
	for _, bits := range []int{16, 32} {
		t.Run(fmt.Sprint(bits), func(t *testing.T) {
			v := makeFixture(bits)
			f, e := collect(v)
			if e != nil || f.Bits != bits {
				t.Fatalf("%v", e)
			}
		})
	}
}
func TestRefuseMalformedGeometryAndChains(t *testing.T) {
	for _, name := range []string{"zero_cluster", "bad_total", "small_fat", "mirror_mismatch", "directory_cycle", "file_cycle", "bad_cluster", "large_file", "reserved_cluster"} {
		t.Run(name, func(t *testing.T) {
			v := makeFixture(16)
			switch name {
			case "zero_cluster":
				v.data[13] = 0
			case "bad_total":
				binary.LittleEndian.PutUint32(v.data[32:], 0xffffffff)
			case "small_fat":
				binary.LittleEndian.PutUint16(v.data[22:], 1)
			case "mirror_mismatch":
				v.data[v.fat+v.fatBytes+3] ^= 1
			case "directory_cycle":
				v.setFat(2, 2)
			case "file_cycle":
				v.setFat(3, 3)
				binary.LittleEndian.PutUint32(v.data[v.image+28:], 513)
			case "bad_cluster":
				binary.LittleEndian.PutUint16(v.data[v.image+26:], 0xffee)
			case "large_file":
				binary.LittleEndian.PutUint32(v.data[v.image+28:], 2<<20)
			case "reserved_cluster":
				v.setFat(3, 0xfff1)
			}
			if _, e := collect(v); e == nil {
				t.Fatal("accepted malformed filesystem")
			}
		})
	}
}
func TestRejectMetadataChange(t *testing.T) {
	v := makeFixture(16)
	f, e := collect(v)
	if e != nil {
		t.Fatal(e)
	}
	v.data[v.image+13] ^= 1
	if f.VerifyMetadata() == nil {
		t.Fatal("missed directory change")
	}
}
func TestFAT32ActiveCopyAndHighBits(t *testing.T) {
	v := makeFixture(32)
	binary.LittleEndian.PutUint16(v.data[40:], 0x81)
	v.data[v.fat+4] ^= 1
	f, e := collect(v)
	if e != nil || f.Bits != 32 {
		t.Fatalf("active copy: %v", e)
	}
}
func TestForensicOversizedBPBRetainsPhysicalBounds(t *testing.T) {
	v := makeFixture(16)
	binary.LittleEndian.PutUint32(v.data[32:], uint32(len(v.data)/512+100))
	if _, err := OpenFAT(v.read, uint64(len(v.data))); err == nil {
		t.Fatal("strict path accepted oversized volume")
	}
	var maxEnd uint64
	calls := 0
	read := func(off, n uint64) ([]byte, error) {
		calls++
		if off+n > maxEnd {
			maxEnd = off + n
		}
		return v.read(off, n)
	}
	f, err := OpenFATForensic(read, uint64(len(v.data)))
	if err != nil {
		t.Fatal(err)
	}
	if f.DeclaredBytes <= f.PhysicalBytes || f.LogicalClusters <= f.Clusters {
		t.Fatal("truncation not reported")
	}
	root, err := f.Directory(0, true)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := f.Directory(root[0].Cluster, false)
	if err != nil {
		t.Fatal(err)
	}
	data, err := f.File(entries[0])
	if err != nil || !bytes.Equal(data, []byte("primary-MDT!")) {
		t.Fatalf("backed file: %v", err)
	}
	ranges, err := f.Extents(entries[0])
	if err != nil || len(ranges) != 1 || ranges[0][1] != 12 {
		t.Fatalf("extents: %v", err)
	}
	bad := entries[0]
	bad.Cluster = f.Clusters + 2
	before := calls
	if _, err = f.File(bad); err == nil {
		t.Fatal("read a logical but unbacked cluster")
	}
	if _, err = f.Extents(bad); err == nil {
		t.Fatal("admitted unbacked extent")
	}
	if calls != before || maxEnd > uint64(len(v.data)) {
		t.Fatal("unbacked operation reached read callback")
	}
	if err = f.VerifyMetadata(); err != nil {
		t.Fatal(err)
	}
}
func TestForensicStillRequiresFullLogicalFAT(t *testing.T) {
	v := makeFixture(16)
	binary.LittleEndian.PutUint32(v.data[32:], uint32(len(v.data)/512+1000))
	if _, err := OpenFATForensic(v.read, uint64(len(v.data))); err == nil {
		t.Fatal("logical table capacity omitted")
	}
}
func TestExtentCycleRefused(t *testing.T) {
	v := makeFixture(16)
	f, err := OpenFAT(v.read, uint64(len(v.data)))
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint16(f.Table[6:], 3)
	if _, err = f.Extents(FATEntry{Name: "adsp.mdt", Cluster: 3, Size: 513}); err == nil {
		t.Fatal("extent cycle accepted")
	}
}
