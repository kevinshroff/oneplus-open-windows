package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
)

type ramRead func(uint64, uint32, string) []byte
type ceRing struct {
	Local          uint32 `json:"local_dword_index"`
	Cached         uint32 `json:"cached_remote_dword_index"`
	Shadow         uint32 `json:"actual_RAM_shadow"`
	Entry          uint32 `json:"entry_dwords"`
	NextDescriptor string `json:"next_descriptor_raw_hex,omitempty"`
}
type ceSnapshot struct {
	ResourceContext uint64
	ResourcePA      uint64
	ResourceBytes   uint64
	Static          []byte
	Context         uint64
	BAR             uint64
	Credits         uint32
	QueueDepth      uint32
	Destination     ceRing
	Status          ceRing
	Summary         map[string]any
}
type ceHardware struct {
	Qualified     bool   `json:"qualified"`
	Selector      uint32 `json:"selector"`
	DestinationHP uint32 `json:"destination_HP"`
	DestinationTP uint32 `json:"destination_TP"`
	StatusHP      uint32 `json:"status_HP"`
	StatusTP      uint32 `json:"status_TP"`
	Refusal       string `json:"refusal,omitempty"`
}

func validIndex(v, entry uint32) bool { return entry > 0 && v < 64*entry && v%entry == 0 }
func captureCE(q uint64, read ramRead, emit func(map[string]any)) ceSnapshot {
	var all []byte
	field := func(a uint64, n uint32, label string) []byte {
		b := read(a, n, label)
		all = append(all, b...)
		return b
	}
	chain := func(a uint64, label string) uint64 {
		require(a&7 == 0, "Unaligned source pointer field")
		v := binary.LittleEndian.Uint64(field(a, 8, label))
		require(validSpan(v, 8) && v&7 == 0, "Unsafe source-owned pointer")
		return v
	}
	d := chain(q+0x396c20, "global_owner")
	a := chain(d+0x10, "owner_10")
	b := chain(a+0x10, "owner_10_10")
	context := chain(b+0xc8, "context")
	wmi := chain(context+0x37f38, "WMI")
	require(binary.LittleEndian.Uint32(field(wmi+0x10, 4, "WMI_endpoint")) == 2, "Actual EP2 required")
	htc := chain(wmi+0x1420, "HTC")
	hif := chain(htc, "HIF")
	hal := chain(hif+0x440, "HAL")
	require(chain(hal, "HAL_HIF_self") == hif, "HAL/HIF self")
	osdev := chain(hif+0x118, "HIF_osdev")
	require(chain(osdev+0x1cb0, "osdev_context") == context, "Source context ownership")
	bar := chain(hif+0x18, "HIF_BAR")
	require(bar&0xfff == 0 && chain(hal+0x10, "HAL_BAR") == bar, "HIF/HAL BAR")
	mhi := chain(context+0x38d18, "MHI")
	require(chain(mhi+0x7800, "MHI_BAR") == bar, "MHI BAR")
	resourceContext := chain(q+0x3968d0, "WDF_resource_context")
	require(chain(resourceContext+0x430, "resource_context_current_adapter") == d, "WDF resource context/adapter ownership")
	resourceRecord := field(b+8, 16, "current_resource_record_VA_length")
	resourceVA := binary.LittleEndian.Uint64(resourceRecord)
	resourceBytes := uint64(binary.LittleEndian.Uint32(resourceRecord[8:]))
	resourcePA := binary.LittleEndian.Uint64(field(b+0x28, 8, "current_resource_record_PA"))
	require(resourceVA == bar && resourcePA == 0x63e00000 && resourceBytes >= 0x85410 && resourceBytes <= 0x1000000, "Actual source-owned resource record and bounded mapping required")
	cPA := binary.LittleEndian.Uint64(field(resourceContext+0x248, 8, "retained_translated_CSR_PA"))
	cMapping := field(resourceContext+0x350, 16, "retained_CSR_VA_length")
	require(cPA == resourcePA && binary.LittleEndian.Uint64(cMapping) == resourceVA && uint64(binary.LittleEndian.Uint32(cMapping[8:])) == resourceBytes, "WDF/resource record propagation equality")
	count := binary.LittleEndian.Uint32(field(resourceContext+0x238, 4, "CM_resource_count"))
	require(count >= 1 && count <= 14, "Bounded retained raw/translated CM arrays")
	memoryCount := 0
	for i := uint32(0); i < count; i++ {
		raw := field(resourceContext+8+uint64(i)*20, 20, "raw_CM_descriptor")
		translated := field(resourceContext+0x120+uint64(i)*20, 20, "translated_CM_descriptor")
		if translated[0] == 3 {
			memoryCount++
			require(raw[0] == 3 && binary.LittleEndian.Uint64(translated[4:]) == resourcePA && uint64(binary.LittleEndian.Uint32(translated[12:])) == resourceBytes, "Actual translated CM Memory descriptor must match current resource record")
		}
	}
	require(memoryCount == 1, "Exactly one retained translated Memory grant required")

	require(chain(hal+0x7758, "selected_HAL_table") == q+0x3951d0, "Exact WCN7850 selected table")
	expected, _ := hex.DecodeString("380000000c0002000010b8010014b801002000200000000000000000ffff000000000000500000000c0004005810b8010814b801002000200000000001000000ffff000000000000")
	var cfg []byte
	for off := uint32(0); off < 72; {
		n := uint32(32)
		if 72-off < n {
			n = 72 - off
		}
		cfg = append(cfg, field(q+0x395314+uint64(off), n, "CE_config")...)
		off += n
	}
	require(bytes.Equal(cfg, expected), "Exact CE configuration bytes")
	mode := field(hal+0x773c, 24, "HAL_window_mode_cache")
	require(binary.LittleEndian.Uint32(mode) == 1 && binary.LittleEndian.Uint32(mode[20:]) == 0, "Reviewed dynamic-window HAL backend")
	ce := chain(hif+0x138, "CE2")
	id := field(ce, 16, "CE2_identity")
	require(binary.LittleEndian.Uint64(id) == hif && binary.LittleEndian.Uint32(id[8:]) == 2, "CE2 self/id")
	shadows := field(hal+0x7660, 16, "shadow_allocation")
	shadowVA := binary.LittleEndian.Uint64(shadows)
	require(validSpan(shadowVA, 4) && shadowVA&3 == 0 && shadowVA+688 > shadowVA, "Shadow base")
	ep := htc + 8 + 2*0x108
	credits := binary.LittleEndian.Uint32(field(ep+0xe8, 4, "EP2_credits"))
	queue := binary.LittleEndian.Uint32(field(ep+0x78, 4, "EP2_queue_depth"))
	policy := field(ep+0xec, 12, "EP2_credit_size_threshold_flow")
	require(binary.LittleEndian.Uint32(policy) > 0 && binary.LittleEndian.Uint32(policy[8:]) == 1, "Flow-controlled EP2 with valid credit size")
	snap := ceSnapshot{ResourceContext: resourceContext, ResourcePA: resourcePA, ResourceBytes: resourceBytes, Context: context, BAR: bar, Credits: credits, QueueDepth: queue}
	for _, r := range []struct {
		name   string
		off    uint64
		id     byte
		entry  uint32
		r0, r2 uint64
	}{{"destination", 0x18, 58, 2, 0x1b85000, 0x1b85400}, {"status", 0x20, 82, 4, 0x1b85058, 0x1b85408}} {
		ring := chain(ce+r.off, r.name+"_ring")
		shape := field(ring, 16, r.name+"_shape")
		require(binary.LittleEndian.Uint32(shape) == 64 && binary.LittleEndian.Uint32(shape[4:]) == 63, "64-entry source geometry")
		backing := field(ring+0x28, 16, r.name+"_RAM_DMA")
		cpu := binary.LittleEndian.Uint64(backing)
		require(validSpan(cpu, 16) && cpu&3 == 0 && validSpan(cpu+uint64(64*r.entry*4)-16, 16), "CPU ring allocation bounds")
		srng := chain(ring+0x48, r.name+"_SRNG")
		sid := field(srng, 2, r.name+"_SRNG_identity")
		require(sid[0] == r.id && sid[1] == 1 && srng == hal+0x20+uint64(r.id)*0xb0, "HAL/SRNG identity")
		geometry := field(srng+0x18, 16, r.name+"_SRNG_geometry")
		require(binary.LittleEndian.Uint32(geometry) == 64 && binary.LittleEndian.Uint32(geometry[4:]) == 64*r.entry && binary.LittleEndian.Uint32(geometry[8:]) == 64*r.entry-1 && binary.LittleEndian.Uint32(geometry[12:]) == r.entry, "SRNG geometry")
		regs := field(srng+0x50, 16, r.name+"_register_values_only")
		require(binary.LittleEndian.Uint64(regs) == bar+r.r0 && binary.LittleEndian.Uint64(regs[8:]) == bar+r.r2, "Source register block relation")
		remote := chain(srng+0x70, r.name+"_shadow_pointer")
		require(remote == shadowVA+uint64(r.id)*4 && remote+4 <= shadowVA+688, "Source shadow allocation relation")
		indices := field(srng+0x64, 32, r.name+"_indices")
		direction := uint32(0)
		if r.id == 82 {
			direction = 1
		}
		require(binary.LittleEndian.Uint32(indices) == direction, "SRNG direction")
		v := ceRing{Local: binary.LittleEndian.Uint32(indices[4:]), Cached: binary.LittleEndian.Uint32(indices[20:]), Entry: r.entry}
		// Device-updated words/descriptors are excluded from static-equality admission.
		v.Shadow = binary.LittleEndian.Uint32(read(remote, 4, r.name+"_actual_shadow"))
		require(validIndex(v.Local, r.entry) && validIndex(v.Cached, r.entry) && validIndex(v.Shadow, r.entry), "Aligned bounded dword indices required")
		if r.name == "status" {
			v.NextDescriptor = hex.EncodeToString(read(cpu+uint64(v.Local)*4, 16, "status_next_descriptor"))
			snap.Status = v
		} else {
			snap.Destination = v
		}
	}
	snap.Static = all
	snap.Summary = map[string]any{"destination": snap.Destination, "status": snap.Status, "EP2_credits": credits, "EP2_queue_depth": queue, "context": address(context), "BAR_virtual": address(bar)}
	emit(map[string]any{"phase": "source_CE2_RAM_snapshot", "snapshot": snap.Summary, "static_bytes": len(all), "target_writes": 0})
	return snap
}
func readCEHardware(s ceSnapshot, read ramRead, emit func(map[string]any)) *ceHardware {
	out := &ceHardware{Selector: binary.LittleEndian.Uint32(read(s.BAR+0x310c, 4, "MMIO_selector_before"))}
	if out.Selector != 0x40000037 {
		out.Refusal = "existing_window_not37_no_window_write"
		emit(map[string]any{"phase": "CE_hardware_unavailable", "selector": out.Selector, "window_writes": 0})
		return out
	}
	raw := read(s.BAR+0x85400, 16, "MMIO_CE2_HP_TP")
	after := binary.LittleEndian.Uint32(read(s.BAR+0x310c, 4, "MMIO_selector_after"))
	require(after == out.Selector, "Window changed; no qualified hardware indices")
	out.DestinationHP = binary.LittleEndian.Uint32(raw)
	out.DestinationTP = binary.LittleEndian.Uint32(raw[4:])
	out.StatusHP = binary.LittleEndian.Uint32(raw[8:])
	out.StatusTP = binary.LittleEndian.Uint32(raw[12:])
	require(validIndex(out.DestinationHP, 2) && validIndex(out.DestinationTP, 2) && validIndex(out.StatusHP, 4) && validIndex(out.StatusTP, 4), "Bounded hardware indices, no allones")
	out.Qualified = true
	return out
}

// Independent current debugger VA->PA translations, not static expected BAR assumptions.
func qualifyBARTranslations(s ceSnapshot, hardware bool, translate func(uint64, uint64, string)) {
	require(s.ResourcePA == 0x63e00000 && s.ResourceBytes >= 0x85410 && s.ResourceBytes <= 0x1000000, "Runtime resource contract")
	translate(s.BAR, s.ResourcePA, "mapping_start")
	translate(s.BAR+s.ResourceBytes-1, s.ResourcePA+s.ResourceBytes-1, "mapping_last_byte")
	for _, off := range []uint64{0x28, 0x2b, 0x48, 0x4b, 0x128, 0x12b, 0x12c, 0x12f, 0x130, 0x133, 0x134, 0x137, 0x138, 0x13b, 0x13c, 0x13f} {
		translate(s.BAR+off, s.ResourcePA+off, "fixed_fault_read_endpoint")
	}
	if hardware {
		for _, off := range []uint64{0x310c, 0x310f, 0x85400, 0x8540f} {
			translate(s.BAR+off, s.ResourcePA+off, "optional_CE_read_endpoint")
		}
	}
}
