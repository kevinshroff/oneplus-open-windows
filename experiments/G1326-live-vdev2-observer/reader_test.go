package main

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func rejects(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected fail-closed rejection")
		}
	}()
	f()
}
func quiet(map[string]any) {}

// Synthetic CPU-model vector derived from guard predicates, not a hardware capture.
func TestActiveGuardModel(t *testing.T) {
	v := make([]uint32, 20)
	v[1] = 1 << 22
	v[2] = 0x3f
	v[4] = 0x80000000
	v[5] = 0x10000
	v[11] = 0x80000000
	v[12] = 0x10000
	v[14] = 0x200
	v[15] = 3
	v[16] = 0x200
	v[17] = 3
	v[19] = 1
	if !activeReady(v) {
		t.Fatal("model satisfying source predicates refused")
	}
	for _, i := range []int{0, 4, 11, 14, 16} {
		bad := append([]uint32{}, v...)
		bad[i] = 0xffffffff
		if activeReady(bad) {
			t.Fatal("unsafe guard accepted", i)
		}
	}
	if !equalWords(v, append([]uint32{}, v...)) {
		t.Fatal("stable vector differs")
	}
	flipped := append([]uint32{}, v...)
	flipped[19] ^= 1
	if !equalWords(v, flipped) {
		t.Fatal("GPIO83 observation-only input change wrongly rejected")
	}
}

func syntheticLedger(phase string) (proof, actionLedger, time.Time) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	one := uint32(1)
	zero := uint32(0)
	p := proof{Phase: phase, BootID: 166, Session: strings.Repeat("1", 32), Image: strings.Repeat("2", 64), Evidence: map[string]string{}}
	l := actionLedger{Schema: "wifi-live-vdev2-action-ledger/1", Phase: phase, BootID: 166, Session: p.Session, Image: p.Image, Created: now.Format(time.RFC3339Nano), NativeCallKnowledge: "NOT_OBSERVED_AT_STOP", ScanCallKnowledge: "NOT_OBSERVED_AT_STOP", RootForceCalls: &zero, RootNativeDiagnosticCalls: &zero, RootResetCalls: &zero, RootStatusClearCalls: &zero, RootWindowWrites: &zero, NoUnload: true, NoGPU: true, Evidence: map[string]string{}}
	keys := []string{"context", "current_tables", "loaded_owner", "loaded_original_driver", "accepted_boot_receipt", "normal_boot_admission", "native_init_selection", "boundary_source"}
	switch phase {
	case "ARM_LIVE_VDEV2":
		p.LoadHoldQualified = true
		keys = append(keys, "owned_load_stop")
	case "PRE_LIVE_VDEV2":
		p.BoundaryQualified = true
		keys = append(keys, "source_resource_origin_contract", "arm_marker", "owned_boundary_stop")
	case "POST_STALL":
		l.NativeCallKnowledge = "ACTUAL_COMPLETED_OUTCOME"
		l.ScanCallKnowledge = "ACTUAL_COMPLETED_OUTCOME"
		l.NativeInitCalls = &one
		l.ExplicitScanCalls = &one
		l.InitOutcomeRecorded = true
		l.FailureBoundaryRecorded = true
		keys = append(keys, "source_resource_origin_contract", "native_init_outcome", "failed_scan_log", "pre_phase_result", "pre_phase_marker", "arm_marker")
	}
	for _, k := range keys {
		p.Evidence[k] = strings.Repeat("a", 64)
		l.Evidence[k] = p.Evidence[k]
	}
	p.Evidence["action_ledger"] = strings.Repeat("b", 64)
	return p, l, now
}
func TestPhaseAdmissionAndUnknownCounts(t *testing.T) {
	for _, phase := range []string{"ARM_LIVE_VDEV2", "PRE_LIVE_VDEV2", "POST_STALL"} {
		p, l, now := syntheticLedger(phase)
		validLedger(p, l, now)
	}
	p, l, now := syntheticLedger("PRE_LIVE_VDEV2")
	zero := uint32(0)
	l.NativeInitCalls = &zero
	rejects(t, func() { validLedger(p, l, now) }) // unknown is not zero
	p, l, now = syntheticLedger("PRE_LIVE_VDEV2")
	l.InitInProgress = true
	rejects(t, func() { validLedger(p, l, now) }) // do not infer API entered from load
	p, l, now = syntheticLedger("PRE_LIVE_VDEV2")
	l.InitOutcomeRecorded = true
	rejects(t, func() { validLedger(p, l, now) })
	p, l, now = syntheticLedger("POST_STALL")
	l.ExplicitScanCalls = nil
	rejects(t, func() { validLedger(p, l, now) })
	p, l, now = syntheticLedger("ARM_LIVE_VDEV2")
	l.RootWindowWrites = nil
	rejects(t, func() { validLedger(p, l, now) })
	p, l, now = syntheticLedger("PRE_LIVE_VDEV2")
	p.Phase = "PRE_HOST_INIT"
	rejects(t, func() { validLedger(p, l, now) })
	p, l, now = syntheticLedger("PRE_LIVE_VDEV2")
	delete(p.Evidence, "source_resource_origin_contract")
	rejects(t, func() { validLedger(p, l, now) })
}
func TestStrictJSON(t *testing.T) {
	var p proof
	rejects(t, func() { strictJSON([]byte(`{"not_a_field":true}`), &p) })
	rejects(t, func() { strictJSON([]byte(`{} {}`), &p) })
}
func syntheticRAM() (uint64, map[uint64]byte, ramRead) {
	q := uint64(0xfffff80000100000)
	m := map[uint64]byte{}
	put := func(a uint64, b []byte) {
		for i, v := range b {
			m[a+uint64(i)] = v
		}
	}
	u64 := func(a, v uint64) { b := make([]byte, 8); binary.LittleEndian.PutUint64(b, v); put(a, b) }
	u32 := func(a uint64, v uint32) { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); put(a, b) }
	zero := func(a uint64, n int) { put(a, make([]byte, n)) }
	k := func(n uint64) uint64 { return 0xfffff80000000000 + n*0x10000000 }
	d, a, b, ctx, c, wmi, htc, hif, hal, mhi, osdev, ce, shadow := k(1), k(2), k(3), k(4), k(5), k(6), k(7), k(8), k(9), k(10), k(11), k(12), k(13)
	bar := k(17)
	u64(q+0x396c20, d)
	u64(d+0x10, a)
	u64(a+0x10, b)
	u64(b+0xc8, ctx)
	u64(ctx+0x37f38, wmi)
	u32(wmi+0x10, 2)
	u64(wmi+0x1420, htc)
	u64(htc, hif)
	u64(hif+0x440, hal)
	u64(hal, hif)
	u64(hif+0x118, osdev)
	u64(osdev+0x1cb0, ctx)
	u64(hif+0x18, bar)
	u64(hal+0x10, bar)
	u64(ctx+0x38d18, mhi)
	u64(mhi+0x7800, bar)
	u64(hal+0x7758, q+0x3951d0)
	u64(q+0x3968d0, c)
	u64(c+0x430, d)
	zero(b+8, 16)
	u64(b+8, bar)
	u32(b+0x10, 0x200000)
	u64(b+0x28, 0x63e00000)
	u64(c+0x248, 0x63e00000)
	zero(c+0x350, 16)
	u64(c+0x350, bar)
	u32(c+0x358, 0x200000)
	u32(c+0x238, 2)
	for i := uint64(0); i < 2; i++ {
		for _, off := range []uint64{8, 0x120} {
			zero(c+off+i*20, 20)
			m[c+off+i*20] = 2
			if i == 0 {
				m[c+off] = 3
				u64(c+off+4, 0x63e00000)
				u32(c+off+12, 0x200000)
			}
		}
	}
	cfg, _ := hex.DecodeString("380000000c0002000010b8010014b801002000200000000000000000ffff000000000000500000000c0004005810b8010814b801002000200000000001000000ffff000000000000")
	put(q+0x395314, cfg)
	zero(hal+0x773c, 24)
	u32(hal+0x773c, 1)
	u64(hif+0x138, ce)
	zero(ce, 16)
	u64(ce, hif)
	u32(ce+8, 2)
	zero(hal+0x7660, 16)
	u64(hal+0x7660, shadow)
	ep := htc + 8 + 2*0x108
	u32(ep+0xe8, 1)
	u32(ep+0x78, 0)
	u32(ep+0xec, 2176)
	u32(ep+0xf0, 1)
	u32(ep+0xf4, 1)
	for _, r := range []struct {
		id                              byte
		off, ring, cpu, r0, r2          uint64
		entry, local, remote, direction uint32
	}{{58, 0x18, k(14), k(18), 0x1b85000, 0x1b85400, 2, 42, 12, 0}, {82, 0x20, k(15), k(19), 0x1b85058, 0x1b85408, 4, 44, 44, 1}} {
		u64(ce+r.off, r.ring)
		zero(r.ring, 16)
		u32(r.ring, 64)
		u32(r.ring+4, 63)
		zero(r.ring+0x28, 16)
		u64(r.ring+0x28, r.cpu)
		srng := hal + 0x20 + uint64(r.id)*0xb0
		u64(r.ring+0x48, srng)
		put(srng, []byte{r.id, 1})
		u32(srng+0x18, 64)
		u32(srng+0x1c, 64*r.entry)
		u32(srng+0x20, 64*r.entry-1)
		u32(srng+0x24, r.entry)
		u64(srng+0x50, bar+r.r0)
		u64(srng+0x58, bar+r.r2)
		zero(srng+0x64, 32)
		u32(srng+0x64, r.direction)
		u32(srng+0x68, r.local)
		u64(srng+0x70, shadow+uint64(r.id)*4)
		u32(srng+0x78, r.remote)
		u32(shadow+uint64(r.id)*4, r.remote)
		zero(r.cpu+uint64(r.local)*4, 16)
	}
	read := func(a uint64, n uint32, _ string) []byte {
		require(validSpan(a, n), "Unsafe test read")
		v := make([]byte, n)
		for i := range v {
			b, ok := m[a+uint64(i)]
			require(ok, "Missing/short synthetic read")
			v[i] = b
		}
		return v
	}
	return q, m, read
}
func TestCMResourceOriginAndIndices(t *testing.T) {
	q, m, read := syntheticRAM()
	s := captureCE(q, read, quiet)
	if s.ResourceBytes != 0x200000 || s.ResourcePA != 0x63e00000 || s.Credits != 1 || s.Status.Local != s.Status.Shadow {
		t.Fatal("source-owned binding differs")
	}
	// Rejected source CM owner, translated length, absent data, and invalid index; no MMIO involved.
	for _, kind := range []string{"owner", "length", "missing", "index"} {
		q, m, read = syntheticRAM()
		switch kind {
		case "owner":
			m[0xfffff80050000430] ^= 8
		case "length":
			m[0xfffff8005000012c] ^= 1
		case "missing":
			delete(m, q+0x3968d0)
		case "index":
			m[0xfffff800d0000148] = 0xff
		}
		rejects(t, func() { captureCE(q, read, quiet) })
	}
}
func TestTranslationAndNaturalWindowRefusal(t *testing.T) {
	q, _, read := syntheticRAM()
	s := captureCE(q, read, quiet)
	calls := 0
	qualifyBARTranslations(s, true, func(va, pa uint64, _ string) {
		calls++
		if pa != s.ResourcePA+va-s.BAR {
			t.Fatal("wrong actual translation endpoint")
		}
	})
	if calls != 22 {
		t.Fatal("fixed finite translation endpoints", calls)
	}
	reads := 0
	h := readCEHardware(s, func(a uint64, n uint32, _ string) []byte {
		reads++
		if a != s.BAR+0x310c || n != 4 {
			t.Fatal("read beyond unavailable natural selector")
		}
		return []byte{0x14, 0, 0, 0x40}
	}, quiet)
	if h.Qualified || reads != 1 {
		t.Fatal("wrong window was not safely refused")
	}
	if validIndex(0xffffffff, 4) || validIndex(3, 4) || !validIndex(252, 4) {
		t.Fatal("index bounds/alignment")
	}
}
