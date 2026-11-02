// SPDX-License-Identifier: MIT
// Exact hardware ABI decoder; contains no native calls.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const magic uint64 = 0x314f52463835474f
const registerCount = 50

type Status struct {
	Size           uint32 `json:"size"`
	Version        uint32 `json:"version"`
	Magic          string `json:"magic"`
	KernelBuild    uint32 `json:"kernel_build"`
	Processors     uint32 `json:"processors"`
	IRQL           uint32 `json:"irql"`
	FirmwareBytes  uint32 `json:"firmware_bytes"`
	FirmwareMatch  uint32 `json:"firmware_match"`
	RegisterCount  uint32 `json:"register_count"`
	FirmwareStatus string `json:"firmware_status"`
	MapCalls       uint32 `json:"map_calls"`
	Sequence       uint64 `json:"sequence"`
	InterruptTime  uint64 `json:"interrupt_time"`
	BuildID        string `json:"build_id"`
}

func parseHardwareStatus(b []byte) (Status, error) {
	if len(b) < 80 {
		return Status{}, errors.New("short status")
	}
	u := func(i int) uint32 { return binary.LittleEndian.Uint32(b[i:]) }
	q := func(i int) uint64 { return binary.LittleEndian.Uint64(b[i:]) }
	s := Status{u(0), u(4), fmt.Sprintf("0x%x", q(8)), u(16), u(20), u(24), u(28), u(32), u(36), fmt.Sprintf("0x%x", u(40)), u(44), q(48), q(56), strings.TrimRight(string(b[64:80]), "\x00")}
	if s.Size != 80 || s.Version != 1 || q(8) != magic || s.BuildID != "G58-livehw1" || s.RegisterCount != uint32(registerCount) {
		return s, errors.New("driver ABI/build differs")
	}
	return s, nil
}
func checkHardwareStatus(s Status) error {
	if s.KernelBuild != 26100 || s.Processors != 8 || s.IRQL != 0 || s.FirmwareMatch != 1 || s.FirmwareBytes != 576 || s.FirmwareStatus != "0x0" {
		return fmt.Errorf("phone/firmware guard: %+v", s)
	}
	return nil
}
func decodePMIC(b []byte) (map[string]any, error) {
	if len(b) != 1728 {
		return nil, errors.New("hardware response size differs")
	}
	s, e := parseHardwareStatus(b)
	if e != nil {
		return nil, e
	}
	if e = checkHardwareStatus(s); e != nil {
		return nil, e
	}
	u := func(i int) uint32 { return binary.LittleEndian.Uint32(b[i:]) }
	q := func(i int) uint64 { return binary.LittleEndian.Uint64(b[i:]) }
	count := u(160)
	if count > 128 {
		return nil, errors.New("PMIC trace count exceeds fixed buffer")
	}
	trace := make([]map[string]any, 0, count)
	for i := uint32(0); i < count; i++ {
		at := 164 + int(i)*12
		trace = append(trace, map[string]any{"kind": u(at), "address": fmt.Sprintf("0x%x", u(at+4)), "value": u(at + 8)})
	}
	bytesAt := func(start, end int) []uint32 {
		r := make([]uint32, end-start)
		for i, v := range b[start:end] {
			r[i] = uint32(v)
		}
		return r
	}
	completion := make([]uint32, 5)
	for i := 0; i < 5; i++ {
		completion[i] = u(104 + i*4)
	}
	r := map[string]any{"status": s, "operation_code": u(80), "stage": u(84), "register_reads": u(88), "observer_write_attempts": u(92), "polls": u(96), "observer_READ_commands": u(100), "completion": completion, "revision": bytesAt(124, 132), "anchor": bytesAt(132, 140), "identity": bytesAt(140, 148), "pmic_status_raw": uint32(b[148]), "configuration": bytesAt(149, 157), "trace": trace, "fixed_registers_unchanged": u(1700), "attempt": u(1704), "elapsed_ticks": q(1712), "counter_frequency": q(1720)}
	return r, nil
}
func decodePower(b []byte) (map[string]any, error) {
	if len(b) != 959896 {
		return nil, errors.New("hardware response size differs")
	}
	status, e := parseHardwareStatus(b)
	if e != nil {
		return nil, e
	}
	if e = checkHardwareStatus(status); e != nil {
		return nil, e
	}
	u := func(i int) uint32 { return binary.LittleEndian.Uint32(b[i:]) }
	q := func(i int) uint64 { return binary.LittleEndian.Uint64(b[i:]) }
	vector := func(at, count int) []uint32 {
		v := make([]uint32, count)
		for i := range v {
			v[i] = u(at + i*4)
		}
		return v
	}
	bytesAt := func(at, count int) []uint32 {
		v := make([]uint32, count)
		for i := range v {
			v[i] = uint32(b[at+i])
		}
		return v
	}
	trace := func(at, count, limit int) ([]map[string]any, error) {
		if count > limit {
			return nil, errors.New("trace exceeds fixed buffer")
		}
		v := make([]map[string]any, 0, count)
		for i := 0; i < count; i++ {
			z := at + i*12
			v = append(v, map[string]any{"kind": u(z), "address": fmt.Sprintf("0x%x", u(z+4)), "value": u(z + 8)})
		}
		return v, nil
	}
	txcount, pmcount := u(96), u(100)
	if txcount > 9 || pmcount > 3 {
		return nil, errors.New("power count exceeds ABI")
	}
	tx := make([]map[string]any, 0, txcount)
	for i := uint32(0); i < txcount; i++ {
		at := 164 + int(i)*3264
		t, e := trace(at+192, int(u(at+24)), 256)
		if e != nil {
			return nil, e
		}
		tx = append(tx, map[string]any{"operation_code": u(at), "restore_error": u(at + 4), "restored": u(at + 8), "stage": u(at + 12), "register_reads": u(at + 16), "register_write_attempts": u(at + 20), "request_address": fmt.Sprintf("0x%x", u(at+28)), "request_data": u(at + 32), "message_id": u(at + 36), "completion": u(at + 40), "response": u(at + 44), "trigger_attempted": u(at + 48), "mutated": u(at + 52), "before": vector(at+56, 17), "after": vector(at+124, 17), "trace": t})
	}
	pm := make([]map[string]any, 0, pmcount)
	for i := uint32(0); i < pmcount; i++ {
		at := 29540 + int(i)*1620
		t, e := trace(at+84, int(u(at+80)), 128)
		if e != nil {
			return nil, e
		}
		pm = append(pm, map[string]any{"operation_code": u(at), "stage": u(at + 4), "register_reads": u(at + 8), "observer_write_attempts": u(at + 12), "polls": u(at + 16), "observer_READ_commands": u(at + 20), "completion": vector(at+24, 5), "revision": bytesAt(at+44, 8), "anchor": bytesAt(at+52, 8), "identity": bytesAt(at+60, 8), "pmic_status_raw": uint32(b[at+68]), "configuration": bytesAt(at+69, 8), "trace": t})
	}

	st, e := trace(34784, int(u(34496)), 128)
	if e != nil {
		return nil, e
	}
	et, e := trace(36932, int(u(36344)), 384)
	if e != nil {
		return nil, e
	}
	tt, e := trace(42356, int(u(41564)), 65536)
	if e != nil {
		return nil, e
	}
	engine := map[string]any{"operation_code": u(36320), "restore_error": u(36324), "restored": u(36328), "stage": u(36332), "register_reads": u(36336), "register_write_attempts": u(36340), "dirty": u(36348), "before": vector(36352, 24), "during": vector(36448, 24), "after": vector(36544, 24), "DFS_before": vector(36640, 25), "DFS_after": vector(36740, 25), "clock_index": u(36840), "source_hz": u(36844), "bus_hz": u(36848), "guards_before": vector(36852, 10), "guards_after": vector(36892, 10), "trace": et}
	spi := map[string]any{"operation_code": u(34472), "restore_error": u(34476), "restored": u(34480), "stage": u(34484), "register_reads": u(34488), "register_write_attempts": u(34492), "dirty_pins": u(34500), "vote_dirty": u(34504), "clock_before": vector(34508, 6), "clock_after": vector(34532, 6), "pins_before": vector(34556, 16), "pins_during": vector(34620, 16), "pins_after": vector(34684, 16), "identity": vector(34748, 8), "enabled_vote": u(34780), "trace": st, "engine": engine}
	at := 828788
	pt, e := trace(at+84, int(u(at+80)), 128)
	if e != nil {
		return nil, e
	}
	poweredPmic := map[string]any{"operation_code": u(at), "stage": u(at + 4), "register_reads": u(at + 8), "observer_write_attempts": u(at + 12), "polls": u(at + 16), "observer_READ_commands": u(at + 20), "completion": vector(at+24, 5), "revision": bytesAt(at+44, 8), "anchor": bytesAt(at+52, 8), "identity": bytesAt(at+60, 8), "pmic_status_raw": uint32(b[at+68]), "configuration": bytesAt(at+69, 8), "trace": pt}
	frame := func(at int) map[string]any {
		return map[string]any{"attempted": u(at), "transport_ok": u(at + 4), "contract_verified": u(at + 8), "header_present": u(at + 12), "header_checksum_valid": u(at + 16), "body_complete": u(at + 20), "body_checksum_valid": u(at + 24), "event_flags": u(at + 28), "point_count": u(at + 32), "point_type": u(at + 36), "start_code": int32(u(at + 40)), "step_code": int32(u(at + 44)), "state": u(at + 48), "steps": u(at + 52), "tx_done": u(at + 56), "rx_done": u(at + 60), "cancel_sent": u(at + 64), "abort_sent": u(at + 68), "wire_TX": bytesAt(at+72, 36), "wire_RX": bytesAt(at+108, 36)}
	}
	settleCount := u(830872)
	if settleCount > 6 {
		return nil, errors.New("IRQ settle count exceeds ABI")
	}
	settle := make([]map[string]any, 0, settleCount)
	for i := uint32(0); i < settleCount; i++ {
		at := 830876 + int(i)*20
		settle = append(settle, map[string]any{"elapsed_us": u(at), "control": u(at + 4), "input": u(at + 8), "IRQ_config": u(at + 12), "IRQ_status": u(at + 16)})
	}
	cycles, wireCount := u(831004), u(881456)
	limit := u(831000)
	if limit > 100 || cycles > limit || wireCount > 4*limit || u(831044) > limit || u(831048) > u(831044) || u(831052) > 4*limit {
		return nil, errors.New("poll counts exceed ABI")
	}
	wires := make([]map[string]any, 0, wireCount)
	for i := uint32(0); i < wireCount; i++ {
		at := 881460 + int(i)*196
		wires = append(wires, map[string]any{"kind": u(at), "address": fmt.Sprintf("0x%x", u(at+4)), "payload": u(at + 8), "attempted": u(at + 12), "transport_ok": u(at + 16), "start_code": int32(u(at + 20)), "step_code": int32(u(at + 24)), "state": u(at + 28), "steps": u(at + 32), "tx_done": u(at + 36), "rx_done": u(at + 40), "cancel_sent": u(at + 44), "abort_sent": u(at + 48), "wire_TX": bytesAt(at+52, 72), "wire_RX": bytesAt(at+124, 72)})
	}
	records := make([]map[string]any, 0, cycles)
	for i := uint32(0); i < cycles; i++ {
		at := 831056 + int(i)*504
		f := at + 212
		count := u(f + 12)
		kind := u(f)
		if u(at) > 90 || u(at+88) > 1 || u(at+92) > 26 || u(at+20) > 15 || (kind == 3 && count > 10) {
			return nil, errors.New("poll record exceeds ABI")
		}
		contacts := make([]map[string]any, 0)
		if kind == 3 {
			for n := uint32(0); n < count; n++ {
				c := f + 52 + int(n)*24
				contacts = append(contacts, map[string]any{"Id": u(c), "X": u(c + 4), "Y": u(c + 8), "Major": u(c + 12), "Minor": u(c + 16), "Type": u(c + 20)})
			}
		}
		irq := make([]map[string]any, 4)
		for k := 0; k < 4; k++ {
			z := at + 24 + k*16
			irq[k] = map[string]any{"control": u(z), "input": u(z + 4), "config": u(z + 8), "status": u(z + 12)}
		}
		records = append(records, map[string]any{"irq_mask": u(at + 20), "irq_samples": irq, "header_retry": u(at + 88), "first_read_bytes": u(at + 92), "first_raw": bytesAt(at+96, int(u(at+92))), "read_bytes": u(at), "tail_read": u(at + 4), "clear_attempted": u(at + 8), "clear_completed": u(at + 12), "elapsed_us": u(at + 16), "raw_bytes": bytesAt(at+122, 90), "kind": kind, "error": u(f + 4), "flags": u(f + 8), "point_count": count, "point_type": u(f + 16), "header_checked": u(f + 20), "header_valid": u(f + 24), "body_checked": u(f + 28), "body_valid": u(f + 32), "meaningful_bytes": u(f + 36), "tail_bytes": u(f + 40), "contact_mask": u(f + 44), "within_provisional_axes": u(f + 48), "contacts": contacts})
	}
	poll := map[string]any{"operation_code": u(830996), "limit": u(831000), "cycles": cycles, "read_attempts": u(831008), "tail_reads": u(831012), "clear_attempts": u(831016), "clear_completed": u(831020), "idle_records": u(831024), "contact_records": u(831028), "request_records": u(831032), "bus_quiescent": u(831036), "elapsed_us": u(831040), "header_retries": u(831044), "headers_recovered": u(831048), "irq_read_attempts": u(831052), "records": records, "wire_count": wireCount, "wires": wires}
	touch := map[string]any{"operation_code": u(41540), "restore_error": u(41544), "restored": u(41548), "stage": u(41552), "register_reads": u(41556), "register_write_attempts": u(41560), "analog_dirty": u(41568), "reset_dirty": u(41572), "command_attempted": u(41576), "transport_ok": u(41580), "identity_ok": u(41584), "bus_quiescent": u(41588), "lengths_saved": u(41592), "lengths_restored": u(41596), "lengths_dirty": u(41600), "GPIO_IRQ_acknowledged": u(41604), "start_code": int32(u(41608)), "step_code": int32(u(41612)), "state": u(41616), "steps": u(41620), "tx_done": u(41624), "rx_done": u(41628), "cancel_sent": u(41632), "abort_sent": u(41636), "pins_before": vector(41640, 12), "pins_on": vector(41688, 12), "pins_after": vector(41736, 12), "lengths_before": vector(41784, 2), "lengths_after": vector(41792, 2), "command_history": vector(41800, 2), "wait_counts": vector(41808, 5), "wire_TX": bytesAt(41828, 252), "wire_RX": bytesAt(42080, 252), "ROM_PID": strings.TrimRight(string(b[42332:42338]), "\x00"), "patch_PID": strings.TrimRight(string(b[42339:42347]), "\x00"), "ROM_VID": bytesAt(42348, 3), "patch_VID": bytesAt(42351, 4), "sensor_id": uint32(b[42355]), "trace": tt, "powered_PMIC": poweredPmic, "info_length": u(830408), "header_length_valid": u(830412), "full_IC_info_checksum_verified": u(830416) == 1, "read_address": "0x10070", "payload_bytes": 242, "report": frame(830420), "ack": frame(830564), "post_report": frame(830708), "IRQ_sample_mask": u(830852), "IRQ_before": vector(830856, 2), "IRQ_after": vector(830864, 2), "settle_sample_count": settleCount, "settle_samples": settle, "poll": poll}
	return map[string]any{"status": status, "operation_code": u(80), "restore_error": u(84), "restored": u(88), "stage": u(92), "transaction_count": txcount, "pmic_count": pmcount, "enable_attempted": u(104), "release_attempted": u(108), "preflight_verified": u(112), "on_verified": u(116), "off_verified": u(120), "RSC_uncertain": u(124), "observer_uncertain": u(128), "source_status_baseline": u(132), "client_before": vector(136, 3), "client_on": u(148), "client_after": vector(152, 3), "transactions": tx, "PMIC": pm, "guards_before": vector(34400, 8), "guards_after": vector(34432, 8), "waits_1ms": u(34464), "waits_10ms": u(34468), "fixed_registers_unchanged": u(959868), "attempt": u(959872), "elapsed_ticks": q(959880), "counter_frequency": q(959888), "spi": spi, "touch": touch, "powered_hook_called": u(959860), "safe_release": u(959864)}, nil
}
