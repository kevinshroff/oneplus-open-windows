// SPDX-License-Identifier: MIT
// Exact hardware ABI decoder; contains no native calls.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const magic uint64 = 0x314f52463639474f
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
	if s.Size != 80 || s.Version != 1 || q(8) != magic || s.BuildID != "G96-livehw1" || s.RegisterCount != uint32(registerCount) {
		return s, errors.New("driver ABI/build differs")
	}
	return s, nil
}
func checkHardwareStatus(s Status) error {
	if s.KernelBuild != 26300 || s.Processors != 8 || s.IRQL != 0 || s.FirmwareMatch != 1 || s.FirmwareBytes != 576 || s.FirmwareStatus != "0x0" {
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
		trace = append(trace, map[string]any{"index": i, "kind": u(at), "address": fmt.Sprintf("0x%x", u(at+4)), "value": u(at + 8)})
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
	if len(b) != 969808 {
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
	txcount, pmcount := u(136), u(140)
	if txcount > 12 || pmcount > 3 {
		return nil, errors.New("power count exceeds ABI")
	}
	tx := make([]map[string]any, 0, txcount)
	for i := uint32(0); i < txcount; i++ {
		at := 360 + int(i)*3264
		t, e := trace(at+192, int(u(at+24)), 256)
		if e != nil {
			return nil, e
		}
		tx = append(tx, map[string]any{"operation_code": u(at), "restore_error": u(at + 4), "restored": u(at + 8), "stage": u(at + 12), "register_reads": u(at + 16), "register_write_attempts": u(at + 20), "request_address": fmt.Sprintf("0x%x", u(at+28)), "request_data": u(at + 32), "message_id": u(at + 36), "completion": u(at + 40), "response": u(at + 44), "trigger_attempted": u(at + 48), "mutated": u(at + 52), "before": vector(at+56, 17), "after": vector(at+124, 17), "trace": t})
	}
	pm := make([]map[string]any, 0, pmcount)
	for i := uint32(0); i < pmcount; i++ {
		at := 39528 + int(i)*1620
		t, e := trace(at+84, int(u(at+80)), 128)
		if e != nil {
			return nil, e
		}
		pm = append(pm, map[string]any{"operation_code": u(at), "stage": u(at + 4), "register_reads": u(at + 8), "observer_write_attempts": u(at + 12), "polls": u(at + 16), "observer_READ_commands": u(at + 20), "completion": vector(at+24, 5), "revision": bytesAt(at+44, 8), "anchor": bytesAt(at+52, 8), "identity": bytesAt(at+60, 8), "pmic_status_raw": uint32(b[at+68]), "configuration": bytesAt(at+69, 8), "trace": t})
	}

	st, e := trace(44700, int(u(44412)), 128)
	if e != nil {
		return nil, e
	}
	et, e := trace(46848, int(u(46260)), 384)
	if e != nil {
		return nil, e
	}
	traceTotal := u(51480)
	if traceTotal > 350000000 || u(51472) > 250000000 || u(51476) > 100000000 {
		return nil, errors.New("touch cumulative budget exceeded")
	}
	traceFirst := uint32(0)
	if traceTotal > 65536 {
		traceFirst = traceTotal - 65536
	}
	tt := make([]map[string]any, 0, traceTotal-traceFirst)
	for i := traceFirst; i < traceTotal; i++ {
		z := 52272 + int(i%65536)*12
		tt = append(tt, map[string]any{"index": i, "kind": u(z), "address": fmt.Sprintf("0x%x", u(z+4)), "value": u(z + 8)})
	}
	engine := map[string]any{"operation_code": u(46236), "restore_error": u(46240), "restored": u(46244), "stage": u(46248), "register_reads": u(46252), "register_write_attempts": u(46256), "dirty": u(46264), "before": vector(46268, 24), "during": vector(46364, 24), "after": vector(46460, 24), "DFS_before": vector(46556, 25), "DFS_after": vector(46656, 25), "clock_index": u(46756), "source_hz": u(46760), "bus_hz": u(46764), "guards_before": vector(46768, 10), "guards_after": vector(46808, 10), "trace": et}
	spi := map[string]any{"operation_code": u(44388), "restore_error": u(44392), "restored": u(44396), "stage": u(44400), "register_reads": u(44404), "register_write_attempts": u(44408), "dirty_pins": u(44416), "vote_dirty": u(44420), "clock_before": vector(44424, 6), "clock_after": vector(44448, 6), "pins_before": vector(44472, 16), "pins_during": vector(44536, 16), "pins_after": vector(44600, 16), "identity": vector(44664, 8), "enabled_vote": u(44696), "trace": st, "engine": engine}
	at := 838704
	pt, e := trace(at+84, int(u(at+80)), 128)
	if e != nil {
		return nil, e
	}
	poweredPmic := map[string]any{"operation_code": u(at), "stage": u(at + 4), "register_reads": u(at + 8), "observer_write_attempts": u(at + 12), "polls": u(at + 16), "observer_READ_commands": u(at + 20), "completion": vector(at+24, 5), "revision": bytesAt(at+44, 8), "anchor": bytesAt(at+52, 8), "identity": bytesAt(at+60, 8), "pmic_status_raw": uint32(b[at+68]), "configuration": bytesAt(at+69, 8), "trace": pt}
	frame := func(at int) map[string]any {
		return map[string]any{"attempted": u(at), "transport_ok": u(at + 4), "contract_verified": u(at + 8), "header_present": u(at + 12), "header_checksum_valid": u(at + 16), "body_complete": u(at + 20), "body_checksum_valid": u(at + 24), "event_flags": u(at + 28), "point_count": u(at + 32), "point_type": u(at + 36), "start_code": int32(u(at + 40)), "step_code": int32(u(at + 44)), "state": u(at + 48), "steps": u(at + 52), "tx_done": u(at + 56), "rx_done": u(at + 60), "cancel_sent": u(at + 64), "abort_sent": u(at + 68), "wire_TX": bytesAt(at+72, 36), "wire_RX": bytesAt(at+108, 36)}
	}
	settleCount := u(840788)
	if settleCount > 6 {
		return nil, errors.New("IRQ settle count exceeds ABI")
	}
	settle := make([]map[string]any, 0, settleCount)
	for i := uint32(0); i < settleCount; i++ {
		at := 840792 + int(i)*20
		settle = append(settle, map[string]any{"elapsed_us": u(at), "control": u(at + 4), "input": u(at + 8), "IRQ_config": u(at + 12), "IRQ_status": u(at + 16)})
	}
	cycles, wireCount := u(840920), u(891372)
	limit := u(840916)
	if limit > 300000 || cycles > limit || wireCount > 4*limit || u(840960) > limit || u(840964) > u(840960) || u(840968) > 4*limit || u(840924) > 3*limit || u(840928) > limit || u(840932) > limit || u(840936) > u(840932) || u(840940) > cycles || u(840944) > cycles || u(840948) > cycles || u(840940)+u(840944)+u(840948) > cycles {
		return nil, errors.New("poll counts exceed ABI")
	}
	wireFirst := uint32(0)
	if wireCount > 400 {
		wireFirst = wireCount - 400
	}
	wires := make([]map[string]any, 0, wireCount-wireFirst)
	for i := wireFirst; i < wireCount; i++ {
		at := 891376 + int(i%400)*196
		wires = append(wires, map[string]any{"index": i, "kind": u(at), "address": fmt.Sprintf("0x%x", u(at+4)), "payload": u(at + 8), "attempted": u(at + 12), "transport_ok": u(at + 16), "start_code": int32(u(at + 20)), "step_code": int32(u(at + 24)), "state": u(at + 28), "steps": u(at + 32), "tx_done": u(at + 36), "rx_done": u(at + 40), "cancel_sent": u(at + 44), "abort_sent": u(at + 48), "wire_TX": bytesAt(at+52, 72), "wire_RX": bytesAt(at+124, 72)})
	}
	recordFirst := uint32(0)
	if cycles > 100 {
		recordFirst = cycles - 100
	}
	records := make([]map[string]any, 0, cycles-recordFirst)
	for i := recordFirst; i < cycles; i++ {
		at := 840972 + int(i%100)*504
		f := at + 212
		count := u(f + 12)
		kind := u(f)
		if u(at) > 90 || u(at+88) > 2 || u(at+92) > 26 || u(at+20) > 15 || (kind == 3 && count > 10) {
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
		records = append(records, map[string]any{"cycle": i + 1, "irq_mask": u(at + 20), "irq_samples": irq, "read_retry_kind": u(at + 88), "first_read_bytes": u(at + 92), "first_raw": bytesAt(at+96, int(u(at+92))), "read_bytes": u(at), "tail_read": u(at + 4), "clear_attempted": u(at + 8), "clear_completed": u(at + 12), "elapsed_us": u(at + 16), "raw_bytes": bytesAt(at+122, 90), "kind": kind, "error": u(f + 4), "flags": u(f + 8), "point_count": count, "point_type": u(f + 16), "header_checked": u(f + 20), "header_valid": u(f + 24), "body_checked": u(f + 28), "body_valid": u(f + 32), "meaningful_bytes": u(f + 36), "tail_bytes": u(f + 40), "contact_mask": u(f + 44), "within_provisional_axes": u(f + 48), "contacts": contacts})
	}
	poll := map[string]any{"operation_code": u(840912), "limit": u(840916), "cycles": cycles, "read_attempts": u(840924), "tail_reads": u(840928), "clear_attempts": u(840932), "clear_completed": u(840936), "idle_records": u(840940), "contact_records": u(840944), "request_records": u(840948), "bus_quiescent": u(840952), "elapsed_us": u(840956), "read_retries": u(840960), "prefixes_recovered": u(840964), "irq_read_attempts": u(840968), "records": records, "record_first_cycle": recordFirst + 1, "record_capacity": 100, "wire_count": wireCount, "wire_first_index": wireFirst, "wire_capacity": 400, "wires": wires}
	touch := map[string]any{"operation_code": u(51456), "restore_error": u(51460), "restored": u(51464), "stage": u(51468), "register_reads": u(51472), "register_write_attempts": u(51476), "analog_dirty": u(51484), "reset_dirty": u(51488), "command_attempted": u(51492), "transport_ok": u(51496), "identity_ok": u(51500), "bus_quiescent": u(51504), "lengths_saved": u(51508), "lengths_restored": u(51512), "lengths_dirty": u(51516), "GPIO_IRQ_acknowledged": u(51520), "start_code": int32(u(51524)), "step_code": int32(u(51528)), "state": u(51532), "steps": u(51536), "tx_done": u(51540), "rx_done": u(51544), "cancel_sent": u(51548), "abort_sent": u(51552), "pins_before": vector(51556, 12), "pins_on": vector(51604, 12), "pins_after": vector(51652, 12), "lengths_before": vector(51700, 2), "lengths_after": vector(51708, 2), "command_history": vector(51716, 2), "wait_counts": vector(51724, 5), "wire_TX": bytesAt(51744, 252), "wire_RX": bytesAt(51996, 252), "ROM_PID": strings.TrimRight(string(b[52248:52254]), "\x00"), "patch_PID": strings.TrimRight(string(b[52255:52263]), "\x00"), "ROM_VID": bytesAt(52264, 3), "patch_VID": bytesAt(52267, 4), "sensor_id": uint32(b[52271]), "trace": tt, "trace_total": traceTotal, "trace_first_index": traceFirst, "trace_capacity": 65536, "powered_PMIC": poweredPmic, "info_length": u(840324), "header_length_valid": u(840328), "full_IC_info_checksum_verified": u(840332) == 1, "read_address": "0x10070", "payload_bytes": 242, "report": frame(840336), "ack": frame(840480), "post_report": frame(840624), "IRQ_sample_mask": u(840768), "IRQ_before": vector(840772, 2), "IRQ_after": vector(840780, 2), "settle_sample_count": settleCount, "settle_samples": settle, "poll": poll}
	return map[string]any{"status": status, "operation_code": u(80), "restore_error": u(84), "restored": u(88), "stage": u(92), "transaction_count": txcount, "pmic_count": pmcount, "enable_attempted": u(156), "release_attempted": u(160), "preflight_verified": u(116), "on_verified": u(120), "off_verified": u(124), "RSC_uncertain": u(128), "observer_uncertain": u(132), "source_status_baseline": uint32(b[39528+68]), "client_before": vector(192, 3), "client_on": u(216), "client_after": vector(220, 3), "transactions": tx, "PMIC": pm, "guards_before": vector(232, 8), "guards_after": vector(328, 8), "waits_1ms": u(184), "waits_10ms": u(188), "fixed_registers_unchanged": u(969784), "attempt": u(969788), "elapsed_ticks": q(969792), "counter_frequency": q(969800), "spi": spi, "touch": touch, "powered_hook_called": u(969776), "safe_release": u(969780)}, nil
}
