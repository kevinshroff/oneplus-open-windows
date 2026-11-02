package main

import (
	"encoding/binary"
	"fmt"
)

var le = binary.LittleEndian

const captureBytes = 1000
const magic uint64 = 0x314d50313631474f

func decodeStatus(b []byte) (map[string]any, error) {
	if len(b) != 80 || le.Uint32(b) != 80 || le.Uint32(b[4:]) != 1 || le.Uint64(b[8:]) != magic {
		return nil, fmt.Errorf("status ABI")
	}
	s := map[string]any{}
	for i, k := range []string{"kernel_build", "processors", "IRQL", "firmware_bytes", "firmware_match", "firmware_status", "map_calls", "attempts", "ready", "fault"} {
		s[k] = le.Uint32(b[16+i*4:])
	}
	for i, k := range []string{"interrupt_time", "frequency", "sequence"} {
		s[k] = le.Uint64(b[56+i*8:])
	}
	return s, nil
}

var queries = [17][3]uint32{{0, 0, 8}, {1, 0, 8}, {2, 0, 8}, {3, 0, 8}, {4, 0, 8}, {2, 6, 8}, {2, 14, 2}, {2, 0x40, 8}, {2, 0x50, 8}, {2, 0x58, 8}, {2, 0x60, 1}, {3, 0x10, 1}, {4, 0x0a, 2}, {4, 0x10, 1}, {4, 0x40, 8}, {4, 0x50, 8}, {2, 6, 8}}
var targets = [5]uint32{0x701, 0x725, 0x726, 0x728, 0x729}
var stateLabels = [8]string{"INHIBIT", "TRICKLE", "PRECHG", "FULLON", "TAPER", "TERMINATION", "PAUSE", "DISABLED"}

func decodeCapture(b []byte, nonce uint64) (map[string]any, error) {
	if len(b) != captureBytes || le.Uint64(b[80:]) != nonce {
		return nil, fmt.Errorf("capture ABI")
	}
	status, e := decodeStatus(b[:80])
	if e != nil {
		return nil, e
	}
	r := b[120:]
	size, code, count := le.Uint32(r), le.Uint32(r[4:]), le.Uint32(r[28:])
	if (size != 880 && !(size == 0 && code >= 1000)) || count > 17 || le.Uint32(r[16:]) > 17 || le.Uint32(r[20:]) > 17 || le.Uint32(b[92:]) != le.Uint32(r[20:]) || le.Uint64(b[112:]) < le.Uint64(b[104:]) {
		return nil, fmt.Errorf("capture fields")
	}
	if le.Uint32(b[100:]) != 0 || le.Uint32(r[40:]) != 0 || le.Uint32(r[44:]) != 0 ||
		le.Uint32(r[12:]) > 4096 || le.Uint32(r[24:]) > 17*64 ||
		(code > 12 && code != 1001 && code != 1002 && code != 1005) {
		return nil, fmt.Errorf("bounds/reserved")
	}
	values := [17][]byte{}
	var traces []map[string]any
	uncertain := false
	for i := uint32(0); i < count; i++ {
		t := r[200+40*i:]
		target, off, n, flags := le.Uint32(t), le.Uint32(t[4:]), le.Uint32(t[8:]), le.Uint32(t[12:])
		if target != queries[i][0] || off != queries[i][1] || n != queries[i][2] || flags > 63 || (flags&32 != 0 && flags != 63) {
			return nil, fmt.Errorf("fixed trace %d", i)
		}
		if le.Uint32(t[36:]) != 0 || (flags&2 != 0 && le.Uint32(t[20:])&1 == 0 && le.Uint32(t[16:]) != 0) {
			return nil, fmt.Errorf("trace reserved/previous pending %d", i)
		}
		record := map[string]any{"address": fmt.Sprintf("SID7:0x%04x", ((targets[target]&255)<<8)+off), "bytes": n, "flags": flags, "completion": le.Uint32(t[24:])}
		if flags&32 != 0 {
			values[i] = append([]byte(nil), r[64+8*i:64+8*i+n]...)
			if le.Uint32(t[24:])&15 != 1 {
				return nil, fmt.Errorf("trace completion %d", i)
			}
			for j := uint32(0); j < n; j++ {
				if values[i][j] != t[28+j] {
					return nil, fmt.Errorf("trace/data binding %d", i)
				}
			}
			for j := n; j < 8; j++ {
				if r[64+8*i+j] != 0 {
					return nil, fmt.Errorf("unused result bytes %d", i)
				}
			}
			record["value_hex"] = fmt.Sprintf("%x", values[i])
		}
		if flags&8 != 0 && flags&16 == 0 {
			uncertain = true
		}
		traces = append(traces, record)
	}
	result := map[string]any{"status": status, "operation_code": code, "stage": le.Uint32(r[8:]), "reads": le.Uint32(r[12:]), "command_attempts": le.Uint32(r[16:]), "commands": le.Uint32(r[20:]), "polls": le.Uint32(r[24:]), "trace_count": count, "cancelled": le.Uint32(r[32:]), "post_routes_verified": le.Uint32(r[36:]), "begin_us": le.Uint64(r[48:]), "end_us": le.Uint64(r[56:]), "native_reads": le.Uint32(b[88:]), "native_observer_READ_commands": le.Uint32(b[92:]), "native_guard": le.Uint32(b[96:]), "uncertain_read": uncertain, "traces": traces, "PMIC_configuration_writes": 0, "charging_policy_approved": false}
	if code == 0 {
		// Two arbiter version checks, before/after route reads, two idle reads
		// per command and its fixed data words, plus every completion poll.
		fixedReads := uint32(6 + 2*17 + 2*17 + 2*5 + 17)
		for _, q := range queries {
			if q[2] > 4 {
				fixedReads++
			}
		}
		if le.Uint32(r[12:]) != fixedReads+le.Uint32(r[24:]) || le.Uint32(r[24:]) < 17 {
			return nil, fmt.Errorf("read/poll accounting")
		}
		for k, want := range map[string]uint32{"kernel_build": 26100, "processors": 8, "IRQL": 0, "firmware_bytes": 576, "firmware_match": 1, "firmware_status": 0, "map_calls": 5, "attempts": 1, "ready": 1, "fault": 0} {
			if status[k] != want {
				return nil, fmt.Errorf("successful platform %s", k)
			}
		}
		begin, end := le.Uint64(r[48:]), le.Uint64(r[56:])
		if end < begin || end-begin > 1000000 || le.Uint32(r[32:]) != 0 {
			return nil, fmt.Errorf("successful time/cancellation")
		}
		if count != 17 || le.Uint32(r[16:]) != 17 || le.Uint32(r[20:]) != 17 || le.Uint32(r[36:]) != 1 || le.Uint32(b[96:]) != 0 || le.Uint32(b[88:]) != le.Uint32(r[12:])+68 {
			return nil, fmt.Errorf("incomplete success")
		}
		for _, v := range values {
			if v == nil {
				return nil, fmt.Errorf("missing completed value")
			}
		}
		if values[0][4] != 0x51 || values[0][5] != 0x47 || values[0][6] != 1 || values[1][4] != 2 || (values[1][5] != 0xa8 && values[1][5] != 0x7f) || values[2][4] != 2 || values[3][4] != 2 || values[4][4] != 2 {
			return nil, fmt.Errorf("native family identity")
		}
		pre := [8]uint32{100, 150, 200, 250, 300, 400, 500, 600}
		port := "pending"
		raw := values[12][1]
		if values[12][0]&1 != 0 {
			port = "unknown"
			labels := [7]string{"SDP", "OCP", "CDP", "DCP", "Float", "QC2", "QC3"}
			for i := 0; i < 7; i++ {
				if raw&(1<<i) != 0 {
					port = labels[i]
				}
			}
		}
		result["telemetry"] = map[string]any{"PMIC_model": "PM8550B source candidate (native type0x51/subtype0x47)", "charger_family": "SCHG type2/subtype a8 or7f", "state_first": stateLabels[values[5][0]&7], "state_last": stateLabels[values[16][0]&7], "precharge_mA": pre[values[8][0]&7], "fast_current_mA": uint32(values[8][4]) * 50, "termination_mA": 100 + uint32(values[10][0]&7)*50, "float_voltage_mV": 3600 + uint32(values[9][0]&127)*10, "APSD_done": values[12][0]&1 != 0, "APSD_type": port, "USB_RT_raw": fmt.Sprintf("0x%02x", values[13][0]), "BATIF_RT_raw": fmt.Sprintf("0x%02x", values[11][0]), "register_2641_raw": fmt.Sprintf("0x%02x", values[7][1]), "configuration_is_approved_for_writes": false}
	}
	return result, nil
}
