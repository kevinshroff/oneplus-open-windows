// SPDX-License-Identifier: MIT
package main

import (
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
)

//go:embed abi.json
var abiJSON []byte

type ABI struct {
	Size, StateSize, RequestSize                                        int
	Magic                                                               string
	Codes                                                               map[string]uint32
	Snapshot, State, Batch, Battery, Request, Monitor, Provider, Health map[string]int
}

var abi ABI

func init() {
	// Underscored C schema names are explicit; unknown field spelling cannot
	// silently choose a zero offset or control code.
	var wire struct {
		Size                                                                int               `json:"size"`
		StateSize                                                           int               `json:"state_size"`
		RequestSize                                                         int               `json:"request_size"`
		Magic                                                               string            `json:"magic"`
		Codes                                                               map[string]uint32 `json:"codes"`
		Snapshot, State, Batch, Battery, Request, Monitor, Provider, Health map[string]int
	}
	if e := json.Unmarshal(abiJSON, &wire); e != nil {
		panic(e)
	}
	abi = ABI{wire.Size, wire.StateSize, wire.RequestSize, wire.Magic, wire.Codes, wire.Snapshot, wire.State, wire.Batch, wire.Battery, wire.Request, wire.Monitor, wire.Provider, wire.Health}
	if abi.Size != 137096 || abi.RequestSize != 48 || abi.StateSize != 136456 || len(abi.Codes) != 9 || len(abi.Snapshot) != 38 {
		panic("C ABI schema")
	}
}
func offset(m map[string]int, n string) int {
	v, ok := m[n]
	if !ok {
		panic("missing C ABI field: " + n)
	}
	return v
}
func u32(b []byte, n int) uint32 { return binary.LittleEndian.Uint32(b[n:]) }
func u64(b []byte, n int) uint64 { return binary.LittleEndian.Uint64(b[n:]) }
func request(mode string, cookie, id, nonce uint64) ([]byte, uint32, error) {
	code, ok := abi.Codes[mode]
	if !ok {
		return nil, 0, fmt.Errorf("fixed operation required")
	}
	read := mode == "status" || mode == "snapshot"
	if (read && (cookie != 0 || id != 0)) || (!read && (cookie == 0 || id == 0)) {
		return nil, 0, fmt.Errorf("cookie/command ID")
	}
	health := mode == "board-fv" || mode == "restart-pulse" || mode == "health-renew"
	if health != (nonce != 0) {
		return nil, 0, fmt.Errorf("opaque health nonce required only for typed health operations")
	}
	magic, e := strconv.ParseUint(abi.Magic, 16, 64)
	if e != nil {
		return nil, 0, e
	}
	b := make([]byte, abi.RequestSize)
	binary.LittleEndian.PutUint32(b, uint32(len(b)))
	binary.LittleEndian.PutUint32(b[4:], 1)
	binary.LittleEndian.PutUint64(b[8:], magic)
	binary.LittleEndian.PutUint64(b[16:], cookie)
	binary.LittleEndian.PutUint64(b[24:], id)
	binary.LittleEndian.PutUint64(b[offset(abi.Request, "HealthNonce"):], nonce)
	return b, code, nil
}
func decode(b []byte) (map[string]any, error) {
	if len(b) != abi.Size {
		return nil, fmt.Errorf("snapshot length %d", len(b))
	}
	g32 := func(n string) uint32 { return u32(b, offset(abi.Snapshot, n)) }
	g64 := func(n string) uint64 { return u64(b, offset(abi.Snapshot, n)) }
	if g32("Size") != uint32(abi.Size) || g32("Version") != 1 || fmt.Sprintf("%016x", g64("Magic")) != abi.Magic || g64("Cookie") == 0 {
		return nil, fmt.Errorf("snapshot identity")
	}
	for _, n := range []string{"FirmwareMatch", "WinPE", "Attempted", "Running", "Stopped", "SafeToUnload", "NativeFault", "HealthBusy", "ProviderUncertain"} {
		if g32(n) > 1 {
			return nil, fmt.Errorf("boolean %s", n)
		}
	}
	if g32("MapsLive") > 2 || (g32("SafeToUnload") != 0 && (g32("Running") != 0 || g32("MapsLive") != 0 || g32("HealthBusy") != 0 || g32("ProviderUncertain") != 0)) || (g32("Running") != 0 && g32("Stopped") != 0) {
		return nil, fmt.Errorf("owner lifetime contradiction")
	}
	s := b[offset(abi.Snapshot, "State"):]
	s32 := func(n string) uint32 { return u32(s, offset(abi.State, n)) }
	s64 := func(n string) uint64 { return u64(s, offset(abi.State, n)) }
	if s32("Phase") > 6 || s32("Fault") > 14 || s32("CurrentOffers") > 32 || s32("TraceCount") > 32 || s32("Query") > 14 || s32("NextLocalId") == 0 || s64("TraceNext") == 0 {
		return nil, fmt.Errorf("core bounds")
	}
	for _, n := range []string{"BoardFvAttempted", "BoardFvAcked", "PulseAttempted", "PulseEnableAcked", "PulseDisableAcked", "StopPulseRequested", "CloseAfterPulse", "RestartOffAcked"} {
		if s32(n) > 1 {
			return nil, fmt.Errorf("core boolean %s", n)
		}
	}
	if (s32("BoardFvAcked") != 0 && s32("BoardFvAttempted") == 0) ||
		(s32("PulseAttempted") != 0 && s32("BoardFvAcked") == 0) ||
		((s32("PulseEnableAcked") != 0 || s32("PulseDisableAcked") != 0 || s32("RestartOffAcked") != 0) && s32("PulseAttempted") == 0) ||
		(s32("PulseEnableAcked") != 0 && s32("RestartOffAcked") == 0) {
		return nil, fmt.Errorf("control admission contradiction")
	}
	if s32("Phase") == 5 && (g32("MapsLive") != 0 || (g32("SafeToUnload") != 1 && g32("HealthBusy") == 0 && g32("ProviderUncertain") == 0)) {
		return nil, fmt.Errorf("closed owner retains maps")
	}
	if e := decodeHealth(b); e != nil {
		return nil, e
	}
	out := map[string]any{"cookie": fmt.Sprintf("%016x", g64("Cookie")), "last_command_id": g64("LastCommandId"), "now_us": g64("NowUs"), "timer_calls": g64("TimerCalls"), "map_calls": g64("MapCalls")}
	for _, n := range []string{"KernelBuild", "Processors", "Irql", "FirmwareBytes", "FirmwareMatch", "FirmwareStatus", "WinPE", "Attempted", "AdmissionCode", "MapsLive", "Running", "Stopped", "SafeToUnload", "NativeFault", "LastAction", "LastResult", "HealthBusy", "HealthAction", "HealthCode", "ProviderUncertain"} {
		out[n] = g32(n)
	}
	state := map[string]any{}
	for _, n := range []string{"Phase", "Fault", "TransportUncertain", "RpcUncertain", "OwnTx", "OwnRx", "RemoteCid", "RemoteOpen", "CloseSent", "CloseAcked", "RemoteClosed", "BatchActive", "Query", "Pending", "NextLocalId", "CurrentOffers", "TraceCount", "BoardFvAttempted", "BoardFvAcked", "PulseAttempted", "PulseEnableAcked", "PulseDisableAcked", "StopPulseRequested", "CloseAfterPulse", "RestartOffAcked"} {
		state[n] = s32(n)
	}
	for _, n := range []string{"TraceNext", "TraceOverwritten", "TxFrames", "RxFrames", "TxWriteAttempts", "CounterWriteAttempts", "KickAttempts", "Steps", "BatchesStarted", "BatchesCompleted", "Events", "IgnoredOpens", "PulseUntilUs", "PulseDisableSinceUs", "RestartUntilUs", "PulseHardUntilUs", "LastHealthLeaseUs", "HealthLeaseRenewals"} {
		state[n] = s64(n)
	}
	for _, n := range []string{"InitialDescriptor", "FinalDescriptor"} {
		v := make([]uint32, 8)
		for i := range v {
			v[i] = u32(b, offset(abi.Snapshot, n)+4*i)
		}
		out[n] = v
	}
	batch := s[offset(abi.State, "LastBatch"):]
	b32 := func(n string) uint32 { return u32(batch, offset(abi.Batch, n)) }
	b64 := func(n string) uint64 { return u64(batch, offset(abi.Batch, n)) }
	kind := b32("Kind")
	result := map[string]any{"generation": b64("Generation"), "begin_us": b64("BeginUs"), "end_us": b64("EndUs"), "complete": b32("Complete"), "aborted": b32("Aborted"), "kind": kind}
	bat := batch[offset(abi.Batch, "Battery"):]
	mask := u32(bat, offset(abi.Battery, "ValueValidMask"))
	wire := u32(bat, offset(abi.Battery, "WireValidMask"))
	reject := u32(bat, offset(abi.Battery, "ServiceRejectedMask"))
	ack := u32(bat, offset(abi.Battery, "ControlAckMask"))
	expectedMask := uint32(1023)
	if kind == 1 {
		expectedMask = 1024
	}
	if kind == 2 {
		expectedMask = 14336
	}
	if kind > 2 || b32("Reserved") != 0 || wire&^expectedMask != 0 || ack&^(expectedMask&15360) != 0 || mask&^uint32(1023) != 0 || (kind != 0 && mask != 0) || mask&ack != 0 || reject&ack != 0 || mask&reject != 0 || (mask|reject|ack) != wire || b32("Complete") > 1 || b32("Aborted") > 1 {
		return nil, fmt.Errorf("batch mask contradiction")
	}
	result["wire_valid_mask"] = wire
	result["value_valid_mask"] = mask
	result["service_rejected_mask"] = reject
	result["control_ack_mask"] = ack
	if b32("Complete") == 1 {
		// A settled initial-off rejection (or cancellation while it was pending)
		// ends this one-shot sequence without ever sending enable or final off.
		if b32("Aborted") == 1 {
			if kind != 2 || wire != 8192 || s32("PulseEnableAcked") != 0 || s32("PulseDisableAcked") != 0 ||
				(reject != 8192 && s32("StopPulseRequested") != 1) {
				return nil, fmt.Errorf("aborted restart sequence contradiction")
			}
			expectedMask = 8192
		}
		if wire != expectedMask || b64("Generation") == 0 || b64("Generation") != s64("BatchesCompleted") || b64("BeginUs") > b64("EndUs") {
			return nil, fmt.Errorf("completed batch contradiction")
		}
		if kind != 0 {
			if s32("BoardFvAttempted") != 1 || u32(bat, offset(abi.Battery, "VoltageMax")) != 0 {
				return nil, fmt.Errorf("fixed control admission")
			}
			services := map[string]uint32{}
			for i := 0; i < 14; i++ {
				if expectedMask&(1<<i) == 0 {
					if u32(batch, offset(abi.Batch, "ReplyBytes")+i*4) != 0 {
						return nil, fmt.Errorf("mixed control batch")
					}
					continue
				}
				start := offset(abi.Batch, "Replies") + i*1024
				raw := batch[start : start+24]
				service := u32(bat, offset(abi.Battery, "ServiceResult")+i*4)
				prop := uint32(24)
				name := "enable"
				if i == 10 {
					prop = 8
					name = "FV"
				}
				if i == 12 {
					name = "disable"
				}
				if i == 13 {
					name = "initial_off"
				}
				if u32(batch, offset(abi.Batch, "ReplyBytes")+i*4) != 24 || u32(raw, 0) != 0x800a || u32(raw, 4) != 1 || u32(raw, 8) != 0x31 || u32(raw, 12) != prop || u32(raw, 20) != service ||
					(service == 0) != (ack&(1<<i) != 0) || (service != 0) != (reject&(1<<i) != 0) {
					return nil, fmt.Errorf("fixed control reply binding %s", name)
				}
				services[name] = service
			}
			if kind == 1 {
				if (s32("BoardFvAcked") == 1) != (ack == 1024) {
					return nil, fmt.Errorf("FV sticky acknowledgement")
				}
				result["service_result"] = services["FV"]
				result["requested_mV"] = uint32(4470)
			} else {
				if s32("PulseAttempted") != 1 || s32("BoardFvAcked") != 1 ||
					(s32("PulseEnableAcked") == 1) != (ack&2048 != 0) || (s32("PulseDisableAcked") == 1) != (ack&4096 != 0) ||
					(s32("RestartOffAcked") == 1) != (ack&8192 != 0) {
					return nil, fmt.Errorf("pulse sticky acknowledgement")
				}
				result["service_results"] = services
				result["health_lease_seconds"] = 90
				result["hard_cap_seconds"] = 900
				result["fixed_off_gap_seconds"] = 5
				result["early_stop_requested"] = s32("StopPulseRequested") != 0
			}
			result["hardware_readback_required"] = true
			// SET word4 is not freshly assigned by the original firmware. It cannot
			// establish an echo or voltage and is deliberately absent from decoded values.
		} else {
			if ack != 0 || u32(batch, offset(abi.Batch, "ReplyBytes")+40) != 0 || u32(batch, offset(abi.Batch, "ReplyBytes")+44) != 0 || u32(batch, offset(abi.Batch, "ReplyBytes")+48) != 0 || u32(batch, offset(abi.Batch, "ReplyBytes")+52) != 0 {
				return nil, fmt.Errorf("GET mixed with control batch")
			}
			values := map[string]uint32{}
			for _, q := range []struct {
				N string
				I uint
			}{{"VoltageMax", 0}, {"Voltage", 1}, {"TemperatureRaw", 1}, {"CurrentRaw", 1}, {"OpenCircuitVoltage", 2}, {"LegacyBatteryId", 3}, {"VoltageNow", 4}, {"CurrentNow", 5}, {"TemperatureProperty", 6}, {"CapacityProperty", 7}, {"UsbOnline", 8}, {"UsbType", 9}} {
				if mask&(1<<q.I) != 0 {
					values[q.N] = u32(bat, offset(abi.Battery, q.N))
				}
			}
			result["raw_values"] = values
			// Independently bind the ten stored wire replies to the C summary.
			spec := [][3]uint32{{0x30, 8, 24}, {1, 0, 44}, {0x30, 6, 24}, {0, 0, 16}, {0x30, 7, 24}, {0x30, 9, 24}, {0x30, 12, 24}, {0x30, 4, 24}, {0x32, 0, 24}, {0x32, 6, 24}}
			fields := []string{"VoltageMax", "Voltage", "OpenCircuitVoltage", "LegacyBatteryId", "VoltageNow", "CurrentNow", "TemperatureProperty", "CapacityProperty", "UsbOnline", "UsbType"}
			for i, q := range spec {
				n := u32(batch, offset(abi.Batch, "ReplyBytes")+4*i)
				if n != q[2] {
					return nil, fmt.Errorf("stored reply length %d", i)
				}
				raw := batch[offset(abi.Batch, "Replies")+1024*i : offset(abi.Batch, "Replies")+1024*i+int(n)]
				if u32(raw, 0) != 0x800a || u32(raw, 4) != 1 || u32(raw, 8) != q[0] {
					return nil, fmt.Errorf("stored reply header %d", i)
				}
				value, result := uint32(0), uint32(0)
				if i == 1 {
					value = u32(raw, 24)
				} else if i == 3 {
					value = u32(raw, 12)
				} else {
					if u32(raw, 12) != q[1] {
						return nil, fmt.Errorf("stored property %d", i)
					}
					value, result = u32(raw, 16), u32(raw, 20)
				}
				if result != u32(bat, offset(abi.Battery, "ServiceResult")+4*i) || ((result != 0) != (reject&(1<<i) != 0)) {
					return nil, fmt.Errorf("service result %d", i)
				}
				if result == 0 && values[fields[i]] != value {
					return nil, fmt.Errorf("wire value %d", i)
				}
			}
		}
	}
	out["health_monitor"] = healthSummary(b)
	out["state"] = state
	out["last_batch"] = result
	out["fdt_sha256"] = hex.EncodeToString(b[offset(abi.Snapshot, "FdtDigest") : offset(abi.Snapshot, "FdtDigest")+32])
	out["limits"] = "GET values can be cached/defaults. Fixed4470mV FV and one off/5s gap/on/off sequence, 90s fresh-health leases and a 15min hard cap; no generic property/value/duration API. Normal disable is driven by the retained kernel timer, not client handles. An initial off failure never permits enable. A transport fault is uncertainty, never proof of disabled hardware. SET acknowledgements require independent hardware readback. Local generation is not a wire transaction ID. No production PnP/power lease."
	return out, nil
}
