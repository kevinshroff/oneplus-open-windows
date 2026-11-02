package main

import (
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
)

//go:embed abi.json
var abiJSON []byte

type schema struct {
	StatusSize                  int `json:"status_size"`
	CaptureSize                 int `json:"capture_size"`
	RequestSize                 int `json:"request_size"`
	IOSize                      int `json:"io_size"`
	HealthSize                  int `json:"health_size"`
	Magic                       string
	Codes                       map[string]uint32
	Status, Capture, IO, Health map[string]int
}

var abi schema
var le = binary.LittleEndian
var captureBytes int

func init() {
	if e := json.Unmarshal(abiJSON, &abi); e != nil {
		panic(e)
	}
	if abi.StatusSize != 96 || abi.CaptureSize != 320 || abi.RequestSize != 32 || abi.IOSize != 208 || abi.HealthSize != 112 || len(abi.Codes) != 3 {
		panic("actual C schema")
	}
	captureBytes = abi.CaptureSize
}
func at(m map[string]int, n string) int {
	v, ok := m[n]
	if !ok {
		panic("missing actual C offset: " + n)
	}
	return v
}
func u32(b []byte, n int) uint32 { return le.Uint32(b[n:]) }
func u64(b []byte, n int) uint64 { return le.Uint64(b[n:]) }
func encodeRequest(nonce uint64) []byte {
	b := make([]byte, 32)
	magic, e := strconv.ParseUint(abi.Magic, 16, 64)
	if e != nil {
		panic(e)
	}
	le.PutUint32(b, 32)
	le.PutUint32(b[4:], 1)
	le.PutUint64(b[8:], magic)
	le.PutUint64(b[16:], nonce)
	return b
}
func decodeStatus(b []byte) (map[string]any, error) {
	if len(b) != abi.StatusSize || u32(b, 0) != 96 || u32(b, 4) != 1 || fmt.Sprintf("%016x", u64(b, 8)) != abi.Magic {
		return nil, fmt.Errorf("G179 status ABI")
	}
	v := map[string]any{}
	names := map[string]string{"KernelBuild": "kernel_build", "Processors": "processors", "Irql": "IRQL", "FirmwareBytes": "firmware_bytes", "FirmwareMatch": "firmware_match", "FirmwareStatus": "firmware_status", "MapCalls": "map_calls", "Attempts": "attempts", "Ready": "ready", "Fault": "fault", "SafeToUnload": "safe_to_unload", "TransportUncertain": "transport_uncertain"}
	for field, key := range names {
		v[key] = u32(b, at(abi.Status, field))
	}
	for field, key := range map[string]string{"InterruptTime": "interrupt_time", "Frequency": "frequency", "Sequence": "sequence"} {
		v[key] = u64(b, at(abi.Status, field))
	}
	for _, n := range []string{"FirmwareMatch", "Attempts", "Ready", "Fault", "SafeToUnload", "TransportUncertain"} {
		if u32(b, at(abi.Status, n)) > 1 {
			return nil, fmt.Errorf("status boolean %s", n)
		}
	}
	if v["map_calls"] != uint32(0) || u32(b, at(abi.Status, "Reserved")) != 0 || u32(b, at(abi.Status, "Reserved")+4) != 0 || v["ready"] == uint32(1) && v["attempts"] != uint32(1) || v["transport_uncertain"] == uint32(1) && v["safe_to_unload"] != uint32(0) {
		return nil, fmt.Errorf("status contradiction")
	}
	return v, nil
}
func decodeCapture(b []byte, nonce uint64) (map[string]any, error) {
	if len(b) != abi.CaptureSize || u64(b, at(abi.Capture, "Nonce")) != nonce || nonce == 0 {
		return nil, fmt.Errorf("capture ABI/nonce")
	}
	s, e := decodeStatus(b[:abi.StatusSize])
	if e != nil {
		return nil, e
	}
	if s["attempts"] != uint32(1) || s["ready"] != uint32(1) || u32(b, at(abi.Capture, "Reserved")) != 0 {
		return nil, fmt.Errorf("capture completion")
	}
	admission := u32(b, at(abi.Capture, "Admission"))
	if admission != 0 && admission != 1001 {
		return nil, fmt.Errorf("admission")
	}
	r := b[at(abi.Capture, "Result"):]
	g := func(n string) uint32 { return u32(r, at(abi.IO, n)) }
	q := func(n string) uint64 { return u64(r, at(abi.IO, n)) }
	if g("ValidationAttempted") > 1 || g("Valid") > 1 || g("ManagedBuffers") > 4 || g("HealthCode") > 14 || g("Reserved") != 0 {
		return nil, fmt.Errorf("provider bounds")
	}
	io := map[string]any{}
	for _, n := range []string{"Stage", "FailedStage", "ValidationAttempted", "Valid", "CreatedMask", "OpenedMask", "SentMask", "ReceivedMask", "ClosedMask", "DeletedMask", "ManagedBuffers", "LastStatus"} {
		io[n] = g(n)
	}
	for _, n := range []string{"CreatedMask", "OpenedMask", "SentMask", "ReceivedMask", "ClosedMask", "DeletedMask"} {
		if g(n) > 3 {
			return nil, fmt.Errorf("mask bounds")
		}
	}
	if g("OpenedMask")&^g("CreatedMask") != 0 || g("SentMask")&^g("OpenedMask") != 0 || g("ReceivedMask")&^g("SentMask") != 0 || g("ClosedMask") != g("OpenedMask") || g("DeletedMask") != g("CreatedMask") {
		return nil, fmt.Errorf("target lifecycle")
	}
	if g("ValidationAttempted") == 1 {
		io["HealthCode"] = g("HealthCode")
	}
	sends := []any{}
	for i := 0; i < 2; i++ {
		if g("SentMask")&(1<<i) != 0 {
			sends = append(sends, map[string]any{"provider": []string{"G167", "G160"}[i], "status": u32(r, at(abi.IO, "SendStatus")+4*i), "bytes": u32(r, at(abi.IO, "ReceivedBytes")+4*i)})
		}
	}
	io["sent_results"] = sends
	for _, n := range []string{"Begin100ns", "Validation100ns", "End100ns"} {
		io[n] = q(n)
	}
	out := map[string]any{"admission": admission, "status": s, "provider_io": io, "valid_at_acquisition": g("Valid") == 1}
	h := r[at(abi.IO, "Health") : at(abi.IO, "Health")+abi.HealthSize]
	if g("Valid") == 0 {
		for _, v := range h {
			if v != 0 {
				return nil, fmt.Errorf("invalid acquisition exposes physical values")
			}
		}
	} else {
		if admission != 0 || s["fault"] != uint32(0) || s["transport_uncertain"] != uint32(0) || s["safe_to_unload"] != uint32(1) || g("Stage") != 100 || g("FailedStage") != 0 || g("ValidationAttempted") != 1 || g("HealthCode") != 0 || g("LastStatus") != 0 || g("ManagedBuffers") != 4 {
			return nil, fmt.Errorf("valid acquisition contradiction")
		}
		for _, n := range []string{"CreatedMask", "OpenedMask", "SentMask", "ReceivedMask", "ClosedMask", "DeletedMask"} {
			if g(n) != 3 {
				return nil, fmt.Errorf("incomplete valid target path")
			}
		}
		for i, n := range []uint32{1096, 279880} {
			if u32(r, at(abi.IO, "SendStatus")+4*i) != 0 || u32(r, at(abi.IO, "ReceivedBytes")+4*i) != n {
				return nil, fmt.Errorf("provider result length/status")
			}
		}
		a, z, v := u64(h, at(abi.Health, "ConfigBegin100ns")), u64(h, at(abi.Health, "ConfigEnd100ns")), u64(h, at(abi.Health, "GaugeEnd100ns"))
		if u64(h, at(abi.Health, "Nonce")) != nonce || z < a || v < z || q("Validation100ns") < v || q("End100ns") < q("Validation100ns") || q("End100ns")-a > 50000000 || v-a > 20000000 || q("Validation100ns") < q("Begin100ns") || s["interrupt_time"].(uint64) < q("End100ns") {
			return nil, fmt.Errorf("physical clock/nonce binding")
		}
		health := map[string]any{"nonce": fmt.Sprintf("%016x", nonce), "config_begin_100ns": a, "config_end_100ns": z, "gauge_end_100ns": v}
		for _, n := range []string{"StateFirst", "StateLast", "Enable", "FloatMv", "FastMa", "UsbType"} {
			health[n] = u32(h, at(abi.Health, n))
		}
		if health["StateFirst"].(uint32) > 7 || health["StateLast"].(uint32) > 7 || health["Enable"].(uint32) > 1 || health["FloatMv"] != uint32(4470) || health["FastMa"] != uint32(300) || health["UsbType"] != uint32(4) {
			return nil, fmt.Errorf("fixed observation profile")
		}
		gauges := []any{}
		for i := 0; i < 2; i++ {
			m := map[string]any{}
			for _, n := range []string{"VoltageMv", "TemperatureDeciK", "CurrentRaw", "Flags", "RemainingMah", "FullMah", "ChargePercent"} {
				m[n] = u32(h, at(abi.Health, n)+4*i)
			}
			voltage, temp, current := m["VoltageMv"].(uint32), m["TemperatureDeciK"].(uint32), m["CurrentRaw"].(uint32)
			if voltage < 3250 || voltage > 4300 || temp < 2931 || temp > 3131 || current > 65535 || m["Flags"].(uint32) > 65535 || m["FullMah"].(uint32) == 0 || m["RemainingMah"].(uint32) > m["FullMah"].(uint32) || m["ChargePercent"].(uint32) > 100 {
				return nil, fmt.Errorf("physical gauge bounds")
			}
			signed := int32(int16(current))
			if signed < -500 || signed > 500 {
				return nil, fmt.Errorf("current range")
			}
			m["average_current_signed_mA"] = signed
			m["temperature_celsius"] = float64(int32(temp)-2731) / 10
			gauges = append(gauges, m)
		}
		health["gauges"] = gauges
		out["health"] = health
		age := s["interrupt_time"].(uint64) - a
		out["age_100ns_at_snapshot"] = age
		out["fresh_at_snapshot"] = age <= 50000000
	}
	out["limits"] = "Immutable completed kernel-provider results. STATUS/RESULT do not refresh sensors; freshness is only at recorded interrupt time. No production hardware lease, Windows battery class, charging control or calibrated aggregate rate."
	return out, nil
}
