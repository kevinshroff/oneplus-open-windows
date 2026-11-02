// SPDX-License-Identifier: MIT
package main

import "fmt"

func healthParts(b []byte) ([]byte, []byte) {
	return b[offset(abi.Snapshot, "Health"):], b[offset(abi.Snapshot, "Provider"):]
}
func decodeHealth(b []byte) error {
	s32 := func(n string) uint32 { return u32(b, offset(abi.Snapshot, n)) }
	s64 := func(n string) uint64 { return u64(b, offset(abi.Snapshot, n)) }
	m, p := healthParts(b)
	m32 := func(n string) uint32 { return u32(m, offset(abi.Monitor, n)) }
	m64 := func(n string) uint64 { return u64(m, offset(abi.Monitor, n)) }
	if s32("HealthCode") > 16 || s32("LastResult") > 4 || m32("Fault") > 16 || m32("LastCode") > 16 ||
		m64("Accepted") > m64("Checks") || (m32("Fault") != 0 && m32("LastCode") != m32("Fault")) || s32("HealthCode") != m32("LastCode") {
		return fmt.Errorf("health policy bookkeeping")
	}
	healthAction := s32("HealthAction")
	typed := func(code uint32) bool {
		return code == abi.Codes["board-fv"] || code == abi.Codes["restart-pulse"] || code == abi.Codes["health-renew"]
	}
	if (healthAction != 0 && !typed(healthAction)) || s64("HealthCommandId") > s64("LastCommandId") ||
		(s32("HealthBusy") != 0 && (s64("HealthCommandId") == 0 || s64("HealthNonce") == 0 || !typed(healthAction))) ||
		(s64("LastRequestNonce") != 0 && !typed(s32("LastAction"))) {
		return fmt.Errorf("health operation binding")
	}
	for _, n := range []string{"Valid", "ValidationAttempted"} {
		if u32(p, offset(abi.Provider, n)) > 1 {
			return fmt.Errorf("provider boolean")
		}
	}
	for _, n := range []string{"CreatedMask", "OpenedMask", "SentMask", "ReceivedMask", "ClosedMask", "DeletedMask"} {
		if u32(p, offset(abi.Provider, n)) > 3 {
			return fmt.Errorf("provider mask")
		}
	}
	if u32(p, offset(abi.Provider, "Reserved")) != 0 || u32(p, offset(abi.Provider, "ManagedBuffers")) > 4 || u32(p, offset(abi.Provider, "HealthCode")) > 16 {
		return fmt.Errorf("provider bounds")
	}
	state := b[offset(abi.Snapshot, "State"):]
	r := u64(state, offset(abi.State, "HealthLeaseRenewals"))
	hard := u64(state, offset(abi.State, "PulseHardUntilUs"))
	if r > 64 || (r > 0 && m64("Accepted") < r+2) || (hard != 0 && u64(state, offset(abi.State, "PulseUntilUs")) > hard) ||
		u64(state, offset(abi.State, "LastHealthLeaseUs")) > hard ||
		(hard != 0 && hard-u64(state, offset(abi.State, "LastHealthLeaseUs")) > 900000000) ||
		(u32(state, offset(abi.State, "PulseEnableAcked")) != 0 && hard == 0) {
		return fmt.Errorf("health lease bounds")
	}
	if m64("Accepted") == 0 {
		if m64("LastNonce") != 0 || m64("LastGaugeEnd100ns") != 0 {
			return fmt.Errorf("unmeasured health identity")
		}
		return nil
	}
	h := m[offset(abi.Monitor, "LastGood"):]
	h64 := func(n string) uint64 { return u64(h, offset(abi.Health, n)) }
	h32 := func(n string) uint32 { return u32(h, offset(abi.Health, n)) }
	if h64("Nonce") == 0 || h64("Nonce") != m64("LastNonce") || h64("GaugeEnd100ns") != m64("LastGaugeEnd100ns") ||
		h64("ConfigBegin100ns") == 0 || h64("ConfigEnd100ns") < h64("ConfigBegin100ns") || h64("GaugeEnd100ns") < h64("ConfigEnd100ns") ||
		h64("GaugeEnd100ns")-h64("ConfigBegin100ns") > 20000000 || h32("FastMa") != 300 || h32("UsbType") != 4 ||
		(h32("FloatMv") != 4470 && h32("FloatMv") != 4550) || h32("Enable") != 1 || h32("StateFirst") < 1 || h32("StateFirst") > 7 || h32("StateLast") < 1 || h32("StateLast") > 7 {
		return fmt.Errorf("accepted health identity or profile")
	}
	for i := 0; i < 2; i++ {
		at := func(n string) uint32 { return u32(h, offset(abi.Health, n)+4*i) }
		raw := at("CurrentRaw")
		current := int32(int16(uint16(raw)))
		if at("VoltageMv") < 3250 || at("VoltageMv") > 4300 || at("TemperatureDeciK") < 2931 || at("TemperatureDeciK") > 3131 || raw > 65535 ||
			current < -500 || current > 500 || at("Flags") > 65535 || at("FullMah") == 0 || at("FullMah") > 65535 || at("RemainingMah") > at("FullMah") || at("ChargePercent") > 100 {
			return fmt.Errorf("accepted health gauge range")
		}
	}
	v0, v1 := u32(h, offset(abi.Health, "VoltageMv")), u32(h, offset(abi.Health, "VoltageMv")+4)
	if v0+150 < v1 || v1+150 < v0 {
		return fmt.Errorf("accepted health voltage delta")
	}
	return nil
}
func healthSummary(b []byte) map[string]any {
	m, p := healthParts(b)
	out := map[string]any{"measurements_are_historical": true, "resource_lease_qualified": false, "aggregate_rate_calibrated": false}
	for _, n := range []string{"Fault", "LastCode"} {
		out[n] = u32(m, offset(abi.Monitor, n))
	}
	for _, n := range []string{"Checks", "Accepted", "LastNonce", "LastGaugeEnd100ns"} {
		out[n] = u64(m, offset(abi.Monitor, n))
	}
	provider := map[string]any{}
	for _, n := range []string{"Stage", "FailedStage", "Valid", "ValidationAttempted", "CreatedMask", "OpenedMask", "SentMask", "ReceivedMask", "ClosedMask", "DeletedMask", "ManagedBuffers", "HealthCode", "LastStatus"} {
		provider[n] = u32(p, offset(abi.Provider, n))
	}
	for _, n := range []string{"Begin100ns", "Validation100ns", "End100ns"} {
		provider[n] = u64(p, offset(abi.Provider, n))
	}
	out["last_provider_result"] = provider
	out["pending_command_id"] = u64(b, offset(abi.Snapshot, "HealthCommandId"))
	out["pending_nonce"] = fmt.Sprintf("%016x", u64(b, offset(abi.Snapshot, "HealthNonce")))
	if u64(m, offset(abi.Monitor, "Accepted")) == 0 {
		out["fresh_at_snapshot"] = false
		return out
	}
	h := m[offset(abi.Monitor, "LastGood"):]
	health := map[string]any{}
	for _, n := range []string{"Nonce", "ConfigBegin100ns", "ConfigEnd100ns", "GaugeEnd100ns"} {
		health[n] = u64(h, offset(abi.Health, n))
	}
	for _, n := range []string{"StateFirst", "StateLast", "Enable", "FloatMv", "FastMa", "UsbType"} {
		health[n] = u32(h, offset(abi.Health, n))
	}
	gauges := []map[string]any{}
	for i := 0; i < 2; i++ {
		g := map[string]any{}
		for _, n := range []string{"VoltageMv", "TemperatureDeciK", "CurrentRaw", "Flags", "RemainingMah", "FullMah", "ChargePercent"} {
			g[n] = u32(h, offset(abi.Health, n)+4*i)
		}
		g["temperature_celsius"] = (float64(g["TemperatureDeciK"].(uint32)) - 2731) / 10
		g["average_current_signed_mA"] = int32(int16(uint16(g["CurrentRaw"].(uint32))))
		gauges = append(gauges, g)
	}
	health["gauges"] = gauges
	out["last_accepted_health"] = health
	now := u64(b, offset(abi.Snapshot, "NowUs"))
	begin := u64(h, offset(abi.Health, "ConfigBegin100ns"))
	fresh := now <= ^uint64(0)/10 && now*10 >= begin && now*10-begin <= 50000000 && u32(m, offset(abi.Monitor, "Fault")) == 0
	out["fresh_at_snapshot"] = fresh
	return out
}
