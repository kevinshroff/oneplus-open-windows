package main

import (
	"encoding/binary"
	"testing"
)

func TestHealthNonceFraming(t *testing.T) {
	for _, mode := range []string{"board-fv", "restart-pulse", "health-renew"} {
		if _, _, e := request(mode, 1, 2, 0); e == nil {
			t.Fatal("missing health nonce", mode)
		}
		b, _, e := request(mode, 1, 2, 0x12345678)
		if e != nil || u64(b, offset(abi.Request, "HealthNonce")) != 0x12345678 {
			t.Fatal("nonce binding", mode, e)
		}
	}
	for _, mode := range []string{"status", "snapshot", "start", "sample", "close", "stop-pulse"} {
		cookie, id := uint64(1), uint64(2)
		if mode == "status" || mode == "snapshot" {
			cookie = 0
			id = 0
		}
		if _, _, e := request(mode, cookie, id, 1); e == nil {
			t.Fatal("nonce on nonhealth operation", mode)
		}
	}
}
func TestActualCHealthLifecycle(t *testing.T) {
	for _, name := range []string{"health-renewed.bin", "health-pending.bin", "health-expired-pending.bin", "health-close-pending.bin", "health-close-drained.bin", "health-precontrol-refused.bin", "health-thermal-stop.bin", "health-provider-uncertain-closed.bin", "health-hard-cap-active.bin", "health-hard-cap-complete.bin"} {
		t.Run(name, func(t *testing.T) {
			r, e := decode(fixture(t, name))
			if e != nil {
				t.Fatal(e)
			}
			m := r["health_monitor"].(map[string]any)
			if m["measurements_are_historical"] != true || m["resource_lease_qualified"] != false || m["aggregate_rate_calibrated"] != false {
				t.Fatal("overclaim", m)
			}
			switch name {
			case "health-renewed.bin":
				if m["fresh_at_snapshot"] != true || m["Accepted"] != uint64(3) || r["state"].(map[string]any)["HealthLeaseRenewals"] != uint64(1) {
					t.Fatal(m)
				}
			case "health-precontrol-refused.bin":
				if _, ok := m["last_accepted_health"]; ok {
					t.Fatal("rejected data exposed as accepted")
				}
			case "health-close-pending.bin":
				if r["SafeToUnload"] != uint32(0) || r["HealthBusy"] != uint32(1) {
					t.Fatal("live worker concealed")
				}
			case "health-close-drained.bin":
				if r["SafeToUnload"] != uint32(1) || r["HealthBusy"] != uint32(0) {
					t.Fatal("drain incomplete")
				}
			case "health-provider-uncertain-closed.bin":
				if r["SafeToUnload"] != uint32(0) || r["ProviderUncertain"] != uint32(1) || m["Fault"] != uint32(16) {
					t.Fatal("uncertainty hidden")
				}
			case "health-thermal-stop.bin", "health-hard-cap-complete.bin":
				if m["fresh_at_snapshot"] != false {
					t.Fatal("historical data relabeled fresh")
				}
			}
		})
	}
}
func TestAcceptedHealthCorruption(t *testing.T) {
	source := fixture(t, "health-renewed.bin")
	monitor := offset(abi.Snapshot, "Health")
	health := monitor + offset(abi.Monitor, "LastGood")
	state := offset(abi.Snapshot, "State")
	cases := map[string]int{"accepted count": monitor + offset(abi.Monitor, "Accepted"), "nonce": health + offset(abi.Health, "Nonce"), "stamp": health + offset(abi.Health, "GaugeEnd100ns"), "temperature": health + offset(abi.Health, "TemperatureDeciK"), "voltage": health + offset(abi.Health, "VoltageMv"), "current": health + offset(abi.Health, "CurrentRaw"), "hard cap": state + offset(abi.State, "PulseHardUntilUs"), "fault": monitor + offset(abi.Monitor, "Fault"), "provider mask": offset(abi.Snapshot, "Provider") + offset(abi.Provider, "SentMask")}
	for name, at := range cases {
		t.Run(name, func(t *testing.T) {
			b := append([]byte(nil), source...)
			binary.LittleEndian.PutUint32(b[at:], 0xffffffff)
			if _, e := decode(b); e == nil {
				t.Fatal("corruption accepted")
			}
		})
	}
	b := append([]byte(nil), source...)
	binary.LittleEndian.PutUint64(b[offset(abi.Snapshot, "NowUs"):], u64(b, offset(abi.Snapshot, "NowUs"))+10000000)
	r, e := decode(b)
	if e != nil || r["health_monitor"].(map[string]any)["fresh_at_snapshot"] != false {
		t.Fatal("saved capture must become historical", e)
	}
}
