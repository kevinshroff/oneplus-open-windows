package main

import "fmt"

func maskCount(v uint32) (uint32, bool) {
	var n uint32
	for n < 24 && v&(1<<n) != 0 {
		n++
	}
	return n, v == (1<<n)-1
}

func selectionCode(samples [2][24]uint32) uint32 {
	if (samples[0][16]|samples[1][16])&0x123c != 0 {
		return 2001
	}
	if samples[0][16] != samples[1][16] || samples[0][17] != samples[1][17] {
		return 2002
	}
	if samples[0][17]&1 != 0 {
		return 2003
	}
	return 0
}

func decodeCapture(b []byte, nonce uint64) (map[string]any, error) {
	if len(b) != captureBytes || nonce == 0 || le.Uint64(b[80:]) != nonce {
		return nil, fmt.Errorf("capture ABI")
	}
	s, err := decodeStatus(b[:80])
	if err != nil {
		return nil, err
	}
	code, complete, reads, maps := le.Uint32(b[88:]), le.Uint32(b[92:]), le.Uint32(b[96:]), le.Uint32(b[100:])
	begin, end := le.Uint64(b[104:]), le.Uint64(b[112:])
	masks := [2]uint32{le.Uint32(b[120:]), le.Uint32(b[124:])}
	n0, ok0 := maskCount(masks[0])
	n1, ok1 := maskCount(masks[1])
	expectedComplete := uint32(0)
	if n0 == 24 {
		expectedComplete |= 1
	}
	if n1 == 24 {
		expectedComplete |= 2
	}
	if !ok0 || !ok1 || n1 > 0 && n0 != 24 || complete != expectedComplete || reads != 4*(n0+n1) || maps > 7 || end < begin || s["attempts"] != uint32(1) || s["ready"] != uint32(1) || s["map_calls"] != maps || s["fault"] != uint32(boolInt(code != 0)) {
		return nil, fmt.Errorf("capture bounds/status")
	}
	var samples [2][24]uint32
	for pass := 0; pass < 2; pass++ {
		for i := 0; i < 24; i++ {
			samples[pass][i] = le.Uint32(b[128+4*(pass*24+i):])
			if masks[pass]&(1<<i) == 0 && samples[pass][i] != 0 {
				return nil, fmt.Errorf("unread word nonzero")
			}
		}
	}
	if maps > 0 && (s["kernel_build"] != uint32(26300) || s["processors"] != uint32(8) || s["IRQL"] != uint32(0) || s["firmware_bytes"] != uint32(576) || s["firmware_match"] != uint32(1) || s["firmware_status"] != uint32(0)) {
		return nil, fmt.Errorf("mapped capture identity")
	}
	switch code {
	case 0, 2001, 2002, 2003:
		if maps != 7 || complete != 3 || reads != 192 || selectionCode(samples) != code {
			return nil, fmt.Errorf("completed capture/code mismatch")
		}
	case 1001, 1002:
		if maps != 0 || reads != 0 {
			return nil, fmt.Errorf("refusal accessed MMIO")
		}
	case 1005:
		if maps == 0 || reads != 0 {
			return nil, fmt.Errorf("map-failure progress")
		}
	case 1004:
		if maps < 7 && reads != 0 || complete == 3 {
			return nil, fmt.Errorf("cancel progress")
		}
	default:
		return nil, fmt.Errorf("unknown capture code")
	}
	rows := make([]map[string]any, 24)
	for i, word := range words {
		observed := [2]bool{masks[0]&(1<<i) != 0, masks[1]&(1<<i) != 0}
		rows[i] = map[string]any{"name": word.Name, "address": fmt.Sprintf("0x%x", word.Address), "values": [2]uint32{samples[0][i], samples[1][i]}, "observed": observed, "stable": observed[0] && observed[1] && samples[0][i] == samples[1][i]}
	}
	r := map[string]any{"status": s, "capture_code": code, "complete_mask": complete, "word_masks": masks, "read_bytes": reads, "map_calls": maps, "begin": begin, "end": end, "words": rows, "configuration_writes": 0, "PARF_PHY_DBI_ECAM_accesses": 0, "PCI_endpoint_identity_verified": false, "source_root0_selection_qualified": code == 0, "link_state": "unobserved", "scope": "Passive GCC/TLMM snapshots; logical votes, hardware completion and GPIO roles remain distinct. No rail/clock/reset/pin configuration or PCIe access."}
	if code == 0 {
		r["source_selected_device_id"] = "0x1107"
		r["source_selected_root_complex"] = 0
		stable := func(i int) bool { return samples[0][i] == samples[1][i] }
		domain := func(ctrl, cfg int, voteBit uint) map[string]any {
			c, f := samples[0][ctrl], samples[0][cfg]
			up, down, powered := f&(1<<16) != 0, f&(1<<15) != 0, c&(1<<31) != 0
			state := "unknown"
			if stable(ctrl) && stable(cfg) && up != down && powered == up {
				if powered {
					state = "on"
				} else {
					state = "off"
				}
			}
			return map[string]any{"hardware_power": state, "gdscr_power_on_bit31": powered, "cfg_power_up_complete_bit16": up, "cfg_power_down_complete_bit15": down, "power_words_stable": stable(ctrl) && stable(cfg), "linux_logical_vote_enabled": samples[0][0]&(1<<voteBit) == 0, "vote_stable": stable(0), "logical_vote_proves_physical_power": false}
		}
		r["core_domain"] = domain(4, 5, 0)
		r["phy_domain"] = domain(13, 14, 3)
		r["core_reset"] = map[string]any{"asserted_bit0": samples[0][3]&1 != 0, "stable": stable(3)}
		r["phy_reset"] = map[string]any{"asserted_bit0": samples[0][15]&1 != 0, "stable": stable(15)}
		pins := map[string]any{}
		for _, pin := range []struct {
			Name  string
			Index int
		}{{"PERST_GPIO94", 18}, {"WAKE_GPIO96", 20}, {"WLAN_EN_GPIO80", 22}} {
			c, v := samples[0][pin.Index], samples[0][pin.Index+1]
			pins[pin.Name] = map[string]any{"mux": (c >> 2) & 15, "output_enable": c&(1<<9) != 0, "egpio_enable": c&(1<<12) != 0, "input_bit0": v & 1, "output_bit1": (v >> 1) & 1, "stable": stable(pin.Index) && stable(pin.Index+1)}
		}
		r["pins"] = pins
	}
	return r, nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
