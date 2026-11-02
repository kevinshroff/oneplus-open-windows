// SPDX-License-Identifier: MIT
// G60 helper policy against the unchanged G59 source-owned session API.
package main

func cancelEligible(s map[string]any) bool {
	for k, want := range map[string]uint32{"state": 2, "phase": 9, "starts": 1, "hardware_calls": 1, "result_ready": 0, "outcome": 0, "stop_reason": 0} {
		got, ok := s[k].(uint32)
		if !ok || got != want {
			return false
		}
	}
	n, ok := s["poll_cycles"].(uint32)
	return ok && n >= 1000 && n < 2500
}
func activeRelease(s map[string]any) bool {
	for k, want := range map[string]uint32{"accepted_mask": 0, "stop_attempts": 1, "stop_accepted": 1, "live_complete": 0, "live_error": 6} {
		got, ok := s[k].(uint32)
		if !ok || got != want {
			return false
		}
	}
	n, ok := s["reports_submitted"].(uint32)
	if !ok || n < 2 {
		return false
	}
	for _, k := range []string{"reports_accepted", "accepted_generation"} {
		v, ok := s[k].(uint32)
		if !ok || v != n {
			return false
		}
	}
	return true
}

func idleRelease(s map[string]any) bool {
	for k, want := range map[string]uint32{"accepted_mask": 0, "stop_attempts": 1, "stop_accepted": 0, "live_complete": 0, "live_error": 6, "reports_submitted": 0, "reports_accepted": 0, "accepted_generation": 0} {
		got, ok := s[k].(uint32)
		if !ok || got != want {
			return false
		}
	}
	return true
}
func cancelRelease(s map[string]any, expectation string) bool {
	if expectation == "active" {
		return activeRelease(s)
	}
	if expectation == "idle" {
		return idleRelease(s)
	}
	return false
}
