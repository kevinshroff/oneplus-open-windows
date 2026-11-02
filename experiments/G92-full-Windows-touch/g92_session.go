// SPDX-License-Identifier: MIT
// Portable decoder for the fixed source-owned session status.
package main

import (
	"encoding/binary"
	"errors"
)

func decodeSession(b []byte) (map[string]any, error) {
	if len(b) != 96 || binary.LittleEndian.Uint32(b) != 96 || binary.LittleEndian.Uint32(b[4:]) != 1 || string(b[8:16]) != "OPG92HD1" {
		return nil, errors.New("G92 session ABI differs")
	}
	names := []string{"state", "stop_reason", "starts", "hardware_calls", "result_ready", "outcome", "stop_checks", "stop_seen", "inhibit", "thread_joined", "phase", "poll_cycles"}
	v := map[string]any{}
	for i, n := range names {
		v[n] = binary.LittleEndian.Uint32(b[16+i*4:])
	}
	for i, n := range []string{"begin_us", "end_us", "stop_us"} {
		v[n] = binary.LittleEndian.Uint64(b[64+i*8:])
	}
	v["thread_create_status"] = binary.LittleEndian.Uint32(b[88:])
	v["stop_requests"] = binary.LittleEndian.Uint32(b[92:])
	u := func(n string) uint32 { return v[n].(uint32) }
	if u("state") > 3 || u("stop_reason") > 6 || u("starts") > 1 || u("hardware_calls") > 1 || u("result_ready") > 1 || u("outcome") > 4 || u("inhibit") > 1 || u("thread_joined") > 1 || u("poll_cycles") > 3000 {
		return nil, errors.New("G92 session bounds differ")
	}
	if u("state") == 0 && (u("starts") != 0 || u("hardware_calls") != 0 || u("result_ready") != 0) {
		return nil, errors.New("idle session already consumed")
	}
	if u("state") != 0 && u("starts") != 1 {
		return nil, errors.New("session start count differs")
	}
	if u("thread_joined") != 0 && u("state") != 3 {
		return nil, errors.New("running session claims joined thread")
	}
	if u("outcome") == 1 || u("outcome") == 2 || u("outcome") == 4 {
		if u("state") != 3 || u("result_ready") != 1 {
			return nil, errors.New("terminal outcome without frozen result")
		}
	}
	return v, nil
}
