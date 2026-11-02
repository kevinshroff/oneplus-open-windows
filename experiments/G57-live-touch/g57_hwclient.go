// SPDX-License-Identifier: MIT
// Fixed project interface only. Persist the large trial before decoding it;
// the controller's stdout cap must never truncate native evidence.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func hardware(mode, ready, dest string) (any, error) {
	paths, e := interfaces(&sourceGUID)
	if e != nil {
		return nil, e
	}
	if len(paths) != 1 {
		return nil, errors.New("expected exactly one G57 source interface")
	}
	h, e := syscall.CreateFile(wide(paths[0]), 0x80000000, 0, nil, 3, 0, 0)
	if e != nil {
		return nil, e
	}
	defer syscall.CloseHandle(h)
	query := func(code uint32, n int) ([]byte, error) {
		in := make([]byte, 16)
		binary.LittleEndian.PutUint32(in, 16)
		binary.LittleEndian.PutUint32(in[4:], 1)
		binary.LittleEndian.PutUint64(in[8:], magic)
		if code == 0x226400 {
			copy(in[8:], []byte("OPG57HD1"))
		}
		out := make([]byte, n)
		var got uint32
		e := syscall.DeviceIoControl(h, code, &in[0], 16, &out[0], uint32(n), &got, nil)
		if e != nil {
			return nil, e
		}
		if got != uint32(n) {
			return nil, errors.New("hardware byte count differs")
		}
		return out, nil
	}
	b, e := query(0x226000, 80)
	if e != nil {
		return nil, e
	}
	identity, e := parseHardwareStatus(b)
	if e != nil {
		return nil, e
	}
	if e = checkHardwareStatus(identity); e != nil {
		return nil, e
	}
	switch mode {
	case "hw-status":
		return identity, nil
	case "snapshot":
		b, e = query(0x226004, 288)
		if e != nil {
			return nil, e
		}
		s, e := parseHardwareStatus(b)
		if e != nil {
			return nil, e
		}
		if e = checkHardwareStatus(s); e != nil {
			return nil, e
		}
		if binary.LittleEndian.Uint32(b[80:]) != 50 {
			return nil, errors.New("fixed register count differs")
		}
		rows := make([]map[string]any, 0, 50)
		for i, f := range registerFields {
			rows = append(rows, map[string]any{"name": f.Name, "address": fmt.Sprintf("0x%x", f.Address), "value": binary.LittleEndian.Uint32(b[88+i*4:])})
		}
		return map[string]any{"status": s, "values": rows, "register_writes": 0}, nil
	case "pmic":
		b, e = query(0x226008, 1728)
		if e != nil {
			return nil, e
		}
		return decodePMIC(b)
	case "live":
		r, e := receiverGuard(ready)
		if e != nil {
			return nil, e
		}
		base := filepath.Join(`X:\OpenG17\payloads`, "G57-receiver-"+r.Token)
		if !strings.EqualFold(filepath.Clean(ready), base+"-ready.json") || !strings.EqualFold(filepath.Clean(dest), base+"-power.bin") {
			return nil, errors.New("only exact nonce-bound project evidence paths are allowed")
		}
		f, e := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return nil, e
		}
		defer f.Close()
		// The path is reserved before any powered attempt. Never repeat this call
		// after timeout or file/transport failure; observe the recorded command.
		b, e = query(0x22600c, 959896)
		if e != nil {
			return nil, e
		}
		n, e := f.Write(b)
		if e != nil {
			return nil, e
		}
		if n != len(b) {
			return nil, errors.New("short native evidence write")
		}
		if e = f.Sync(); e != nil {
			return nil, e
		}
		sum := sha256.Sum256(b)
		v, e := decodePower(b)
		if e != nil {
			return nil, e
		}
		t := v["touch"].(map[string]any)
		poll := t["poll"].(map[string]any)
		summary := map[string]any{"path": dest, "bytes": len(b), "sha256": hex.EncodeToString(sum[:]), "operation_code": v["operation_code"], "restore_error": v["restore_error"], "restored": v["restored"], "fixed_registers_unchanged": v["fixed_registers_unchanged"], "attempt": v["attempt"], "touch_code": t["operation_code"], "poll_code": poll["operation_code"], "cycles": poll["cycles"], "contacts": poll["contact_records"], "idle": poll["idle_records"], "header_retries": poll["header_retries"], "headers_recovered": poll["headers_recovered"], "irq_read_attempts": poll["irq_read_attempts"], "owned_receiver_verified_before_attempt": r}
		stateBytes, stateError := query(0x226400, 160)
		if stateError != nil {
			return summary, stateError
		}
		state, stateError := parseStatus(stateBytes)
		if stateError != nil {
			return summary, stateError
		}
		summary["source_status"] = state
		if state["live_complete"] != uint32(1) || state["live_error"] != uint32(0) || state["accepted_mask"] != uint32(0) || state["stop_attempts"] != uint32(1) {
			return summary, errors.New("Windows live input or final release failed; saved hardware evidence is preserved")
		}
		if v["operation_code"] != uint32(0) || v["restore_error"] != uint32(0) || v["restored"] != uint32(1) || v["fixed_registers_unchanged"] != uint32(1) || poll["operation_code"] != uint32(0) || poll["limit"] != uint32(100) || poll["cycles"] != uint32(100) {
			return summary, errors.New("live episode or restoration failed; inspect saved evidence without replay")
		}
		return summary, nil
	}
	return nil, errors.New("unsupported hardware mode")
}
