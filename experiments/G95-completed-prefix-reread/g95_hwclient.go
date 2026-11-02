// SPDX-License-Identifier: MIT
// Fixed project interface only. Persist the large trial before decoding it;
// the controller's stdout cap must never truncate native evidence.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func hardware(mode, ready, dest string) (any, error) {
	paths, e := interfaces(&sourceGUID)
	if e != nil {
		return nil, e
	}
	if len(paths) != 1 {
		return nil, errors.New("expected exactly one G95 source interface")
	}
	h, e := syscall.CreateFile(wide(paths[0]), 0xc0000000, 0, nil, 3, 0, 0)
	if e != nil {
		return nil, e
	}
	defer func() {
		if h != 0 && h != syscall.InvalidHandle {
			syscall.CloseHandle(h)
		}
	}()
	query := func(code uint32, n int) ([]byte, error) {
		in := make([]byte, 16)
		binary.LittleEndian.PutUint32(in, 16)
		binary.LittleEndian.PutUint32(in[4:], 1)
		binary.LittleEndian.PutUint64(in[8:], magic)
		if code == 0x226400 || code == 0x226404 || code == 0x22a408 || code == 0x22a40c {
			copy(in[8:], []byte("OPG95HD1"))
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
	case "session":
		b, e = query(0x226404, 96)
		if e != nil {
			return nil, e
		}
		return decodeSession(b)
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
	case "live", "live-stop", "live-close", "hardware-episode":
		var r ReceiverReady
		headless := mode == "hardware-episode"
		if headless {
			// Explicit finite hardware qualification. No claim of a foreground
			// Windows consumer is made, and the live receiver guard is unchanged.
			if len(ready) != 32 {
				return nil, errors.New("fresh 32-hex hardware token required")
			}
			for _, c := range ready {
				if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
					return nil, errors.New("hardware token")
				}
			}
			r = ReceiverReady{Token: ready, TrialMode: "complete"}
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			awake, _, err := kernel.NewProc("SetThreadExecutionState").Call(0x80000003)
			if awake == 0 {
				return nil, fmt.Errorf("display lease: %v", err)
			}
			defer kernel.NewProc("SetThreadExecutionState").Call(0x80000000)
		} else {
			r, e = receiverGuard(ready)
			if e != nil {
				return nil, e
			}
		}
		trialMode := "complete"
		if mode == "live-stop" {
			trialMode = "stop"
		}
		if mode == "live-close" {
			trialMode = "close"
		}
		if r.TrialMode != trialMode {
			return nil, errors.New("receiver and source session mode differ")
		}
		beforeBytes, e := query(0x226404, 96)
		if e != nil {
			return nil, e
		}
		beforeSession, e := decodeSession(beforeBytes)
		if e != nil {
			return nil, e
		}
		if beforeSession["state"] != uint32(0) || beforeSession["starts"] != uint32(0) {
			return nil, errors.New("G95 session is already consumed; observe it without restarting")
		}
		base := filepath.Join(`C:\OpenG81\payloads`, "G95-receiver-"+r.Token)
		if headless {
			base = filepath.Join(`C:\OpenG81\payloads`, "G95-hardware-"+r.Token)
		}
		if (!headless && !strings.EqualFold(filepath.Clean(ready), base+"-ready.json")) || !strings.EqualFold(filepath.Clean(dest), base+"-power.bin") {
			return nil, errors.New("only exact nonce-bound project evidence paths are allowed")
		}
		f, e := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return nil, e
		}
		defer f.Close()
		// The path is reserved before any powered attempt. Never repeat this call
		// after timeout or file/transport failure; observe the recorded command.
		if _, e = query(0x22a408, 96); e != nil {
			return nil, e
		}
		deadline := time.Now().Add(52 * time.Second)
		stopped := false
		var stopPhase uint32
		var session map[string]any
		armed := false
		for {
			raw, err := query(0x226404, 96)
			if err != nil {
				return nil, err
			}
			session, err = decodeSession(raw)
			if err != nil {
				return nil, err
			}
			if !armed && session["state"] == uint32(2) && session["poll_cycles"].(uint32) >= 1 {
				row := map[string]any{"token": r.Token, "receiver_pid": r.PID, "admin_pid": os.Getpid(), "poll_cycles": session["poll_cycles"], "session": session, "meaning": "first validated native polling cycle completed"}
				raw, _ := json.Marshal(row)
				if err := os.WriteFile(base+"-armed.json", raw, 0600); err != nil {
					return nil, err
				}
				armed = true
			}
			if session["state"] == uint32(3) {
				break
			}
			if trialMode != "complete" && !stopped && session["phase"] == uint32(8) {
				stopPhase = 8
				stopped = true
				if trialMode == "stop" {
					if _, err = query(0x22a40c, 96); err != nil {
						return nil, err
					}
				} else {
					old := h
					h = syscall.InvalidHandle
					if err = syscall.CloseHandle(old); err != nil {
						return nil, err
					}
					h, err = syscall.CreateFile(wide(paths[0]), 0xc0000000, 0, nil, 3, 0, 0)
					if err != nil {
						return nil, err
					}
				}
				continue
			}
			if time.Now().After(deadline) {
				return nil, errors.New("G95 observation deadline expired; helper close requests stop, do not rearm")
			}
			time.Sleep(25 * time.Millisecond)
		}
		b, e = query(0x22600c, 969808)
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
		summary := map[string]any{"path": dest, "bytes": len(b), "sha256": hex.EncodeToString(sum[:]), "operation_code": v["operation_code"], "restore_error": v["restore_error"], "restored": v["restored"], "fixed_registers_unchanged": v["fixed_registers_unchanged"], "attempt": v["attempt"], "touch_code": t["operation_code"], "poll_code": poll["operation_code"], "cycles": poll["cycles"], "contacts": poll["contact_records"], "idle": poll["idle_records"], "read_retries": poll["read_retries"], "prefixes_recovered": poll["prefixes_recovered"], "irq_read_attempts": poll["irq_read_attempts"], "owned_receiver_verified_before_attempt": r}
		stateBytes, stateError := query(0x226400, 160)
		if stateError != nil {
			return summary, stateError
		}
		state, stateError := parseStatus(stateBytes)
		if stateError != nil {
			return summary, stateError
		}
		summary["foreground_consumer_qualified"] = !headless
		summary["qualification_mode"] = mode
		summary["source_status"] = state
		sessionBytes, sessionError := query(0x226404, 96)
		if sessionError != nil {
			return summary, sessionError
		}
		session, sessionError = decodeSession(sessionBytes)
		if sessionError != nil {
			return summary, sessionError
		}
		summary["driver_session"] = session
		summary["session_before"] = beforeSession
		summary["trial_mode"] = trialMode
		summary["stop_at_phase"] = stopPhase
		if session["starts"] != uint32(1) || session["hardware_calls"] != uint32(1) || session["result_ready"] != uint32(1) || session["thread_joined"] != uint32(1) {
			return summary, errors.New("owner count, frozen result or actual thread join differs")
		}
		if trialMode != "complete" {
			expectedReason := uint32(1)
			if trialMode == "close" {
				expectedReason = 2
			}
			if !stopped || session["outcome"] != uint32(2) || session["stop_reason"] != expectedReason || session["stop_seen"] == uint32(0) || poll["cycles"] != uint32(0) || poll["wire_count"] != uint32(0) || t["operation_code"] != uint32(21) || v["operation_code"] != uint32(6) {
				return summary, errors.New("startup-window cancellation did not match; saved evidence retained")
			}
			if v["restore_error"] != uint32(0) || v["restored"] != uint32(1) || v["safe_release"] != uint32(1) || v["fixed_registers_unchanged"] != uint32(1) || t["restored"] != uint32(1) || t["restore_error"] != uint32(0) || state["reports_submitted"] != uint32(0) || state["accepted_mask"] != uint32(0) || state["stop_attempts"] != uint32(1) {
				return summary, errors.New("cancellation restoration or zero-input contract failed; inspect saved evidence")
			}
			return summary, nil
		}
		if session["outcome"] != uint32(1) {
			return summary, errors.New("full session did not complete; inspect saved evidence")
		}

		if state["live_complete"] != uint32(1) || state["live_error"] != uint32(0) || state["accepted_mask"] != uint32(0) || state["stop_attempts"] != uint32(1) {
			return summary, errors.New("Windows live input or final release failed; saved hardware evidence is preserved")
		}
		if v["operation_code"] != uint32(0) || v["restore_error"] != uint32(0) || v["restored"] != uint32(1) || v["fixed_registers_unchanged"] != uint32(1) || poll["operation_code"] != uint32(0) || poll["limit"] != uint32(2500) || poll["cycles"] != uint32(2500) {
			return summary, errors.New("live episode or restoration failed; inspect saved evidence without replay")
		}
		return summary, nil
	}
	return nil, errors.New("unsupported hardware mode")
}
