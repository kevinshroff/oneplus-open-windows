package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func keyIO(h syscall.Handle, code uint32, q []byte, n int) ([]byte, error) {
	b := make([]byte, n)
	var got uint32
	e := syscall.DeviceIoControl(h, code, &q[0], uint32(len(q)), &b[0], uint32(n), &got, nil)
	if e != nil {
		return nil, e
	}
	if got != uint32(n) {
		return nil, fmt.Errorf("short result %d", got)
	}
	return b, nil
}
func main() {
	result := map[string]any{"ok": false, "sample_submitted": false, "retirement_submitted": false}
	defer func() {
		if e := recover(); e != nil {
			result["error"] = fmt.Sprint(e)
		}
		json.NewEncoder(os.Stdout).Encode(result)
		if result["ok"] != true {
			os.Exit(1)
		}
	}()
	must := func(e error) {
		if e != nil {
			panic(e)
		}
	}
	must(fullOSGuard())
	if len(os.Args) < 2 {
		panic("status | bus | state | sample count nonce16 path | result nonce16 path | retire nonce16 path")
	}
	mode := os.Args[1]
	var nonce uint64
	var count uint64
	var nonceText, path string
	var e error
	switch mode {
	case "status", "bus", "state":
		if len(os.Args) != 2 {
			panic("query arguments")
		}
	case "sample":
		if len(os.Args) != 5 {
			panic("sample arguments")
		}
		count, e = strconv.ParseUint(os.Args[2], 10, 32)
		must(e)
		if count < 1 || count > 1024 {
			panic("sample count")
		}
		nonceText, path = os.Args[3], os.Args[4]
	case "result", "retire":
		if len(os.Args) != 4 {
			panic("capture arguments")
		}
		nonceText, path = os.Args[2], os.Args[3]
	default:
		panic("unknown mode")
	}
	if nonceText != "" {
		nonce, e = strconv.ParseUint(nonceText, 16, 64)
		must(e)
		if len(nonceText) != 16 || nonce == 0 || strings.ToLower(nonceText) != nonceText {
			panic("nonce")
		}
		want := "G100-result-" + nonceText + ".bin"
		recovered := "G100-result-" + nonceText + "-recovered.bin"
		if !strings.EqualFold(filepath.Dir(path), `C:\OpenG81\payloads`) || (filepath.Base(path) != want && filepath.Base(path) != recovered) {
			panic("exclusive project result path")
		}
	}
	ptr, _ := syscall.UTF16PtrFromString(`\\.\OpenG100Keys`)
	h, e := syscall.CreateFile(ptr, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, 0, 0)
	must(e)
	defer syscall.CloseHandle(h)
	if mode == "bus" {
		b, e := keyIO(h, 0x22680c, keyRequest(0, 0), 56)
		must(e)
		if le.Uint32(b) != 56 || le.Uint32(b[4:]) != 1 {
			panic("bus ABI")
		}
		v := map[string]any{}
		for i, n := range []string{"ready", "poisoned", "owners", "peak_owners"} {
			v[n] = le.Uint32(b[8+4*i:])
		}
		for i, n := range []string{"acquires", "releases", "timeouts", "denied"} {
			v[n] = le.Uint64(b[24+8*i:])
		}
		result["bus"] = v
		result["ok"] = true
		return
	}
	stateBytes, e := keyIO(h, 0x226814, keyRequest(0, 0), 64)
	must(e)
	state, e := decodeCaptureState(stateBytes)
	must(e)
	result["capture_state_before"] = state
	if mode == "state" {
		result["ok"] = true
		return
	}
	if mode == "retire" {
		if state.CurrentNonce != nonce || (state.Phase != 2 && !(state.Phase == 0 && state.LastRetiredNonce == nonce)) {
			panic("capture is not awaiting this acknowledgment")
		}
		b, sum, e := durableCapture(path, nonce)
		must(e)
		q, e := retireRequest(nonce, b)
		must(e)
		result["path"], result["sha256"], result["bytes"] = path, sum, len(b)
		result["retirement_submitted"] = true
		afterBytes, e := keyIO(h, 0x22e810, q, 64)
		must(e)
		after, e := decodeCaptureState(afterBytes)
		must(e)
		must(validateRetirement(state, after, nonce))
		result["capture_state_after"] = after
		result["idempotent_acknowledgment"] = state.Phase == 0
		result["ok"] = true
		return
	}
	b, e := keyIO(h, 0x226800, keyRequest(0, 0), 80)
	must(e)
	status, e := decodeStatus(b)
	must(e)
	result["status_before"] = status
	if mode == "status" {
		result["ok"] = true
		return
	}
	if status["kernel_build"] != uint32(26300) || status["processors"] != uint32(8) || status["IRQL"] != uint32(0) || status["firmware_match"] != uint32(1) || status["firmware_bytes"] != uint32(576) {
		panic("qualified platform required")
	}
	if mode == "sample" && (state.Phase != 0 || state.Captures >= state.Slots || status["attempts"] != uint32(0) || status["map_calls"] != uint32(0) || status["fault"] != uint32(0)) {
		panic("capture slot unavailable; preserve the frozen result")
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(e)
	defer f.Close()
	code := uint32(0x226808)
	if mode == "sample" {
		code = 0x22e804
		result["sample_submitted"] = true
	}
	b, e = keyIO(h, code, keyRequest(nonce, uint32(count)), captureBytes)
	must(e)
	written, e := f.Write(b)
	must(e)
	if written != len(b) {
		panic("short capture file write")
	}
	must(f.Sync())
	must(f.Close())
	sum := sha256.Sum256(b)
	result["path"], result["sha256"], result["bytes"] = path, hex.EncodeToString(sum[:]), len(b)
	decoded, e := decodeCapture(b, nonce)
	must(e)
	result["result"] = decoded
	result["ok"] = true
}
