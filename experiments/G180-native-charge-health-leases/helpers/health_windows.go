// Fixed local G180 health acquisition. No values, properties, addresses or
// durations are accepted. Providers remain loaded until kernel RESULT work ends.
package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const base = `X:\OpenG17\payloads`

var healthFiles string

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func ownerIO(mode string, prior map[string]any, nonce uint64) ([]byte, map[string]any) {
	cookie, id := uint64(0), uint64(0)
	if mode != "snapshot" {
		var e error
		cookie, e = strconv.ParseUint(prior["cookie"].(string), 16, 64)
		must(e)
		id = prior["last_command_id"].(uint64) + 1
		if id == 0 {
			panic("command IDs exhausted")
		}
	}
	in, code, e := request(mode, cookie, id, nonce)
	must(e)
	name, e := syscall.UTF16PtrFromString(`\\.\OpenG180`)
	must(e)
	access := uint32(syscall.GENERIC_READ)
	if mode != "snapshot" {
		access |= syscall.GENERIC_WRITE
	}
	h, e := syscall.CreateFile(name, access, 0, nil, syscall.OPEN_EXISTING, 0, 0)
	must(e)
	defer syscall.CloseHandle(h)
	b := make([]byte, abi.Size)
	var got uint32
	must(syscall.DeviceIoControl(h, code, &in[0], uint32(len(in)), &b[0], uint32(len(b)), &got, nil))
	if got != uint32(len(b)) {
		panic("owner output length")
	}
	s, e := decode(b)
	must(e)
	return b, s
}
func clean(s map[string]any) bool {
	v := s["state"].(map[string]any)
	return s["Running"] == uint32(1) && s["MapsLive"] == uint32(2) && s["NativeFault"] == uint32(0) && v["Phase"] == uint32(3) && v["Fault"] == uint32(0) && v["RpcUncertain"] == uint32(0) && v["TransportUncertain"] == uint32(0)
}
func main() {
	out := map[string]any{"ok": false, "generic_commands": 0, "results": map[string]any{}, "steps": []any{}}
	var journal *os.File
	ownerVerified := false
	failed := false
	record := func(v any) {
		if journal != nil {
			must(json.NewEncoder(journal).Encode(v))
			must(journal.Sync())
		}
	}
	defer func() {
		if e := recover(); e != nil {
			failed = true
			out["error"] = fmt.Sprint(e)
		}
		if failed && ownerVerified {
			func() {
				defer func() {
					if e := recover(); e != nil {
						out["stop_error"] = fmt.Sprint(e)
					}
				}()
				_, s := ownerIO("snapshot", nil, 0)
				v := s["state"].(map[string]any)
				if clean(s) && v["BatchActive"] == uint32(1) && v["PulseAttempted"] == uint32(1) && v["StopPulseRequested"] == uint32(0) {
					record(map[string]any{"intent": "stop-pulse-after-helper-error", "command_id": s["last_command_id"].(uint64) + 1})
					_, stopped := ownerIO("stop-pulse", s, 0)
					out["error_stop_snapshot"] = stopped
				}
			}()
		}
		if journal != nil {
			json.NewEncoder(journal).Encode(out)
			journal.Sync()
			journal.Close()
		}
		json.NewEncoder(os.Stdout).Encode(out)
		if out["ok"] != true {
			os.Exit(1)
		}
	}()
	must(winPEGuard())
	if len(os.Args) != 3 || !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(os.Args[2]) {
		panic("board-fv|restart-pulse|health-renew|observe opaque-nonce")
	}
	mode, nonceText := os.Args[1], os.Args[2]
	if mode != "board-fv" && mode != "restart-pulse" && mode != "health-renew" && mode != "observe" {
		panic("fixed operation required")
	}
	nonce, e := strconv.ParseUint(nonceText, 16, 64)
	must(e)
	if nonce == 0 {
		panic("zero nonce")
	}
	self, e := os.Executable()
	must(e)
	if !strings.EqualFold(filepath.Dir(self), base) {
		panic("fixed payload directory")
	}
	var pins map[string]string
	b, e := base64.StdEncoding.DecodeString(healthFiles)
	must(e)
	must(json.Unmarshal(b, &pins))
	if len(pins) != 10 {
		panic("exact10fixed files")
	}
	for n, h := range pins {
		b, e := os.ReadFile(filepath.Join(base, n))
		must(e)
		v := sha256.Sum256(b)
		if hex.EncodeToString(v[:]) != h {
			panic("file identity: " + n)
		}
	}
	journal, e = os.OpenFile(filepath.Join(base, "G180-health-"+nonceText+".jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(e)
	out["mode"] = mode
	out["nonce"] = nonceText
	out["utc_begin"] = time.Now().UTC().Format(time.RFC3339Nano)
	_, initial := ownerIO("snapshot", nil, 0)
	if !clean(initial) || initial["HealthBusy"] != uint32(0) || initial["ProviderUncertain"] != uint32(0) {
		panic("retain owner; no sensor acquisition")
	}
	ownerVerified = true
	state := initial["state"].(map[string]any)
	monitor := initial["health_monitor"].(map[string]any)
	if mode != "observe" && monitor["Fault"] != uint32(0) {
		panic("health fault latched")
	}
	switch mode {
	case "board-fv":
		if state["BoardFvAttempted"] != uint32(0) || state["BatchActive"] != uint32(0) {
			panic("FV already consumed or busy")
		}
	case "restart-pulse":
		if state["BoardFvAcked"] != uint32(1) || state["PulseAttempted"] != uint32(0) || state["BatchActive"] != uint32(0) {
			panic("restart not admitted")
		}
	case "health-renew":
		now, until := initial["now_us"].(uint64), state["PulseUntilUs"].(uint64)
		if state["BatchActive"] != uint32(1) || state["PulseEnableAcked"] != uint32(1) || state["StopPulseRequested"] != uint32(0) || until <= now || until-now < 10000000 {
			panic("too late or no active health interval")
		}
	case "observe":
		if state["BatchActive"] != uint32(0) {
			panic("settled observation required")
		}
	}
	out["owner_before"] = initial
	record(map[string]any{"intent": "fixed-paired-physical-capture", "mode": mode, "nonce": nonceText})
	call := func(c, tool string, args ...string) map[string]any {
		b, e := exec.Command(filepath.Join(base, c+"-"+tool+".exe"), args...).Output()
		if e != nil {
			if x, ok := e.(*exec.ExitError); ok {
				panic(fmt.Sprintf("%s/%s: %v %s %s", c, tool, e, b, x.Stderr))
			}
			panic(e)
		}
		var v map[string]any
		must(json.Unmarshal(b, &v))
		if v["ok"] != true {
			panic(string(b))
		}
		out["steps"] = append(out["steps"].([]any), map[string]any{"campaign": c, "tool": tool, "operation": args[0], "ok": true})
		return v
	}
	results := out["results"].(map[string]any)
	raws := map[string][]byte{}
	for _, c := range []string{"G167", "G160"} {
		v := call(c, "manage", "status")
		if v["service_absent"] != true {
			panic("provider already loaded")
		}
		v = call(c, "manage", "load")
		if v["service_status"].(map[string]any)["State"] != float64(4) {
			panic("provider not running")
		}
		v = call(c, "client", "status")
		s := v["status_before"].(map[string]any)
		if s["attempts"] != float64(0) || s["map_calls"] != float64(0) || s["firmware_match"] != float64(1) {
			panic("provider initial state")
		}
		path := filepath.Join(base, c+"-result-"+nonceText+".bin")
		v = call(c, "client", "read", nonceText, path)
		r := v["result"].(map[string]any)
		if v["read_submitted"] != true || r["operation_code"] != float64(0) || r["native_guard"] != float64(0) {
			panic("retain failed provider context")
		}
		if c == "G160" {
			if r["uncertain_mask"] != float64(0) || r["clean_mask"] != float64(3) || r["restored_mask"] != float64(3) || r["commands"] != float64(46) {
				panic("retain uncertain gauge")
			}
		} else {
			if r["uncertain_read"] != false || r["post_routes_verified"] != float64(1) || r["commands"] != float64(19) {
				panic("retain uncertain config")
			}
		}
		raw, e := os.ReadFile(path)
		must(e)
		h := sha256.Sum256(raw)
		if hex.EncodeToString(h[:]) != v["sha256"] {
			panic("provider raw hash")
		}
		raws[c] = raw
		results[c] = map[string]any{"result": r, "path": path, "nonce": nonceText, "capture_sha256": v["sha256"], "retired": false}
	}
	_, prior := ownerIO("snapshot", nil, 0)
	if !clean(prior) || prior["HealthBusy"] != uint32(0) {
		panic("owner changed during capture")
	}
	var finalBytes []byte
	final := prior
	if mode != "observe" {
		id := prior["last_command_id"].(uint64) + 1
		record(map[string]any{"intent": mode, "cookie": prior["cookie"], "command_id": id, "health_nonce": nonceText})
		finalBytes, final = ownerIO(mode, prior, nonce)
		deadline := time.Now().Add(15 * time.Second)
		for final["HealthBusy"] == uint32(1) && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
			finalBytes, final = ownerIO("snapshot", nil, 0)
		}
		if final["HealthBusy"] != uint32(0) || final["ProviderUncertain"] != uint32(0) {
			panic("retain providers until work/transport is resolved")
		}
		if !clean(final) {
			panic("retain uncertain charge owner")
		}
		m := final["health_monitor"].(map[string]any)
		if final["HealthCode"] == uint32(0) {
			if m["LastNonce"] != nonce || m["fresh_at_snapshot"] != true || m["pending_command_id"] != id || m["pending_nonce"] != nonceText {
				panic("kernel health operation binding")
			}
			h := m["last_accepted_health"].(map[string]any)
			if h["ConfigBegin100ns"] != binary.LittleEndian.Uint64(raws["G167"][104:]) || h["ConfigEnd100ns"] != binary.LittleEndian.Uint64(raws["G167"][112:]) || h["GaugeEnd100ns"] != binary.LittleEndian.Uint64(raws["G160"][56:]) {
				panic("kernel timestamp binding")
			}
			cfg := results["G167"].(map[string]any)["result"].(map[string]any)["telemetry"].(map[string]any)
			if h["FloatMv"] != uint32(cfg["float_voltage_mV"].(float64)) || h["FastMa"] != uint32(cfg["fast_current_mA"].(float64)) || h["Enable"] != uint32(raws["G167"][184+7*8+6]&1) || h["StateFirst"] != uint32(raws["G167"][184+5*8]&7) || h["StateLast"] != uint32(raws["G167"][184+18*8]&7) {
				panic("kernel config binding")
			}
			gauges := h["gauges"].([]map[string]any)
			fields := map[string]int{"VoltageMv": 4, "TemperatureDeciK": 3, "CurrentRaw": 8, "Flags": 5, "RemainingMah": 6, "FullMah": 7, "ChargePercent": 9}
			for i := 0; i < 2; i++ {
				for name, index := range fields {
					if gauges[i][name] != binary.LittleEndian.Uint32(raws["G160"][200+40*i+4*index:]) {
						panic("kernel gauge binding: " + name)
					}
				}
			}
		}
	}
	for _, c := range []string{"G160", "G167"} {
		v := call(c, "manage", "unload")
		if v["service_deleted"] != true {
			panic("retain unretired service")
		}
		v = call(c, "manage", "status")
		if v["service_absent"] != true {
			panic("retirement not independently observed")
		}
		results[c].(map[string]any)["retired"] = true
	}
	if mode != "observe" {
		path := filepath.Join(base, "G180-health-"+nonceText+".bin")
		f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		must(e)
		_, e = f.Write(finalBytes)
		must(e)
		must(f.Sync())
		must(f.Close())
		hash := sha256.Sum256(finalBytes)
		out["owner_result_path"] = path
		out["owner_result_sha256"] = hex.EncodeToString(hash[:])
		out["kernel_sensor_binding_passed"] = final["HealthCode"] == uint32(0)
		if final["HealthCode"] != uint32(0) {
			out["owner_after"] = final
			panic("kernel health policy refused; fault retained")
		}
	} else {
		cfg := raws["G167"]
		if cfg[184+7*8+6]&1 != 0 || cfg[184+5*8]&7 != 7 || cfg[184+18*8]&7 != 7 {
			panic("post-off hardware is not disabled")
		}
	}
	if mode == "observe" {
		finalBytes, final = ownerIO("snapshot", nil, 0)
	}
	archivePath := filepath.Join(base, "G180-capture-"+nonceText+".zip")
	archive, e := os.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(e)
	z := zip.NewWriter(archive)
	for _, entry := range []struct {
		name string
		data []byte
	}{{"G167.bin", raws["G167"]}, {"G160.bin", raws["G160"]}, {"G180.bin", finalBytes}} {
		f, e := z.Create(entry.name)
		must(e)
		_, e = f.Write(entry.data)
		must(e)
	}
	must(z.Close())
	must(archive.Sync())
	must(archive.Close())
	archiveBytes, e := os.ReadFile(archivePath)
	must(e)
	digest := sha256.Sum256(archiveBytes)
	out["capture_archive"] = map[string]any{"path": archivePath, "sha256": hex.EncodeToString(digest[:]), "bytes": len(archiveBytes)}
	out["owner_after"] = final
	out["utc_end"] = time.Now().UTC().Format(time.RFC3339Nano)
	out["ok"] = true
}
