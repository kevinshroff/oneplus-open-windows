// Fixed local sensor acquisition and read-only kernel-consumer qualification.
// G167/G160 stay loaded only until their frozen results are consumed by G179.
package main

import (
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
	"strings"
	"time"
)

var observerFiles string

const base = `X:\OpenG17\payloads`

func main() {
	out := map[string]any{"ok": false, "PMIC_configuration_writes": 0, "GLINK_requests": 0, "results": map[string]any{}, "steps": []any{}}
	var receipt *os.File
	defer func() {
		if e := recover(); e != nil {
			out["error"] = fmt.Sprint(e)
		}
		if receipt != nil {
			json.NewEncoder(receipt).Encode(out)
			receipt.Sync()
			receipt.Close()
		}
		json.NewEncoder(os.Stdout).Encode(out)
		if out["ok"] != true {
			os.Exit(1)
		}
	}()
	must := func(e error) {
		if e != nil {
			panic(e)
		}
	}
	must(winPEGuard())
	if len(os.Args) != 2 || !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(os.Args[1]) {
		panic("fixed observation nonce required")
	}
	self, e := os.Executable()
	must(e)
	if !strings.EqualFold(filepath.Dir(self), base) {
		panic("fixed payload directory")
	}
	var pins map[string]string
	encoded, e := base64.StdEncoding.DecodeString(observerFiles)
	must(e)
	must(json.Unmarshal(encoded, &pins))
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
	nonce := os.Args[1]
	receipt, e = os.OpenFile(filepath.Join(base, "G179-observe-"+nonce+".json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(e)
	out["utc_begin"] = time.Now().UTC().Format(time.RFC3339Nano)
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
	v := call("G179", "manage", "status")
	if v["service_absent"] != true {
		panic("consumer already loaded")
	}
	v = call("G179", "manage", "load")
	if v["service_status"].(map[string]any)["State"] != float64(4) {
		panic("consumer not running")
	}
	v = call("G179", "client", "status")
	initial := v["status_before"].(map[string]any)
	if initial["attempts"] != float64(0) || initial["map_calls"] != float64(0) || initial["safe_to_unload"] != float64(1) {
		panic("consumer initial state")
	}
	results := out["results"].(map[string]any)
	raws := map[string][]byte{}
	for _, c := range []string{"G167", "G160"} {
		v = call(c, "manage", "status")
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
		path := filepath.Join(base, c+"-result-"+nonce+".bin")
		v = call(c, "client", "read", nonce, path)
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
		results[c] = map[string]any{"result": r, "path": path, "nonce": nonce, "capture_sha256": v["sha256"], "retired": false}
	}
	path := filepath.Join(base, "G179-result-"+nonce+".bin")
	v = call("G179", "client", "read", nonce, path)
	consumer := v["result"].(map[string]any)
	if consumer["valid_at_acquisition"] != true || consumer["fresh_at_snapshot"] != true {
		panic("kernel consumer did not validate fresh physical data")
	}
	health := consumer["health"].(map[string]any)
	if health["nonce"] != nonce || health["config_begin_100ns"] != float64(binary.LittleEndian.Uint64(raws["G167"][104:])) || health["config_end_100ns"] != float64(binary.LittleEndian.Uint64(raws["G167"][112:])) || health["gauge_end_100ns"] != float64(binary.LittleEndian.Uint64(raws["G160"][56:])) {
		panic("native provider interrupt-time binding")
	}
	cfg := results["G167"].(map[string]any)["result"].(map[string]any)["telemetry"].(map[string]any)
	if health["FloatMv"] != cfg["float_voltage_mV"] || health["FastMa"] != cfg["fast_current_mA"] || health["Enable"] != float64(raws["G167"][184+7*8+6]&1) || health["StateFirst"] != float64(raws["G167"][184+5*8]&7) || health["StateLast"] != float64(raws["G167"][184+18*8]&7) {
		panic("kernel config data differs")
	}
	original := results["G160"].(map[string]any)["result"].(map[string]any)["gauges"].([]any)
	measured := health["gauges"].([]any)
	fields := map[string]int{"VoltageMv": 4, "TemperatureDeciK": 3, "CurrentRaw": 8, "Flags": 5, "RemainingMah": 6, "FullMah": 7, "ChargePercent": 9}
	for i := 0; i < 2; i++ {
		words := original[i].(map[string]any)["raw_words"].([]any)
		for name, index := range fields {
			if measured[i].(map[string]any)[name] != words[index] {
				panic("kernel gauge data differs: " + name)
			}
		}
	}
	raw, e := os.ReadFile(path)
	must(e)
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != v["sha256"] {
		panic("consumer raw hash")
	}
	results["G179"] = map[string]any{"result": consumer, "path": path, "nonce": nonce, "capture_sha256": v["sha256"], "raw_physical_values_match_providers": true, "retired": false}
	for _, c := range []string{"G160", "G167", "G179"} {
		v = call(c, "manage", "unload")
		if v["service_deleted"] != true {
			panic("retain unretired service")
		}
		v = call(c, "manage", "status")
		if v["service_absent"] != true {
			panic("retirement not independently observed")
		}
		results[c].(map[string]any)["retired"] = true
	}
	out["utc_end"] = time.Now().UTC().Format(time.RFC3339Nano)
	out["ok"] = true
}
