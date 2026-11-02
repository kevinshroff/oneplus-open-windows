// Fixed read-only G167/G160 orchestration on the admitted WinPE target.
// Child managers retain their exact driver/firmware/source admission checks.
package main

import (
	"crypto/sha256"
	"encoding/base64"
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

var observerFiles string // exact six audited files, built in
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
		panic("fixed 16-hex observation nonce required")
	}
	self, e := os.Executable()
	must(e)
	if !strings.EqualFold(filepath.Dir(self), base) {
		panic("fixed project payload directory")
	}
	var pins map[string]string
	encoded, e := base64.StdEncoding.DecodeString(observerFiles)
	must(e)
	must(json.Unmarshal(encoded, &pins))
	if len(pins) != 6 {
		panic("observer input pins")
	}
	for n, h := range pins {
		b, e := os.ReadFile(filepath.Join(base, n))
		must(e)
		v := sha256.Sum256(b)
		if hex.EncodeToString(v[:]) != h {
			panic("observer file identity: " + n)
		}
	}
	nonce := os.Args[1]
	receipt, e = os.OpenFile(filepath.Join(base, "G170-observe-"+nonce+".json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	must(e)
	out["utc_begin"] = time.Now().UTC().Format(time.RFC3339Nano)
	call := func(c, which string, args ...string) map[string]any {
		b, e := exec.Command(filepath.Join(base, c+"-"+which+".exe"), args...).Output()
		if e != nil {
			if v, ok := e.(*exec.ExitError); ok {
				panic(fmt.Sprintf("%s %s failed: %s %s", c, which, string(b), string(v.Stderr)))
			}
			panic(e)
		}
		var v map[string]any
		must(json.Unmarshal(b, &v))
		if v["ok"] != true {
			panic("observer child refused: " + string(b))
		}
		out["steps"] = append(out["steps"].([]any), map[string]any{"campaign": c, "tool": which, "operation": args[0], "ok": true})
		return v
	}
	for _, c := range []string{"G167", "G160"} {
		v := call(c, "manage", "status")
		if v["service_absent"] != true || v["service_created"] != false {
			panic("observer already loaded")
		}
		v = call(c, "manage", "load")
		if v["service_status"].(map[string]any)["State"] != float64(4) {
			panic("observer not running")
		}
		v = call(c, "client", "status")
		initial := v["status_before"].(map[string]any)
		if initial["map_calls"] != float64(0) || initial["attempts"] != float64(0) || initial["firmware_match"] != float64(1) {
			panic("observer initial state")
		}
		path := filepath.Join(base, c+"-result-"+nonce+".bin")
		v = call(c, "client", "read", nonce, path)
		if v["read_submitted"] != true {
			panic("observer read was not submitted")
		}
		result := v["result"].(map[string]any)
		if result["operation_code"] != float64(0) || result["native_guard"] != float64(0) {
			panic("retain failed observer context")
		}
		if c == "G160" {
			if result["uncertain_mask"] != float64(0) || result["clean_mask"] != float64(3) || result["restored_mask"] != float64(3) || result["commands"] != float64(46) || v["bytes"] != float64(279880) {
				panic("retain uncertain gauge context")
			}
		} else {
			if result["uncertain_read"] != false || result["post_routes_verified"] != float64(1) || result["commands"] != float64(19) || v["bytes"] != float64(1096) {
				panic("retain uncertain config context")
			}
		}
		raw, e := os.ReadFile(path)
		must(e)
		h := sha256.Sum256(raw)
		if hex.EncodeToString(h[:]) != v["sha256"] {
			panic("native capture hash")
		}
		done := call(c, "manage", "unload")
		if done["service_deleted"] != true {
			panic("observer not retired")
		}
		gone := call(c, "manage", "status")
		if gone["service_absent"] != true || gone["service_created"] != false {
			panic("observer retirement not independently observed")
		}
		out["results"].(map[string]any)[c] = map[string]any{"result": result, "path": path, "nonce": nonce, "capture_sha256": v["sha256"], "retired": true}
	}
	out["utc_end"] = time.Now().UTC().Format(time.RFC3339Nano)
	out["ok"] = true
}
