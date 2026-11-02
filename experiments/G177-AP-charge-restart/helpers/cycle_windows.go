// Fixed local G177 restart qualification. Kernel timer, not this helper,
// owns the off/5s/on/90s/off sequence. No caller value or duration is accepted.
package main

import (
	"crypto/rand"
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
	"syscall"
	"time"
)

const cycleBase = `X:\OpenG17\payloads`

var cyclePins string

type cycleRun struct {
	nonce     string
	journal   *os.File
	out       map[string]any
	snapshots int
	started   bool
}

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func (c *cycleRun) record(v any) { must(json.NewEncoder(c.journal).Encode(v)); must(c.journal.Sync()) }
func (c *cycleRun) io(mode string, prior map[string]any) ([]byte, map[string]any) {
	cookie, id := uint64(0), uint64(0)
	if mode != "snapshot" {
		var e error
		cookie, e = hexCookie(prior["cookie"].(string))
		must(e)
		id = prior["last_command_id"].(uint64) + 1
		if id == 0 {
			panic("command ID exhausted")
		}
		// Synced intent precedes the one and only DeviceIoControl. No retry path.
		c.record(map[string]any{"intent": mode, "cookie": prior["cookie"], "command_id": id})
	}
	in, code, e := request(mode, cookie, id)
	must(e)
	name, e := syscall.UTF16PtrFromString(`\\.\OpenG177`)
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
		panic("snapshot output length")
	}
	s, e := decode(b)
	must(e)
	return b, s
}
func hexCookie(v string) (uint64, error) {
	b, e := hex.DecodeString(v)
	if e != nil || len(b) != 8 {
		return 0, fmt.Errorf("cookie format")
	}
	return binary.BigEndian.Uint64(b), nil
}
func st(s map[string]any) map[string]any { return s["state"].(map[string]any) }
func clean(s map[string]any) bool {
	v := st(s)
	return s["Running"] == uint32(1) && s["NativeFault"] == uint32(0) && s["MapsLive"] == uint32(2) && v["Phase"] == uint32(3) && v["Fault"] == uint32(0) && v["RpcUncertain"] == uint32(0) && v["TransportUncertain"] == uint32(0)
}
func (c *cycleRun) save(label string, b []byte, s map[string]any) {
	c.snapshots++
	p := filepath.Join(cycleBase, fmt.Sprintf("G177-%s-%02d-%s.bin", c.nonce, c.snapshots, label))
	f, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(e)
	_, e = f.Write(b)
	must(e)
	must(f.Sync())
	must(f.Close())
	h := sha256.Sum256(b)
	c.record(map[string]any{"snapshot": label, "path": p, "sha256": hex.EncodeToString(h[:]), "decoded": s})
}
func (c *cycleRun) snapshot(label string) map[string]any {
	b, s := c.io("snapshot", nil)
	if label != "" {
		c.save(label, b, s)
	}
	return s
}
func (c *cycleRun) stopIfActive() {
	// A fresh, clean native snapshot must resolve the state before issuing stop.
	// Failed/uncertain transports are retained. This is never an enable retry.
	defer func() {
		if e := recover(); e != nil {
			c.record(map[string]any{"stop_observation_error": fmt.Sprint(e)})
		}
	}()
	s := c.snapshot("error-state")
	if clean(s) && st(s)["BatchActive"] == uint32(1) && st(s)["PulseAttempted"] == uint32(1) && st(s)["StopPulseRequested"] == uint32(0) {
		b, v := c.io("stop-pulse", s)
		c.save("error-stop", b, v)
	}
}
func (c *cycleRun) wait(label string, deadline time.Time, condition func(map[string]any) bool) map[string]any {
	for time.Now().Before(deadline) {
		b, s := c.io("snapshot", nil)
		if !clean(s) {
			c.save("fault-"+label, b, s)
			panic("retain failed or uncertain owner: " + label)
		}
		if condition(s) {
			c.save(label, b, s)
			return s
		}
		time.Sleep(20 * time.Millisecond)
	}
	panic("observation deadline, no resubmission: " + label)
}
func getNumber(m map[string]any, n string) float64 { return m[n].(float64) }
func (c *cycleRun) observe(label string, wantEnable byte, minUs, maxUs uint64) {
	var random [8]byte
	_, e := rand.Read(random[:])
	must(e)
	nonce := hex.EncodeToString(random[:])
	c.record(map[string]any{"observation_intent": label, "nonce": nonce, "expected_enable_bit": wantEnable, "interrupt_window_us": []uint64{minUs, maxUs}})
	b, e := exec.Command(filepath.Join(cycleBase, "G170-observe.exe"), nonce).Output()
	if e != nil {
		panic(fmt.Sprintf("retain observer context %s: %v %s", label, e, b))
	}
	var v map[string]any
	must(json.Unmarshal(b, &v))
	if v["ok"] != true {
		panic("observer refused")
	}
	results := v["results"].(map[string]any)
	if len(results) != 2 {
		panic("paired observer set")
	}
	var configRaw []byte
	for _, camp := range []string{"G167", "G160"} {
		item := results[camp].(map[string]any)
		if item["retired"] != true || item["nonce"] != nonce {
			panic("observer retirement/nonce")
		}
		path := item["path"].(string)
		if path != filepath.Join(cycleBase, camp+"-result-"+nonce+".bin") {
			panic("capture path")
		}
		raw, e := os.ReadFile(path)
		must(e)
		h := sha256.Sum256(raw)
		if hex.EncodeToString(h[:]) != item["capture_sha256"] {
			panic("capture file hash")
		}
		if camp == "G167" {
			if len(raw) != 1096 {
				panic("config capture size")
			}
			configRaw = raw
			begin, end := binary.LittleEndian.Uint64(raw[104:])/10, binary.LittleEndian.Uint64(raw[112:])/10
			if begin < minUs || end < begin || end > maxUs {
				panic("configuration outside interrupt-time interval")
			}
		} else {
			if len(raw) != 279880 {
				panic("gauge capture size")
			}
			// Final status interrupt point is after cleanup. Result begin/end are QPC
			// and must not be compared directly with this interrupt-time interval.
			end := binary.LittleEndian.Uint64(raw[56:]) / 10
			if end < minUs || end > maxUs {
				panic("gauge completion outside interrupt-time interval")
			}
		}
	}
	cfg := results["G167"].(map[string]any)["result"].(map[string]any)
	telemetry := cfg["telemetry"].(map[string]any)
	if telemetry["register_4f43_raw"] != "0x40" || getNumber(telemetry, "fast_current_mA") != 300 || getNumber(telemetry, "float_voltage_mV") != 4470 || telemetry["APSD_type"] != "CDP" {
		panic("physical configuration changed")
	}
	// Fixed result query7 reads2640..2647. The independent G167 decoder has
	// already bound all19 trace addresses, lengths, completions and result bytes.
	enable := configRaw[184+7*8+6] & 1
	if enable != wantEnable {
		panic(fmt.Sprintf("physical enable=%d, expected%d", enable, wantEnable))
	}
	gauges := results["G160"].(map[string]any)["result"].(map[string]any)["gauges"].([]any)
	if len(gauges) != 2 {
		panic("gauge set")
	}
	for _, g := range gauges {
		a := g.(map[string]any)
		volt, temp := getNumber(a, "voltage_mV"), getNumber(a, "temperature_celsius")
		if a["identity_recognized"] != true || volt < 3250 || volt > 4300 || temp < 20 || temp > 40 {
			panic("physical voltage/temperature admission")
		}
	}
	c.record(map[string]any{"observation": label, "physical_enable_bit": enable, "receipt": v})
	c.out["observations"] = append(c.out["observations"].([]any), map[string]any{"label": label, "nonce": nonce, "results": results})
}
func main() {
	c := &cycleRun{out: map[string]any{"ok": false, "observations": []any{}, "normal_off_owned_by_kernel": true, "native_sequence_retries": 0}}
	defer func() {
		if e := recover(); e != nil {
			c.out["error"] = fmt.Sprint(e)
			if c.started {
				c.stopIfActive()
			}
		}
		if c.journal != nil {
			c.record(map[string]any{"final": c.out})
			c.journal.Close()
		}
		json.NewEncoder(os.Stdout).Encode(c.out)
		if c.out["ok"] != true {
			os.Exit(1)
		}
	}()
	must(winPEGuard())
	if len(os.Args) != 2 || !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(os.Args[1]) {
		panic("fixed experiment nonce required")
	}
	c.nonce = os.Args[1]
	self, e := os.Executable()
	must(e)
	if !strings.EqualFold(filepath.Dir(self), cycleBase) {
		panic("fixed project payload directory")
	}
	var pins map[string]string
	b, e := base64.StdEncoding.DecodeString(cyclePins)
	must(e)
	must(json.Unmarshal(b, &pins))
	if len(pins) != 10 {
		panic("driver,client,manager,observer and six child pins")
	}
	for n, h := range pins {
		raw, e := os.ReadFile(filepath.Join(cycleBase, n))
		must(e)
		v := sha256.Sum256(raw)
		if hex.EncodeToString(v[:]) != h {
			panic("file identity: " + n)
		}
	}
	c.journal, e = os.OpenFile(filepath.Join(cycleBase, "G177-cycle-"+c.nonce+".jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(e)
	c.out["nonce"] = c.nonce
	c.record(map[string]any{"campaign": "G177", "fixed_sequence": "off/5s/on/90s/off", "pins": pins})
	before := c.snapshot("before-restart")
	if !clean(before) || st(before)["BoardFvAcked"] != uint32(1) || st(before)["PulseAttempted"] != uint32(0) || st(before)["BatchActive"] != uint32(0) || st(before)["Pending"] != uint32(0) {
		panic("fresh restart admission")
	}
	c.started = true
	b, s := c.io("restart-pulse", before)
	c.save("restart-request", b, s)
	if s["LastResult"] != uint32(1) {
		panic("restart request not accepted")
	}
	gap := c.wait("initial-off-ack", time.Now().Add(12*time.Second), func(s map[string]any) bool {
		return st(s)["RestartOffAcked"] == uint32(1) || st(s)["BatchActive"] == uint32(0)
	})
	ready := st(gap)["RestartUntilUs"].(uint64)
	now := gap["now_us"].(uint64)
	if st(gap)["RestartOffAcked"] != uint32(1) || ready <= now || ready-now < 2500000 {
		panic("initial off rejected or insufficient capture interval")
	}
	c.observe("initial-off", 0, now, ready)
	on := c.wait("enable-ack", time.Now().Add(12*time.Second), func(s map[string]any) bool {
		return st(s)["PulseEnableAcked"] == uint32(1) || st(s)["BatchActive"] == uint32(0)
	})
	if st(on)["PulseEnableAcked"] != uint32(1) {
		panic("enable rejected")
	}
	until := st(on)["PulseUntilUs"].(uint64)
	enabledAt := until - 90000000
	c.wait("early-capture-time", time.Now().Add(12*time.Second), func(s map[string]any) bool { return s["now_us"].(uint64) >= enabledAt+3000000 })
	c.observe("enabled-early", 1, enabledAt, until)
	c.wait("late-capture-time", time.Now().Add(70*time.Second), func(s map[string]any) bool { return s["now_us"].(uint64) >= enabledAt+60000000 })
	c.observe("enabled-late", 1, enabledAt, until)
	final := c.wait("final-off-ack", time.Now().Add(45*time.Second), func(s map[string]any) bool { return st(s)["BatchActive"] == uint32(0) })
	if st(final)["PulseDisableAcked"] != uint32(1) || final["last_batch"].(map[string]any)["control_ack_mask"] != uint32(14336) {
		panic("final off not acknowledged")
	}
	offAt := final["last_batch"].(map[string]any)["end_us"].(uint64)
	c.wait("after-off-settled", time.Now().Add(10*time.Second), func(s map[string]any) bool { return s["now_us"].(uint64) >= offAt+3000000 })
	c.observe("after-final-off", 0, offAt, ^uint64(0))
	c.snapshot("retained-final")
	c.out["ok"] = true
}
