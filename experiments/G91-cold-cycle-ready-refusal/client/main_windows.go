package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"syscall"
)

func operation(h syscall.Handle, code uint32, size int, nonce uint64) []byte {
	q := make([]byte, 24)
	le.PutUint32(q, 24)
	le.PutUint32(q[4:], 1)
	le.PutUint64(q[8:], 0x314c43313947504f)
	le.PutUint64(q[16:], nonce)
	b := make([]byte, size)
	var got uint32
	must(syscall.DeviceIoControl(h, code, &q[0], 24, &b[0], uint32(size), &got, nil))
	require(got == uint32(size), "short IOCTL result")
	return b
}
func main() {
	r := map[string]any{"version": "G91-full-Windows-client", "run_submitted": false}
	defer func() {
		if e := recover(); e != nil {
			r["error"] = fmt.Sprint(e)
		}
		must(json.NewEncoder(os.Stdout).Encode(r))
		if r["error"] != nil {
			os.Exit(1)
		}
	}()
	guard()
	require(len(os.Args) == 3, "usage: probe|trial|result HEX_NONCE")
	mode := os.Args[1]
	nonce, e := strconv.ParseUint(os.Args[2], 16, 64)
	must(e)
	require(nonce != 0 && len(os.Args[2]) == 16, "nonce")
	h, e := syscall.CreateFile(ptr(`\\.\OpenG91`), syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, 0, 0)
	must(e)
	defer syscall.CloseHandle(h)
	s := operation(h, 0x226a00, 96, 0)
	r["observed_platform"] = map[string]any{"build": u(s, 16), "CPUs": u(s, 20), "IRQL": u(s, 24), "firmware_bytes": u(s, 28), "firmware_match": u(s, 32), "register_count": u(s, 36), "firmware_status": u(s, 40), "map_calls": u(s, 44), "run_attempts": u(s, 80)}
	r["status"] = status(s)
	if mode == "probe" {
		return
	}
	if mode == "observe" {
		b := operation(h, 0x226a08, 1744, 0)
		path := `C:\OpenG81\payloads\G91-observe-` + os.Args[2] + `.bin`
		f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		must(e)
		_, e = f.Write(b)
		must(e)
		must(f.Sync())
		must(f.Close())
		r["file"] = path
		r["observer_code"] = u(b, 96)
		r["PMIC_status"] = fmt.Sprintf("0x%02x", b[96+68])
		r["PMIC_configuration"] = hex.EncodeToString(b[96+69 : 96+77])
		r["fixed_unchanged"] = u(b, 1716)
		r["attempt"] = u(b, 1720)
		r["status_after"] = status(b)
		return
	}
	require(mode == "trial" || mode == "result", "mode")
	path := `C:\OpenG81\payloads\G91-` + mode + `-` + os.Args[2] + `.bin`
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(e)
	defer f.Close()
	var raw []byte
	if mode == "trial" {
		require(u(s, 80) == 0 && u(s, 84) == 0 && u(s, 88) == 0 && u(s, 92) == 0, "fresh driver required")
		before := operation(h, 0x226a04, 304, 0)
		baseline := snapshot(before)
		pre, e := os.OpenFile(path+".preflight", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		must(e)
		preRaw := operation(h, 0x226a08, 1744, 0)
		_, e = pre.Write(preRaw)
		must(e)
		must(pre.Sync())
		must(pre.Close())
		r["preflight_file"] = path + ".preflight"
		r["PMIC_before"] = outsidePmic(preRaw)
		ready := operation(h, 0x226a00, 96, 0)
		status(ready)
		require(u(ready, 80) == 0 && u(ready, 84) == 1 && u(ready, 88) == 0 && u(ready, 92) == 1, "native preflight not ready")
		r["run_submitted"] = true
		raw = operation(h, 0x22ea0c, 44848, nonce)
		_, e = f.Write(raw)
		must(e)
		must(f.Sync())
		r["file"] = path
		sum := sha256.Sum256(raw)
		r["sha256"] = hex.EncodeToString(sum[:])
		// Save the complete hardware result before interpreting any operation failure.
		r["run"] = runResult(raw, nonce)
		r["PMIC_after"] = outsidePmic(operation(h, 0x226a08, 1744, 0))
		after := operation(h, 0x226a04, 304, 0)
		snapshot(after)
		require(bytes.Equal(baseline, after[104:]), "external fixed baseline changed")
		cached := operation(h, 0x226a10, 44848, nonce)
		require(bytes.Equal(raw, cached), "cached result changed")
		r["cached_identical"] = true
		r["fixed_words_restored"] = 50
		r["status_after"] = status(operation(h, 0x226a00, 96, 0))
	} else {
		raw = operation(h, 0x226a10, 44848, nonce)
		_, e = f.Write(raw)
		must(e)
		must(f.Sync())
		r["file"] = path
		sum := sha256.Sum256(raw)
		r["sha256"] = hex.EncodeToString(sum[:])
		r["run"] = runResult(raw, nonce)
	}
}
