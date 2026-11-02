package main

import (
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
	le.PutUint64(q[8:], 0x314c43303947504f)
	le.PutUint64(q[16:], nonce)
	b := make([]byte, size)
	var got uint32
	must(syscall.DeviceIoControl(h, code, &q[0], 24, &b[0], uint32(size), &got, nil))
	require(got == uint32(size), "short IOCTL result")
	return b
}
func main() {
	r := map[string]any{"version": "G90-full-Windows-client", "run_submitted": false}
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
	require(mode == "probe" || mode == "observe", "observer mode only")
	nonce, e := strconv.ParseUint(os.Args[2], 16, 64)
	must(e)
	require(nonce != 0 && len(os.Args[2]) == 16, "nonce")
	h, e := syscall.CreateFile(ptr(`\\.\OpenG90`), syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, 0, 0)
	must(e)
	defer syscall.CloseHandle(h)
	s := operation(h, 0x226a00, 96, 0)
	r["observed_platform"] = map[string]any{"build": u(s, 16), "CPUs": u(s, 20), "IRQL": u(s, 24), "firmware_bytes": u(s, 28), "firmware_match": u(s, 32), "register_count": u(s, 36), "firmware_status": u(s, 40), "map_calls": u(s, 44), "run_attempts": u(s, 80)}
	r["status"] = status(s)
	if mode == "probe" {
		return
	}
	if mode == "observe" {
		path := `C:\OpenG81\payloads\G90-observe-` + os.Args[2] + `.bin`
		f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		must(e)
		b := operation(h, 0x226a08, 1744, 0)
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
}
