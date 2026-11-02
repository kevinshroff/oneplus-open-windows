// SPDX-License-Identifier: MIT
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

func main() {
	out := map[string]any{"ok": false, "request_submitted": false}
	defer func() {
		if e := recover(); e != nil {
			out["error"] = fmt.Sprint(e)
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
	if len(os.Args) != 3 && len(os.Args) != 5 {
		panic("status|snapshot path OR start|sample|close|board-fv cookie command-id path")
	}
	mode := os.Args[1]
	cookie, id := uint64(0), uint64(0)
	path := os.Args[len(os.Args)-1]
	if len(os.Args) == 5 {
		var e error
		cookie, e = strconv.ParseUint(os.Args[2], 16, 64)
		must(e)
		id, e = strconv.ParseUint(os.Args[3], 10, 64)
		must(e)
	}
	in, code, e := request(mode, cookie, id)
	must(e)
	if !strings.EqualFold(filepath.Dir(path), `X:\OpenG17\payloads`) || !strings.HasPrefix(filepath.Base(path), "G169-") || !strings.HasSuffix(path, ".bin") {
		panic("fixed project result file required")
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(e)
	defer f.Close()
	req, e := os.OpenFile(path+".request.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(e)
	must(json.NewEncoder(req).Encode(map[string]any{"mode": mode, "control_code": code, "cookie": fmt.Sprintf("%016x", cookie), "command_id": id}))
	must(req.Sync())
	must(req.Close())
	name, e := syscall.UTF16PtrFromString(`\\.\OpenG169`)
	must(e)
	access := uint32(syscall.GENERIC_READ)
	if mode != "status" && mode != "snapshot" {
		access |= syscall.GENERIC_WRITE
	}
	h, e := syscall.CreateFile(name, access, 0, nil, syscall.OPEN_EXISTING, 0, 0)
	must(e)
	defer syscall.CloseHandle(h)
	b := make([]byte, abi.Size)
	var got uint32
	out["request_submitted"] = true
	out["operation"] = mode
	out["command_id"] = id
	must(syscall.DeviceIoControl(h, code, &in[0], uint32(len(in)), &b[0], uint32(len(b)), &got, nil))
	if got != uint32(len(b)) {
		panic("snapshot output length")
	}
	_, e = f.Write(b)
	must(e)
	must(f.Sync())
	hash := sha256.Sum256(b)
	out["sha256"] = hex.EncodeToString(hash[:])
	out["bytes"] = len(b)
	out["path"] = path
	decoded, e := decode(b)
	must(e)
	out["snapshot"] = decoded
	out["ok"] = true
}
