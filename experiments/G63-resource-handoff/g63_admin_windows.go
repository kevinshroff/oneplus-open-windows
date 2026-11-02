// SPDX-License-Identifier: MIT
// One read-only interface query; preserve exact bytes before interpreting them.
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
	"syscall"
	"unsafe"
)

var resourceGUID = syscall.GUID{Data1: 0x01404e15, Data2: 0xc240, Data3: 0x46c1, Data4: [8]byte{0x94, 0xf4, 0x1e, 0x97, 0xa1, 0x65, 0x63, 0x71}}

//go:uintptrescapes
func cmCall(p *syscall.LazyProc, args ...uintptr) uint32 {
	v, _, _ := p.Call(args...)
	return uint32(v)
}
func checkTable() error {
	p := syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemFirmwareTable")
	n, _, _ := p.Call(0x41435049, 0x54445344, 0, 0)
	if n != 730 {
		return fmt.Errorf("G63 trial DSDT length%d differs", n)
	}
	b := make([]byte, n)
	got, _, _ := p.Call(0x41435049, 0x54445344, uintptr(unsafe.Pointer(&b[0])), n)
	if got != n {
		return errors.New("G63 DSDT short read")
	}
	s := sha256.Sum256(b)
	if hex.EncodeToString(s[:]) != "cdc95eadbedcaf60088741e36803b9c96297ccc72afa48b2adb5d9b9c3205ece" {
		return errors.New("G63 trial DSDT hash differs")
	}
	return nil
}
func oneInterface() (string, error) {
	cm := syscall.NewLazyDLL("cfgmgr32.dll")
	size := cm.NewProc("CM_Get_Device_Interface_List_SizeW")
	list := cm.NewProc("CM_Get_Device_Interface_ListW")
	var n uint32
	if r := cmCall(size, uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&resourceGUID)), 0, 0); r != 0 || n < 2 || n > 16384 {
		return "", fmt.Errorf("G63 interface list size CR0x%x length%d", r, n)
	}
	buf := make([]uint16, n)
	if r := cmCall(list, uintptr(unsafe.Pointer(&resourceGUID)), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(n), 0); r != 0 {
		return "", fmt.Errorf("G63 interface list CR0x%x", r)
	}
	paths := []string{}
	at := 0
	ended := false
	for i, v := range buf {
		if v == 0 {
			if i == at {
				ended = true
				break
			}
			paths = append(paths, syscall.UTF16ToString(buf[at:i]))
			at = i + 1
		}
	}
	if !ended || len(paths) != 1 {
		return "", errors.New("G63 requires exactly one terminated present source interface")
	}
	return paths[0], nil
}
func capture(token string) (any, error) {
	if runtime.GOOS != "windows" || runtime.GOARCH != "arm64" || runtime.NumCPU() != 8 || !tokenOK(token) {
		return nil, errors.New("G63 architecture/processor/nonce guard failed")
	}
	if e := checkTable(); e != nil {
		return nil, e
	}
	path, e := oneInterface()
	if e != nil {
		return nil, e
	}
	u := syscall.StringToUTF16(path)
	h, e := syscall.CreateFile(&u[0], 0x80000000, 0, nil, 3, 0, 0)
	if e != nil {
		return nil, e
	}
	defer syscall.CloseHandle(h)
	dest := filepath.Join(`X:\OpenG17\payloads`, "G63-assigned-"+token+".bin")
	f, e := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	in := make([]byte, 16)
	binary.LittleEndian.PutUint32(in, 16)
	binary.LittleEndian.PutUint32(in[4:], 1)
	binary.LittleEndian.PutUint64(in[8:], resourceMagic)
	out := make([]byte, reportBytes)
	var got uint32
	e = syscall.DeviceIoControl(h, 0x2267c0, &in[0], 16, &out[0], reportBytes, &got, nil)
	if e != nil {
		return nil, e
	}
	if got != reportBytes {
		return nil, errors.New("G63 IOCTL result size differs")
	}
	n, e := f.Write(out)
	if e != nil {
		return nil, e
	}
	if n != len(out) {
		return nil, errors.New("G63 raw capture short write")
	}
	if e = f.Sync(); e != nil {
		return nil, e
	}
	sum := sha256.Sum256(out)
	summary := map[string]any{"path": dest, "bytes": len(out), "sha256": hex.EncodeToString(sum[:]), "source_interface": path, "source_file_opened_for_read_only": true}
	v, e := decodeCapture(out)
	summary["report"] = v
	return summary, e
}
func main() {
	var result any
	var err error
	if len(os.Args) == 3 && os.Args[1] == "capture" {
		result, err = capture(os.Args[2])
	} else if len(os.Args) == 3 && os.Args[1] == "decode" {
		var b []byte
		b, err = os.ReadFile(os.Args[2])
		if err == nil {
			result, err = decodeCapture(b)
		}
	} else {
		err = errors.New("usage: capture TOKEN | decode FILE")
	}
	if err != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": false, "error": err.Error(), "result": result})
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "result": result})
}
