// SPDX-License-Identifier: MIT
// Exact RAM-trial-only installer. No disk/partition/BCD API, root device create,
// arbitrary package path, reboot command or hardware register operation.
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
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")
var cfg = syscall.NewLazyDLL("cfgmgr32.dll")
var setup = syscall.NewLazyDLL("setupapi.dll")
var regexpOEM = regexp.MustCompile(`(?i)^oem[0-9]+\.inf$`)

//go:uintptrescapes
func call(p *syscall.LazyProc, args ...uintptr) (uintptr, error) {
	r, _, e := p.Call(args...)
	return r, e
}
func wide(s string) *uint16 {
	p, e := syscall.UTF16PtrFromString(s)
	if e != nil {
		panic(e)
	}
	return p
}
func winerr(label string, e error) error {
	if e == nil || e == syscall.Errno(0) {
		return errors.New(label + ": Windows call returned failure")
	}
	return fmt.Errorf("%s: %w", label, e)
}
func digest(p string) (string, error) {
	b, e := os.ReadFile(p)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func environment() (Environment, error) {
	e := Environment{OS: runtime.GOOS, Arch: runtime.GOARCH, CPUs: runtime.NumCPU(), SystemRoot: os.Getenv("SystemRoot")}
	version := make([]byte, 276)
	binary.LittleEndian.PutUint32(version, 276)
	r, _ := call(syscall.NewLazyDLL("ntdll.dll").NewProc("RtlGetVersion"), uintptr(unsafe.Pointer(&version[0])))
	if uint32(r) != 0 {
		return e, fmt.Errorf("RtlGetVersion status0x%x", r)
	}
	e.Build = binary.LittleEndian.Uint32(version[12:])
	n, _ := call(kernel.NewProc("GetSystemFirmwareTable"), 0x41435049, 0x54445344, 0, 0)
	e.DSDTBytes = int(n)
	if n == 0 || n > 65536 {
		return e, errors.New("firmware table size invalid")
	}
	b := make([]byte, n)
	got, _ := call(kernel.NewProc("GetSystemFirmwareTable"), 0x41435049, 0x54445344, uintptr(unsafe.Pointer(&b[0])), n)
	if got != n {
		return e, errors.New("firmware table short read")
	}
	h := sha256.Sum256(b)
	e.DSDTSHA = hex.EncodeToString(h[:])
	var key syscall.Handle
	if er := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, wide(`SYSTEM\CurrentControlSet\Control`), 0, syscall.KEY_QUERY_VALUE, &key); er != nil {
		return e, er
	}
	defer syscall.RegCloseKey(key)
	buf := make([]uint16, 2048)
	sz := uint32(len(buf) * 2)
	var typ uint32
	r, er := call(syscall.NewLazyDLL("advapi32.dll").NewProc("RegQueryValueExW"), uintptr(key), uintptr(unsafe.Pointer(wide("SystemBootDevice"))), 0, uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&sz)))
	if r != 0 || typ != 1 || sz < 2 || sz > uint32(len(buf)*2) || sz%2 != 0 {
		return e, winerr("SystemBootDevice query", er)
	}
	e.BootDevice = syscall.UTF16ToString(buf[:sz/2])
	names := make([]uint16, 2048)
	r, er = call(kernel.NewProc("QueryDosDeviceW"), uintptr(unsafe.Pointer(wide("X:"))), uintptr(unsafe.Pointer(&names[0])), uintptr(len(names)))
	if r == 0 || r > uintptr(len(names)) {
		return e, winerr("X device query", er)
	}
	e.XDevice = syscall.UTF16ToString(names[:r])
	return e, nil
}

type Manifest struct {
	Version    string            `json:"version"`
	Files      map[string]string `json:"files"`
	Interface  string            `json:"interface_guid"`
	HardwareID string            `json:"hardware_id"`
	Table      string            `json:"trial_DSDT_sha256"`
}

func packageCheck() (Manifest, error) {
	var m Manifest
	p := filepath.Join(packageDir, "package.json")
	h, e := digest(p)
	if e != nil || h != packageSHA {
		return m, errors.New("exact G69 package manifest hash differs")
	}
	b, e := os.ReadFile(p)
	if e != nil {
		return m, e
	}
	if e = json.Unmarshal(b, &m); e != nil {
		return m, e
	}
	if m.Version != "G69-package-1" || len(m.Files) != 4 || m.HardwareID != hardwareID || m.Table != trialDSDT || m.Interface != "2f1df03e-a4ab-4e14-a587-32af76b23969" {
		return m, errors.New("package identity differs")
	}
	for _, name := range []string{"OpenG69.inf", "OpenG69.sys", "OpenG69.cat", "G69-public.cer"} {
		v, ok := m.Files[name]
		if !ok {
			return m, errors.New("package file missing")
		}
		h, e := digest(filepath.Join(packageDir, name))
		if e != nil || h != v {
			return m, fmt.Errorf("package file hash differs: %s", name)
		}
	}
	if m.Files["G69-public.cer"] != "0000000000000000000000000000000000000000000000000000000000000000" {
		return m, errors.New("project public certificate differs")
	}
	return m, nil
}

// Prove the fixed package directory resolves to this boot's RAM device before
// reading package files or creating any phase intent. Refuse directory aliases.
func packageRAMDirectory(env Environment) error {

	h, e := syscall.CreateFile(wide(packageDir), syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0x02000000|0x00200000, 0)
	if e != nil {
		return fmt.Errorf("RAM package directory: %w", e)
	}
	defer syscall.CloseHandle(h)
	var info syscall.ByHandleFileInformation
	if e = syscall.GetFileInformationByHandle(h, &info); e != nil || info.FileAttributes&0x10 == 0 || info.FileAttributes&0x400 != 0 {
		return fmt.Errorf("RAM package directory attributes: %v", e)
	}
	buf := make([]uint16, 32768)
	n, er := call(kernel.NewProc("GetFinalPathNameByHandleW"), uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 2)
	if n == 0 || n >= uintptr(len(buf)) || !strings.EqualFold(syscall.UTF16ToString(buf[:n]), env.XDevice+packageDir[2:]) {
		return winerr("RAM package final NT path", er)
	}
	return nil
}
func oneNode() (map[string]any, error) {
	var n uint32
	r, _ := call(cfg.NewProc("CM_Get_Device_ID_List_SizeW"), uintptr(unsafe.Pointer(&n)), 0, 0x100)
	if r != 0 || n < 2 || n > 65536 {
		return nil, fmt.Errorf("present device list size CR0x%x len%d", r, n)
	}
	buf := make([]uint16, n)
	r, _ = call(cfg.NewProc("CM_Get_Device_ID_ListW"), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(n), 0x100)
	if r != 0 {
		return nil, fmt.Errorf("present device list CR0x%x", r)
	}
	ids := []string{}
	at := 0
	ended := false
	for i, c := range buf {
		if c == 0 {
			if i == at {
				ended = true
				break
			}
			id := syscall.UTF16ToString(buf[at:i])
			if strings.HasPrefix(strings.ToUpper(id), hardwareID+`\`) {
				ids = append(ids, id)
			}
			at = i + 1
		}
	}
	if !ended || len(ids) != 1 {
		return nil, errors.New("need exactly one present ACPI OPEN0067 device")
	}
	if !strings.EqualFold(ids[0], hardwareID+`\0`) {
		return nil, errors.New("owned ACPI device instance differs from UID0")
	}
	var dn uint32
	r, _ = call(cfg.NewProc("CM_Locate_DevNodeW"), uintptr(unsafe.Pointer(&dn)), uintptr(unsafe.Pointer(wide(ids[0]))), 0)
	if r != 0 {
		return nil, fmt.Errorf("owned node locate CR0x%x", r)
	}
	var status, problem uint32
	r, _ = call(cfg.NewProc("CM_Get_DevNode_Status"), uintptr(unsafe.Pointer(&status)), uintptr(unsafe.Pointer(&problem)), uintptr(dn), 0)
	if r != 0 {
		return nil, fmt.Errorf("owned node status CR0x%x", r)
	}
	var typ uint32
	name := make([]uint16, 256)
	size := uint32(len(name) * 2)
	r, _ = call(cfg.NewProc("CM_Get_DevNode_Registry_PropertyW"), uintptr(dn), 5, uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&size)), 0)
	service := ""
	if r != 0 && r != 0x25 { // CR_NO_SUCH_VALUE means the unbound service property is absent.
		return nil, fmt.Errorf("owned node service query CR0x%x", r)
	}
	if r == 0 {
		if typ != 1 || size < 2 || size > uint32(len(name)*2) || size%2 != 0 {
			return nil, errors.New("owned node service property malformed")
		}
		service = syscall.UTF16ToString(name[:size/2])
	}
	return map[string]any{"instance": ids[0], "status": status, "problem": problem, "service": service, "service_query_CR": r}, nil
}
func intent(mode, token string, env Environment) error {
	if !goodToken(token) {
		return errors.New("fresh32lowercase-hex nonce required")
	}
	p := filepath.Join(packageDir, "G69-"+mode+"-intent.json")
	f, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	e = json.NewEncoder(f).Encode(map[string]any{"phase": mode, "token": token, "package_sha256": packageSHA, "hardware_id": hardwareID, "environment": env, "PID": os.Getpid(), "UTC": time.Now().UTC().Format(time.RFC3339Nano)})
	if e != nil {
		return e
	}
	return f.Sync()
}
func trust() (any, error) {
	crypt := syscall.NewLazyDLL("crypt32.dll")
	b, e := os.ReadFile(filepath.Join(packageDir, "G69-public.cer"))
	if e != nil {
		return nil, e
	}
	rows := []map[string]any{}
	for _, name := range []string{"ROOT", "TrustedPublisher"} {
		store, er := call(crypt.NewProc("CertOpenStore"), 10, 0, 0, 0x20000, uintptr(unsafe.Pointer(wide(name))))
		if store == 0 {
			return rows, winerr("RAM local-machine certificate store", er)
		}
		r, er := call(crypt.NewProc("CertAddEncodedCertificateToStore"), store, 0x10001, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 2, 0)
		closed, ce := call(crypt.NewProc("CertCloseStore"), store, 0)
		if r == 0 {
			return rows, winerr("add expected project public certificate", er)
		}
		if closed == 0 {
			return rows, winerr("close certificate store", ce)
		}
		rows = append(rows, map[string]any{"store": name, "scope": "RAM-trial local machine", "public_certificate_sha256": "0000000000000000000000000000000000000000000000000000000000000000", "add_use_existing_succeeded": true})
	}
	return map[string]any{"stores": rows, "private_key_exported": false, "persistent_host_trust_changed": false}, nil
}
func stage(token string) (any, error) {
	name := make([]uint16, 512)
	var needed uint32
	r, e := call(setup.NewProc("SetupCopyOEMInfW"), uintptr(unsafe.Pointer(wide(filepath.Join(packageDir, "OpenG69.inf")))), 0, 1, 0, uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)), uintptr(unsafe.Pointer(&needed)), 0)
	if r == 0 {
		return nil, winerr("stage exact G69 package", e)
	}
	published := syscall.UTF16ToString(name)
	if !strings.EqualFold(filepath.Dir(published), `X:\Windows\INF`) || !regexpOEM.MatchString(filepath.Base(published)) {
		return nil, errors.New("published INF path differs")
	}
	h, e := digest(published)
	m, e2 := packageCheck()
	if e != nil || e2 != nil || h != m.Files["OpenG69.inf"] {
		return nil, errors.New("published INF hash differs")
	}
	out := map[string]any{"version": 1, "token": token, "package_sha256": packageSHA, "published_inf": published}
	f, e := os.OpenFile(filepath.Join(packageDir, "G69-stage-result.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return out, e
	}
	defer f.Close()
	if e = json.NewEncoder(f).Encode(out); e != nil {
		return out, e
	}
	return out, f.Sync()
}
func bind(token string) (any, error) {
	b, e := os.ReadFile(filepath.Join(packageDir, "G69-stage-result.json"))
	if e != nil {
		return nil, e
	}
	var recorded struct {
		Version int    `json:"version"`
		Token   string `json:"token"`
		Package string `json:"package_sha256"`
		INF     string `json:"published_inf"`
	}
	if e = json.Unmarshal(b, &recorded); e != nil {
		return nil, e
	}
	m, e := packageCheck()
	if e != nil {
		return nil, e
	}
	if recorded.Version != 1 || recorded.Token != token || recorded.Package != packageSHA || !strings.EqualFold(filepath.Dir(recorded.INF), `X:\Windows\INF`) || !regexpOEM.MatchString(filepath.Base(recorded.INF)) {
		return nil, errors.New("exact stage receipt/published INF path differs")
	}
	h, e := digest(recorded.INF)
	if e != nil || h != m.Files["OpenG69.inf"] {
		return nil, errors.New("published INF hash differs")
	}
	before, e := oneNode()
	if e != nil {
		return nil, e
	}
	if before["service"] != "" && !strings.EqualFold(before["service"].(string), "OpenG69") {
		return nil, errors.New("owned HID already has another service; refuse replacement")
	}
	if strings.EqualFold(before["service"].(string), "OpenG69") && before["status"].(uint32)&8 != 0 && before["problem"] == uint32(0) {
		return map[string]any{"already_owned_started": true, "before": before, "bound": true, "reboot_requested": false}, nil
	}
	var reboot int32
	r, e := call(syscall.NewLazyDLL("newdev.dll").NewProc("UpdateDriverForPlugAndPlayDevicesW"), 0, uintptr(unsafe.Pointer(wide(hardwareID))), uintptr(unsafe.Pointer(wide(filepath.Join(packageDir, "OpenG69.inf")))), 4, uintptr(unsafe.Pointer(&reboot)))
	if r == 0 {
		return nil, winerr("bind exact G69 ACPI device", e)
	}
	after, e := oneNode()
	if e != nil {
		return nil, e
	}
	result := map[string]any{"update_API_succeeded": true, "bound": false, "before": before, "after": after, "reboot_requested": reboot != 0, "force_flag_used": false}
	if reboot != 0 || !strings.EqualFold(after["service"].(string), "OpenG69") || after["problem"] != uint32(0) || after["status"].(uint32)&8 == 0 {
		return result, errors.New("owned G69 node did not start without reboot; inspect the recorded state without replay")
	}
	result["bound"] = true
	return result, nil
}
func run(mode, token string) (any, error) {
	env, e := environment()
	out := map[string]any{"environment": env, "native_resource_handoff_qualified": false}
	if e != nil {
		return out, e
	}
	if e = allowedRAM(env); e != nil {
		return out, e
	}
	if mode == "describe" {
		v, e := oneNode()
		out["node"] = v
		return out, e
	}
	if mode != "trust" && mode != "stage" && mode != "bind" {
		return out, errors.New("unsupported setup phase")
	}
	if e = packageRAMDirectory(env); e != nil {
		return out, e
	}
	if _, e = packageCheck(); e != nil {
		return out, e
	}
	if _, e = oneNode(); e != nil {
		return out, e
	}
	if e = intent(mode, token, env); e != nil {
		return out, e
	}
	var v any
	switch mode {
	case "trust":
		v, e = trust()
	case "stage":
		v, e = stage(token)
	case "bind":
		v, e = bind(token)
	}
	out["phase"] = mode
	out["result"] = v
	return out, e
}
func main() {
	var out any
	var e error
	if len(os.Args) == 2 && os.Args[1] == "describe" {
		out, e = run("describe", "")
	} else if len(os.Args) == 3 {
		out, e = run(os.Args[1], os.Args[2])
	} else {
		e = errors.New("usage: describe | trust TOKEN | stage TOKEN | bind TOKEN")
	}
	if e != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": false, "error": e.Error(), "result": out})
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "result": out})
}
