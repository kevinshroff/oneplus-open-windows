package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var adv = syscall.NewLazyDLL("advapi32.dll")
var setup = syscall.NewLazyDLL("setupapi.dll")
var cfg = syscall.NewLazyDLL("cfgmgr32.dll")
var kernel = syscall.NewLazyDLL("kernel32.dll")
var user = syscall.NewLazyDLL("user32.dll")

type GUID struct {
	D1     uint32
	D2, D3 uint16
	D4     [8]byte
}

var classGUID = GUID{0x745a17a0, 0x74d3, 0x11d0, [8]byte{0xb6, 0xfe, 0, 0xa0, 0xc9, 0x0f, 0x57, 0xda}}

const rootID = `Root\OnePlusOpenTouchG51`

type devInfo struct {
	Size     uint32
	Class    GUID
	Inst     uint32
	Reserved uintptr
}
type manifest struct {
	Version   string            `json:"version"`
	Files     map[string]string `json:"files"`
	Interface string            `json:"interface_guid"`
}

func wide(s string) *uint16 {
	p, e := syscall.UTF16PtrFromString(s)
	if e != nil {
		panic(e)
	}
	return p
}
func winerr(where string, e error) error {
	if e == nil || e == syscall.Errno(0) {
		return errors.New(where + ": unknown Windows failure")
	}
	return fmt.Errorf("%s: %w", where, e)
}
func textAt(p uintptr) string {
	if p == 0 {
		return ""
	}
	buf := make([]uint16, 0, 128)
	for i := uintptr(0); i < 32768; i++ {
		v := *(*uint16)(unsafe.Pointer(p + i*2))
		if v == 0 {
			return syscall.UTF16ToString(buf)
		}
		buf = append(buf, v)
	}
	return "[unterminated]"
}
func closeSvc(h uintptr) {
	if h != 0 {
		adv.NewProc("CloseServiceHandle").Call(h)
	}
}
func service(name string) map[string]any {
	out := map[string]any{"name": name}
	m, _, e := adv.NewProc("OpenSCManagerW").Call(0, 0, 1)
	if m == 0 {
		out["error"] = winerr("OpenSCManager", e).Error()
		return out
	}
	defer closeSvc(m)
	h, _, e := adv.NewProc("OpenServiceW").Call(m, uintptr(unsafe.Pointer(wide(name))), 1|4)
	if h == 0 {
		out["present"] = false
		out["error"] = e.Error()
		return out
	}
	defer closeSvc(h)
	out["present"] = true
	var need uint32
	adv.NewProc("QueryServiceConfigW").Call(h, 0, 0, uintptr(unsafe.Pointer(&need)))
	if need < 64 || need > 1<<20 {
		out["config_error"] = "unexpected config size"
		return out
	}
	b := make([]byte, need)
	ok, _, e := adv.NewProc("QueryServiceConfigW").Call(h, uintptr(unsafe.Pointer(&b[0])), uintptr(need), uintptr(unsafe.Pointer(&need)))
	if ok == 0 {
		out["config_error"] = e.Error()
		return out
	}
	out["type"] = *(*uint32)(unsafe.Pointer(&b[0]))
	out["start_type"] = *(*uint32)(unsafe.Pointer(&b[4]))
	out["error_control"] = *(*uint32)(unsafe.Pointer(&b[8]))
	out["binary"] = textAt(*(*uintptr)(unsafe.Pointer(&b[16])))
	out["load_group"] = textAt(*(*uintptr)(unsafe.Pointer(&b[24])))
	var status [7]uint32
	ok, _, e = adv.NewProc("QueryServiceStatus").Call(h, uintptr(unsafe.Pointer(&status[0])))
	if ok != 0 {
		out["state"] = status[1]
	} else {
		out["status_error"] = e.Error()
	}
	runtime.KeepAlive(b)
	return out
}
func file(path string) map[string]any {
	b, e := os.ReadFile(path)
	if e != nil {
		return map[string]any{"path": path, "present": false, "error": e.Error()}
	}
	s := sha256.Sum256(b)
	return map[string]any{"path": path, "present": true, "bytes": len(b), "sha256": hex.EncodeToString(s[:])}
}
func inventory() (any, error) {
	var f [576]byte
	r, _, e := kernel.NewProc("GetSystemFirmwareTable").Call(0x41435049, 0x54445344, uintptr(unsafe.Pointer(&f[0])), uintptr(len(f)))
	if r != 576 {
		return nil, winerr("exact G17 DSDT", e)
	}
	s := sha256.Sum256(f[:])
	dsdt := hex.EncodeToString(s[:])
	if dsdt != "c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01" {
		return nil, errors.New("G17 DSDT identity mismatch")
	}
	a, _, _ := user.NewProc("GetSystemMetrics").Call(0)
	b, _, _ := user.NewProc("GetSystemMetrics").Call(1)
	d, _, _ := user.NewProc("GetSystemMetrics").Call(94)
	services := []any{}
	for _, n := range []string{"vhf", "mshidkmdf", "Wdf01000", "hidusb", "mouhid", "kbdhid"} {
		services = append(services, service(n))
	}
	files := []any{}
	for _, n := range []string{"vhf.sys", "mshidkmdf.sys", "hidclass.sys", "hidparse.sys", "mouhid.sys", "kbdhid.sys"} {
		files = append(files, file(`X:\Windows\System32\drivers\`+n))
	}
	return map[string]any{"DSDT_sha256": dsdt, "GOARCH": runtime.GOARCH, "display_pixels": []uintptr{a, b}, "SM_DIGITIZER": d, "services": services, "files": files, "setupapi_LoadLibrary": setup.Load() == nil, "cfgmgr32_LoadLibrary": cfg.Load() == nil, "native_mutations": 0}, nil
}
func digest(p string) (string, error) {
	b, e := os.ReadFile(p)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func checkManifest(path, want string) (manifest, string, error) {
	var m manifest
	h, e := digest(path)
	if e != nil || h != want {
		return m, "", errors.New("manifest hash mismatch")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return m, "", e
	}
	if e = json.Unmarshal(b, &m); e != nil {
		return m, "", e
	}
	if m.Version != "G51-package-1" || len(m.Files) != 4 {
		return m, "", errors.New("unexpected package manifest")
	}
	d := filepath.Dir(path)
	for _, n := range []string{"OpenG51.inf", "OpenG51.sys", "OpenG51.cat", "G51-public.cer"} {
		v, ok := m.Files[n]
		if !ok {
			return m, "", errors.New("missing package file")
		}
		h, e := digest(filepath.Join(d, n))
		if e != nil || h != v {
			return m, "", fmt.Errorf("package hash mismatch: %s", n)
		}
	}
	return m, d, nil
}
func intent(d, phase string) error {
	p := filepath.Join(d, "G51-"+phase+"-intent.json")
	f, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = json.NewEncoder(f).Encode(map[string]any{"phase": phase, "UTC": time.Now().UTC().Format(time.RFC3339Nano), "hardware_ID": rootID, "process": os.Getpid()}); e != nil {
		return e
	}
	return f.Sync()
}
func setClose(h uintptr) {
	if h != 0 && h != ^uintptr(0) {
		setup.NewProc("SetupDiDestroyDeviceInfoList").Call(h)
	}
}
func prop(h uintptr, d *devInfo, id uint32) ([]uint16, error) {
	var n, t uint32
	setup.NewProc("SetupDiGetDeviceRegistryPropertyW").Call(h, uintptr(unsafe.Pointer(d)), uintptr(id), uintptr(unsafe.Pointer(&t)), 0, 0, uintptr(unsafe.Pointer(&n)))
	if n == 0 || n > 65536 {
		return nil, errors.New("missing or excessive device property")
	}
	b := make([]uint16, (n+1)/2)
	r, _, e := setup.NewProc("SetupDiGetDeviceRegistryPropertyW").Call(h, uintptr(unsafe.Pointer(d)), uintptr(id), uintptr(unsafe.Pointer(&t)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)*2), uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return nil, winerr("device property", e)
	}
	return b, nil
}
func multi(b []uint16) []string {
	out := []string{}
	start := 0
	for i, v := range b {
		if v == 0 {
			if i == start {
				break
			}
			out = append(out, syscall.UTF16ToString(b[start:i]))
			start = i + 1
		}
	}
	return out
}
func instance(h uintptr, d *devInfo) (string, error) {
	b := make([]uint16, 512)
	var need uint32
	r, _, e := setup.NewProc("SetupDiGetDeviceInstanceIdW").Call(h, uintptr(unsafe.Pointer(d)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&need)))
	if r == 0 {
		return "", winerr("device instance", e)
	}
	return syscall.UTF16ToString(b), nil
}
func ownRoots() (uintptr, []devInfo, error) {
	h, _, e := setup.NewProc("SetupDiGetClassDevsW").Call(uintptr(unsafe.Pointer(&classGUID)), 0, 0, 0)
	if h == ^uintptr(0) {
		return 0, nil, winerr("list HID class", e)
	}
	out := []devInfo{}
	for i := uint32(0); ; i++ {
		d := devInfo{Size: 32}
		r, _, e := setup.NewProc("SetupDiEnumDeviceInfo").Call(h, uintptr(i), uintptr(unsafe.Pointer(&d)))
		if r == 0 {
			if errors.Is(e, syscall.Errno(259)) {
				break
			}
			setClose(h)
			return 0, nil, winerr("enum HID class", e)
		}
		b, e := prop(h, &d, 1)
		if e != nil {
			continue
		}
		for _, id := range multi(b) {
			if strings.EqualFold(id, rootID) {
				out = append(out, d)
				break
			}
		}
	}
	if len(out) > 1 {
		setClose(h)
		return 0, nil, errors.New("multiple owned G51 roots; refusing mutation")
	}
	return h, out, nil
}

const inboxHash = "086cfd93451de78d172384de4956a04443eb5d92576db316471085066558f92a"
const inboxTarget = `X:\Windows\INF\mshidkmdf.inf`

func dependency(mode, dir, source string) (any, error) {
	for p, want := range map[string]string{
		`X:\Windows\INF\hidvhf.inf`:                 "c229aa79c0bdfb7dba04866b33bae4de14a17292f3709f4af172783c0d8b278c",
		`X:\Windows\System32\drivers\vhf.sys`:       "72f675a9da6368e9d8e9fcaf1e1fa15be797fd03f8f0e27399caddc7abab27d3",
		`X:\Windows\System32\drivers\mshidkmdf.sys`: "c363d97c5f036acc7a863e98d949c32873a056b37aabef02a17b37a3a9fe272c",
	} {
		h, e := digest(p)
		if e != nil || h != want {
			return nil, fmt.Errorf("native inbox identity mismatch: %s", p)
		}
	}
	set, roots, e := ownRoots()
	if e != nil {
		return nil, e
	}
	setClose(set)
	out := map[string]any{"target": inboxTarget, "sha256": inboxHash, "bytes": 7858, "mode": mode, "service_before": service("mshidkmdf")}
	if mode == "import" {
		if len(roots) != 1 {
			return nil, errors.New("need exactly one owned root")
		}
		h, e := digest(source)
		if e != nil || h != inboxHash || !strings.EqualFold(filepath.Base(source), "mshidkmdf.inf") {
			return nil, errors.New("exact original INF required")
		}
		if e = intent(dir, "import-original-mshid-inbox-include"); e != nil {
			return nil, e
		}
		name := make([]uint16, 512)
		var need uint32
		r, _, e := setup.NewProc("SetupCopyOEMInfW").Call(uintptr(unsafe.Pointer(wide(source))), 0, 1, 0, uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)), uintptr(unsafe.Pointer(&need)), 0)
		if r == 0 {
			return out, winerr("import original inbox include", e)
		}
		out["published_inf"] = syscall.UTF16ToString(name)
		out["driver_store_imported"] = true
	} else if mode == "restore" {
		if len(roots) != 1 {
			return nil, errors.New("need exactly one owned root before restoring dependency")
		}
		h, e := digest(source)
		if e != nil || h != inboxHash {
			return nil, errors.New("staged inbox dependency hash mismatch")
		}
		b, e := os.ReadFile(source)
		if e != nil || len(b) != 7858 {
			return nil, errors.New("staged dependency length mismatch")
		}
		if _, e = os.Stat(inboxTarget); !os.IsNotExist(e) {
			return nil, errors.New("inbox dependency already exists or cannot be inspected")
		}
		if e = intent(dir, "restore-mshid-inbox-include"); e != nil {
			return nil, e
		}
		f, e := os.OpenFile(inboxTarget, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return nil, e
		}
		n, e := f.Write(b)
		if e != nil || n != len(b) {
			f.Close()
			return out, errors.New("incomplete new dependency write; do not retry")
		}
		e = f.Sync()
		ce := f.Close()
		if e != nil {
			return out, e
		}
		if ce != nil {
			return out, ce
		}
		h, e = digest(inboxTarget)
		if e != nil || h != inboxHash {
			return out, errors.New("restored dependency readback mismatch")
		}
		out["created_new_absent_file"] = true
		out["readback_verified"] = true
	} else if mode == "undo" {
		if len(roots) != 0 {
			return nil, errors.New("owned source must be removed before dependency undo")
		}
		if _, e = os.Stat(filepath.Join(dir, "G51-restore-mshid-inbox-include-intent.json")); e != nil {
			return nil, e
		}
		h, e := digest(inboxTarget)
		if e != nil || h != inboxHash {
			return nil, errors.New("dependency changed or missing; refusing removal")
		}
		if e = intent(dir, "undo-mshid-inbox-include"); e != nil {
			return nil, e
		}
		if e = os.Remove(inboxTarget); e != nil {
			return nil, e
		}
		out["owned_dependency_removed"] = true
	} else {
		return nil, errors.New("invalid dependency mode")
	}
	return out, nil
}
func main() {
	var v any
	var e error
	if runtime.GOARCH != "arm64" || runtime.NumCPU() != 8 {
		e = errors.New("physical phone required")
	} else if _, e = inventory(); e == nil {
		if len(os.Args) == 5 && (os.Args[1] == "restore" || os.Args[1] == "import") {
			_, d, x := checkManifest(os.Args[2], os.Args[3])
			if x != nil {
				e = x
			} else {
				v, e = dependency(os.Args[1], d, os.Args[4])
			}
		} else if len(os.Args) == 4 && os.Args[1] == "undo" {
			_, d, x := checkManifest(os.Args[2], os.Args[3])
			if x != nil {
				e = x
			} else {
				v, e = dependency("undo", d, "")
			}
		} else {
			e = errors.New("usage: restore manifest sha staged-INF | undo manifest sha")
		}
	}
	out := map[string]any{"ok": e == nil, "result": v}
	if e != nil {
		out["error"] = e.Error()
	}
	json.NewEncoder(os.Stdout).Encode(out)
	if e != nil {
		os.Exit(1)
	}
}
