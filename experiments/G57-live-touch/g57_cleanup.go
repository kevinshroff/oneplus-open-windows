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

const rootID = `Root\OnePlusOpenTouchG57`

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
	if m.Version != "G57-package-1" || len(m.Files) != 4 {
		return m, "", errors.New("unexpected package manifest")
	}
	d := filepath.Dir(path)
	for _, n := range []string{"OpenG57.inf", "OpenG57.sys", "OpenG57.cat", "G57-public.cer"} {
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
	p := filepath.Join(d, "G57-"+phase+"-intent.json")
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
		return 0, nil, errors.New("multiple owned G57 roots; refusing mutation")
	}
	return h, out, nil
}

const inboxHash = "086cfd93451de78d172384de4956a04443eb5d92576db316471085066558f92a"
const inboxTarget = `X:\Windows\INF\mshidkmdf.inf`

func sourceInterfaces() ([]string, error) {
	g := GUID{0x5f9cc9b7, 0xb53a, 0x4ec2, [8]byte{0xa8, 0x79, 0xb5, 0x8e, 0xfe, 0xdf, 0, 0x57}}
	var n uint32
	r, _, _ := cfg.NewProc("CM_Get_Device_Interface_List_SizeW").Call(uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&g)), 0, 0)
	if r != 0 || n > 65536 {
		return nil, errors.New("source interface length unavailable")
	}
	if n == 0 {
		return []string{}, nil
	}
	b := make([]uint16, n)
	r, _, _ = cfg.NewProc("CM_Get_Device_Interface_ListW").Call(uintptr(unsafe.Pointer(&g)), 0, uintptr(unsafe.Pointer(&b[0])), uintptr(n), 0)
	if r != 0 {
		return nil, errors.New("source interface inventory failed")
	}
	return multi(b), nil
}
func audit() (any, error) {
	h, roots, e := ownRoots()
	if e != nil {
		return nil, e
	}
	setClose(h)
	ifs, e := sourceInterfaces()
	if e != nil {
		return nil, e
	}
	inv, e := inventory()
	if e != nil {
		return nil, e
	}
	return map[string]any{"owned_roots": len(roots), "source_interfaces": ifs, "source_service": service("OpenG57"), "inbox_include": file(inboxTarget), "inventory": inv, "processors": runtime.NumCPU(), "native_mutations": 0}, nil
}
func noSource() error {
	h, roots, e := ownRoots()
	if e != nil {
		return e
	}
	setClose(h)
	if len(roots) != 0 {
		return errors.New("owned root still present")
	}
	ifs, e := sourceInterfaces()
	if e != nil {
		return e
	}
	if len(ifs) != 0 {
		return errors.New("source interface still present")
	}
	return nil
}

func deleteSource(dir string, m manifest) (any, error) {
	if e := noSource(); e != nil {
		return nil, e
	}
	for _, phase := range []string{"bind", "remove"} {
		if _, e := os.Stat(filepath.Join(dir, "G57-"+phase+"-intent.json")); e != nil {
			return nil, e
		}
	}
	sc, _, e := adv.NewProc("OpenSCManagerW").Call(0, 0, 1)
	if sc == 0 {
		return nil, winerr("OpenSCManager", e)
	}
	defer closeSvc(sc)
	svc, _, e := adv.NewProc("OpenServiceW").Call(sc, uintptr(unsafe.Pointer(wide("OpenG57"))), 0x10000|1|4)
	if svc == 0 {
		if errors.Is(e, syscall.Errno(1060)) {
			return map[string]any{"source_service_absent": true, "already_absent": true}, nil
		}
		return nil, winerr("open owned source service", e)
	}
	defer closeSvc(svc)
	row := service("OpenG57")
	if row["state"] != uint32(1) || row["type"] != uint32(1) || row["start_type"] != uint32(3) {
		return nil, errors.New("owned source service is not stopped with expected configuration")
	}
	path, ok := row["binary"].(string)
	low := strings.ToLower(strings.ReplaceAll(path, `\\`, `\`))
	if !ok || !strings.HasPrefix(low, `\systemroot\system32\driverstore\filerepository\openg57.inf_arm64_`) || !strings.HasSuffix(low, `\openg57.sys`) {
		return nil, errors.New("owned source service image path mismatch")
	}
	actual := `X:\Windows` + low[len(`\systemroot`):]
	h, e := digest(actual)
	if e != nil || h != m.Files["OpenG57.sys"] {
		return nil, errors.New("stopped source image bytes mismatch")
	}
	if e = intent(dir, "delete-owned-stopped-source-service"); e != nil {
		return nil, e
	}
	r, _, e := adv.NewProc("DeleteService").Call(svc)
	if r == 0 {
		return nil, winerr("delete exact owned stopped source service", e)
	}
	return map[string]any{"source_service_delete_requested": true, "image_sha256": h, "service_before": row}, nil
}
func main() {
	var v any
	var e error
	if runtime.GOARCH != "arm64" || runtime.NumCPU() != 8 {
		e = errors.New("physical phone required")
	} else if _, e = inventory(); e == nil {
		if len(os.Args) == 2 && os.Args[1] == "audit" {
			v, e = audit()
		} else if len(os.Args) == 4 || len(os.Args) == 5 {
			var m manifest
			var d string
			m, d, e = checkManifest(os.Args[2], os.Args[3])
			if e == nil {
				switch os.Args[1] {
				case "delete-source-service":
					if len(os.Args) != 4 {
						e = errors.New("argument count")
					} else {
						v, e = deleteSource(d, m)
					}
				default:
					e = errors.New("invalid cleanup mode")
				}
			}
		} else {
			e = errors.New("usage: audit | delete-source-service manifest hash")
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
