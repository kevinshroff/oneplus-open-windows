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

const rootID = `Root\OnePlusOpenTouchG95`

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
		files = append(files, file(`C:\Windows\System32\drivers\`+n))
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
	if m.Version != "G95-package-1" || len(m.Files) != 4 {
		return m, "", errors.New("unexpected package manifest")
	}
	d := filepath.Dir(path)
	for _, n := range []string{"OpenG95.inf", "OpenG95.sys", "OpenG95.cat", "G95-public.cer"} {
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
	p := filepath.Join(d, "G95-"+phase+"-intent.json")
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
		return 0, nil, errors.New("multiple owned G95 roots; refusing mutation")
	}
	return h, out, nil
}
func isDescendant(inst, root uint32) bool {
	for i := 0; i < 12; i++ {
		if inst == root {
			return true
		}
		var p uint32
		r, _, _ := cfg.NewProc("CM_Get_Parent").Call(uintptr(unsafe.Pointer(&p)), uintptr(inst), 0)
		if r != 0 || p == inst {
			return false
		}
		inst = p
	}
	return false
}
func describeChildren() (any, error) {
	parent, roots, e := ownRoots()
	if e != nil {
		return nil, e
	}
	setClose(parent)
	if len(roots) != 1 {
		return nil, errors.New("need exactly one owned source root")
	}
	h, _, e := setup.NewProc("SetupDiGetClassDevsW").Call(0, 0, 0, 6)
	if h == ^uintptr(0) {
		return nil, winerr("all present devices", e)
	}
	defer setClose(h)
	rows := []any{}
	for i := uint32(0); ; i++ {
		d := devInfo{Size: 32}
		r, _, e := setup.NewProc("SetupDiEnumDeviceInfo").Call(h, uintptr(i), uintptr(unsafe.Pointer(&d)))
		if r == 0 {
			if errors.Is(e, syscall.Errno(259)) {
				break
			}
			return nil, winerr("enum present", e)
		}
		if d.Inst == roots[0].Inst || !isDescendant(d.Inst, roots[0].Inst) {
			continue
		}
		id, e := instance(h, &d)
		if e != nil {
			return nil, e
		}
		var state, problem uint32
		cr, _, _ := cfg.NewProc("CM_Get_DevNode_Status").Call(uintptr(unsafe.Pointer(&state)), uintptr(unsafe.Pointer(&problem)), uintptr(d.Inst), 0)
		row := map[string]any{"instance": id, "state": state, "problem": problem, "status_CR": cr}
		for name, key := range map[string]uint32{"hardware_ids": 1, "compatible_ids": 2, "description": 0, "service": 4, "class": 7, "class_guid": 8, "driver_key": 9, "manufacturer": 11} {
			b, x := prop(h, &d, key)
			if x == nil {
				row[name] = multi(b)
			} else {
				row[name+"_error"] = x.Error()
			}
		}
		rows = append(rows, row)
	}
	return map[string]any{"owned_descendants": rows, "native_mutations": 0}, nil
}
func ownedChild() (uintptr, devInfo, error) {
	parent, roots, e := ownRoots()
	if e != nil {
		return 0, devInfo{}, e
	}
	setClose(parent)
	if len(roots) != 1 {
		return 0, devInfo{}, errors.New("need exactly one owned source root")
	}
	h, _, e := setup.NewProc("SetupDiGetClassDevsW").Call(0, 0, 0, 6)
	if h == ^uintptr(0) {
		return 0, devInfo{}, winerr("all present devices", e)
	}
	found := []devInfo{}
	for i := uint32(0); ; i++ {
		d := devInfo{Size: 32}
		r, _, e := setup.NewProc("SetupDiEnumDeviceInfo").Call(h, uintptr(i), uintptr(unsafe.Pointer(&d)))
		if r == 0 {
			if errors.Is(e, syscall.Errno(259)) {
				break
			}
			setClose(h)
			return 0, devInfo{}, winerr("enum present", e)
		}
		if d.Inst == roots[0].Inst || !isDescendant(d.Inst, roots[0].Inst) {
			continue
		}
		b, e := prop(h, &d, 1)
		if e != nil {
			continue
		}
		for _, id := range multi(b) {
			if strings.EqualFold(id, `OPENLAB\ONEPLUSOPENTOUCHG95`) {
				found = append(found, d)
				break
			}
		}
	}
	if len(found) != 1 {
		setClose(h)
		return 0, devInfo{}, fmt.Errorf("expected exactly one owned VHF child, got %d", len(found))
	}
	return h, found[0], nil
}

type childManifest struct {
	Version string            `json:"version"`
	Base    string            `json:"base_manifest_sha256"`
	Files   map[string]string `json:"files"`
}

func checkChild(path, want, base string) (childManifest, string, error) {
	var m childManifest
	h, e := digest(path)
	if e != nil || h != want {
		return m, "", errors.New("child manifest hash mismatch")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return m, "", e
	}
	if e = json.Unmarshal(b, &m); e != nil {
		return m, "", e
	}
	if m.Version != "G95-vhf-package-1" || m.Base != base || len(m.Files) != 3 {
		return m, "", errors.New("child package/base binding mismatch")
	}
	d := filepath.Dir(path)
	for _, name := range []string{"G95Vhf.inf", "G95Vhf.cat", "G95-public.cer"} {
		v, ok := m.Files[name]
		if !ok {
			return m, "", errors.New("missing child file")
		}
		h, e = digest(filepath.Join(d, name))
		if e != nil || h != v {
			return m, "", errors.New("child package bytes mismatch")
		}
	}
	h, e = digest(`C:\Windows\System32\drivers\mshidkmdf.sys`)
	if e != nil || h != "c363d97c5f036acc7a863e98d949c32873a056b37aabef02a17b37a3a9fe272c" {
		return m, "", errors.New("existing Microsoft miniport identity mismatch")
	}
	return m, d, nil
}

// DiInstallDevice's failed cleanup left this owned child problem-free but
// unbound. Permit that observed state only when neither driver-loaded nor
// started is set and Windows explicitly reports SPDRP_SERVICE as absent.
func unboundChild(h uintptr, d *devInfo, state, problem uint32) bool {
	if state&(8|2) != 0 {
		return false
	}
	if problem == 1 || problem == 28 {
		return true
	}
	if problem != 0 {
		return false
	}
	var n, t uint32
	r, _, e := setup.NewProc("SetupDiGetDeviceRegistryPropertyW").Call(h, uintptr(unsafe.Pointer(d)), 4, uintptr(unsafe.Pointer(&t)), 0, 0, uintptr(unsafe.Pointer(&n)))
	return r == 0 && n == 0 && errors.Is(e, syscall.Errno(13))
}
func stageChild(dir string) (any, error) {
	h, d, e := ownedChild()
	if e != nil {
		return nil, e
	}
	defer setClose(h)
	var state, problem uint32
	r, _, _ := cfg.NewProc("CM_Get_DevNode_Status").Call(uintptr(unsafe.Pointer(&state)), uintptr(unsafe.Pointer(&problem)), uintptr(d.Inst), 0)
	if r != 0 || !unboundChild(h, &d, state, problem) {
		return nil, errors.New("unexpected child state before package stage")
	}
	if e = intent(dir, "stage-owned-vhf-binding"); e != nil {
		return nil, e
	}
	name := make([]uint16, 512)
	var need uint32
	r, _, e = setup.NewProc("SetupCopyOEMInfW").Call(uintptr(unsafe.Pointer(wide(filepath.Join(dir, "G95Vhf.inf")))), 0, 1, 0, uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)), uintptr(unsafe.Pointer(&need)), 0)
	if r == 0 {
		return nil, winerr("stage sealed child binding", e)
	}
	return map[string]any{"published_inf": syscall.UTF16ToString(name), "device_install_performed": false}, nil
}
func configure(mode, dir string) (any, error) {
	h, d, e := ownedChild()
	if e != nil {
		return nil, e
	}
	defer setClose(h)
	id, e := instance(h, &d)
	if e != nil {
		return nil, e
	}
	var state, problem uint32
	cr, _, _ := cfg.NewProc("CM_Get_DevNode_Status").Call(uintptr(unsafe.Pointer(&state)), uintptr(unsafe.Pointer(&problem)), uintptr(d.Inst), 0)
	if cr != 0 {
		return nil, fmt.Errorf("owned child status CR%x", cr)
	}
	params := make([]byte, 584)
	binary.LittleEndian.PutUint32(params, 584)
	r, _, e := setup.NewProc("SetupDiGetDeviceInstallParamsW").Call(h, uintptr(unsafe.Pointer(&d)), uintptr(unsafe.Pointer(&params[0])))
	if r == 0 {
		return nil, winerr("get owned child parameters", e)
	}
	flags := binary.LittleEndian.Uint32(params[4:]) | 0x00800000 | 0x00010000 // QUIETINSTALL | ENUMSINGLEINF
	binary.LittleEndian.PutUint32(params[4:], flags)
	path := syscall.StringToUTF16(filepath.Join(dir, "G95Vhf.inf"))
	if len(path) > 260 {
		return nil, errors.New("single INF path exceeds SDK layout")
	}
	for i, v := range path {
		binary.LittleEndian.PutUint16(params[60+i*2:], v)
	}
	r, _, e = setup.NewProc("SetupDiSetDeviceInstallParamsW").Call(h, uintptr(unsafe.Pointer(&d)), uintptr(unsafe.Pointer(&params[0])))
	if r == 0 {
		return nil, winerr("set exact single INF search", e)
	}
	r, _, e = setup.NewProc("SetupDiBuildDriverInfoList").Call(h, uintptr(unsafe.Pointer(&d)), 2)
	if r == 0 {
		return nil, winerr("build exact child binding driver list", e)
	}
	defer setup.NewProc("SetupDiDestroyDriverInfoList").Call(h, uintptr(unsafe.Pointer(&d)), 2)
	candidates := []any{}
	var selected []byte
	for i := uint32(0); i < 16; i++ {
		b := make([]byte, 1568)
		binary.LittleEndian.PutUint32(b, 1568)
		r, _, e = setup.NewProc("SetupDiEnumDriverInfoW").Call(h, uintptr(unsafe.Pointer(&d)), 2, uintptr(i), uintptr(unsafe.Pointer(&b[0])))
		if r == 0 {
			if errors.Is(e, syscall.Errno(259)) {
				break
			}
			return nil, winerr("enum exact binding drivers", e)
		}
		row := map[string]any{"description": textAt(uintptr(unsafe.Pointer(&b[16]))), "manufacturer": textAt(uintptr(unsafe.Pointer(&b[528]))), "provider": textAt(uintptr(unsafe.Pointer(&b[1040]))), "version": binary.LittleEndian.Uint64(b[1560:])}
		candidates = append(candidates, row)
		if i == 0 {
			selected = append([]byte(nil), b...)
		}
		runtime.KeepAlive(b)
	}
	out := map[string]any{"instance": id, "state_before": state, "problem_before": problem, "compatible_drivers": candidates, "exact_INF": filepath.Join(dir, "G95Vhf.inf"), "installed": false, "service_before": service("mshidkmdf")}
	if len(candidates) != 1 || candidates[0].(map[string]any)["provider"] != "OnePlus Open Private Lab" {
		return out, errors.New("need exactly the sealed project binding candidate")
	}
	if mode == "probe" {
		return out, nil
	}
	if mode != "install" {
		return nil, errors.New("invalid child binding mode")
	}
	if !unboundChild(h, &d, state, problem) {
		return out, errors.New("unexpected or already started child")
	}
	svc := service("mshidkmdf")
	if svc["present"] != true || svc["start_type"] != uint32(3) || svc["type"] != uint32(1) {
		return out, errors.New("existing inbox service changed")
	}
	if e = intent(dir, "bind-owned-vhf-selfcontained"); e != nil {
		return nil, e
	}
	var reboot uint32
	r, _, e = syscall.NewLazyDLL("newdev.dll").NewProc("DiInstallDevice").Call(0, h, uintptr(unsafe.Pointer(&d)), uintptr(unsafe.Pointer(&selected[0])), 0, uintptr(unsafe.Pointer(&reboot)))
	runtime.KeepAlive(selected)
	runtime.KeepAlive(params)
	out["installation_API"] = "DiInstallDevice"
	out["restart_required"] = reboot != 0
	if r == 0 {
		return out, winerr("install exact sealed binding on owned VHF child", e)
	}
	out["installed"] = true
	out["service_after"] = service("mshidkmdf")
	return out, nil
}
func uninstallChild(dir, published string, m childManifest) (any, error) {
	h, roots, e := ownRoots()
	if e != nil {
		return nil, e
	}
	setClose(h)
	if len(roots) != 0 {
		return nil, errors.New("remove owned source before uninstalling child binding")
	}
	name := strings.ToLower(filepath.Base(published))
	if !strings.HasPrefix(name, "oem") || !strings.HasSuffix(name, ".inf") {
		return nil, errors.New("need published OEM INF name")
	}
	middle := strings.TrimSuffix(strings.TrimPrefix(name, "oem"), ".inf")
	if len(middle) == 0 {
		return nil, errors.New("empty OEM index")
	}
	for _, c := range middle {
		if c < '0' || c > '9' {
			return nil, errors.New("invalid OEM index")
		}
	}
	got, e := digest(filepath.Join(`C:\Windows\INF`, name))
	if e != nil || got != m.Files["G95Vhf.inf"] {
		return nil, errors.New("published OEM binding hash mismatch")
	}
	if e = intent(dir, "uninstall-owned-vhf-binding"); e != nil {
		return nil, e
	}
	r, _, e := setup.NewProc("SetupUninstallOEMInfW").Call(uintptr(unsafe.Pointer(wide(name))), 0, 0)
	if r == 0 {
		return nil, winerr("uninstall owned child binding", e)
	}
	return map[string]any{"uninstalled": name, "forced": false}, nil
}
func main() {
	var v any
	var e error
	if e = fullOSGuard(); e != nil {
	} else if runtime.GOARCH != "arm64" || runtime.NumCPU() != 8 {
		e = errors.New("physical phone required")
	} else if _, e = inventory(); e == nil {
		if len(os.Args) == 2 && os.Args[1] == "describe" {
			v, e = describeChildren()
		} else if len(os.Args) == 6 || len(os.Args) == 7 {
			_, _, e = checkManifest(os.Args[2], os.Args[3])
			if e == nil {
				var m childManifest
				var d string
				m, d, e = checkChild(os.Args[4], os.Args[5], os.Args[3])
				if e == nil {
					switch os.Args[1] {
					case "stage":
						if len(os.Args) != 6 {
							e = errors.New("argument count")
						} else {
							v, e = stageChild(d)
						}
					case "probe", "install":
						if len(os.Args) != 6 {
							e = errors.New("argument count")
						} else {
							v, e = configure(os.Args[1], d)
						}
					case "uninstall":
						if len(os.Args) != 7 {
							e = errors.New("argument count")
						} else {
							v, e = uninstallChild(d, os.Args[6], m)
						}
					default:
						e = errors.New("invalid mode")
					}
				}
			}
		} else {
			e = errors.New("usage: describe | stage/probe/install base-manifest hash child-manifest hash | uninstall base-manifest hash child-manifest hash published-INF")
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
