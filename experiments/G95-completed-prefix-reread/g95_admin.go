// Source-built native manager for the OnePlus Open G95 input foundation.
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

type GUID struct {
	D1     uint32
	D2, D3 uint16
	D4     [8]byte
}

var sourceGUID = GUID{0x5f9cc9b9, 0xb53a, 0x4ec2, [8]byte{0xa8, 0x79, 0xb5, 0x8e, 0xfe, 0xdf, 0x0, 0x95}}

const rootID = `Root\OnePlusOpenTouchG95`

var classGUID = GUID{0x745a17a0, 0x74d3, 0x11d0, [8]byte{0xb6, 0xfe, 0, 0xa0, 0xc9, 0x0f, 0x57, 0xda}}

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
func roots() (any, error) {
	h, ds, e := ownRoots()
	if e != nil {
		return nil, e
	}
	defer setClose(h)
	out := []any{}
	for _, d := range ds {
		id, e := instance(h, &d)
		if e != nil {
			return nil, e
		}
		var state, problem uint32
		cr, _, _ := cfg.NewProc("CM_Get_DevNode_Status").Call(uintptr(unsafe.Pointer(&state)), uintptr(unsafe.Pointer(&problem)), uintptr(d.Inst), 0)
		out = append(out, map[string]any{"instance": id, "status": state, "problem": problem, "CM_result": cr})
	}
	return map[string]any{"owned_roots": out}, nil
}
func stage(d string) (any, error) {
	if e := intent(d, "stage"); e != nil {
		return nil, e
	}
	name := make([]uint16, 512)
	var need uint32
	r, _, e := setup.NewProc("SetupCopyOEMInfW").Call(uintptr(unsafe.Pointer(wide(filepath.Join(d, "OpenG95.inf")))), 0, 1, 0, uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)), uintptr(unsafe.Pointer(&need)), 0)
	if r == 0 {
		return nil, winerr("SetupCopyOEMInfW", e)
	}
	return map[string]any{"published_inf": syscall.UTF16ToString(name)}, nil
}
func create(d string) (any, error) {
	h, ds, e := ownRoots()
	if e != nil {
		return nil, e
	}
	setClose(h)
	if len(ds) != 0 {
		return nil, errors.New("owned root already exists; observe it")
	}
	if e = intent(d, "create"); e != nil {
		return nil, e
	}
	h, _, e = setup.NewProc("SetupDiCreateDeviceInfoList").Call(uintptr(unsafe.Pointer(&classGUID)), 0)
	if h == ^uintptr(0) {
		return nil, winerr("CreateDeviceInfoList", e)
	}
	defer setClose(h)
	info := devInfo{Size: 32}
	r, _, e := setup.NewProc("SetupDiCreateDeviceInfoW").Call(h, uintptr(unsafe.Pointer(wide("OnePlusOpenTouchG95"))), uintptr(unsafe.Pointer(&classGUID)), uintptr(unsafe.Pointer(wide("OnePlus Open G95 Touch Input Foundation"))), 0, 1, uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		return nil, winerr("CreateDeviceInfo", e)
	}
	b := append(syscall.StringToUTF16(rootID), 0)
	r, _, e = setup.NewProc("SetupDiSetDeviceRegistryPropertyW").Call(h, uintptr(unsafe.Pointer(&info)), 1, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)*2))
	if r == 0 {
		return nil, winerr("set exact root ID", e)
	}
	r, _, e = setup.NewProc("SetupDiCallClassInstaller").Call(0x19, h, uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		return nil, winerr("register root", e)
	}
	id, e := instance(h, &info)
	if e != nil {
		return nil, e
	}
	return map[string]any{"created": true, "instance": id}, nil
}
func bind(d string) (any, error) {
	h, ds, e := ownRoots()
	if e != nil {
		return nil, e
	}
	setClose(h)
	if len(ds) != 1 {
		return nil, errors.New("need exactly one owned root")
	}
	if e = intent(d, "bind"); e != nil {
		return nil, e
	}
	var reboot int32
	r, _, e := syscall.NewLazyDLL("newdev.dll").NewProc("UpdateDriverForPlugAndPlayDevicesW").Call(0, uintptr(unsafe.Pointer(wide(rootID))), uintptr(unsafe.Pointer(wide(filepath.Join(d, "OpenG95.inf")))), 5, uintptr(unsafe.Pointer(&reboot)))
	if r == 0 {
		return nil, winerr("bind G95 package", e)
	}
	return map[string]any{"bound": true, "reboot_requested": reboot != 0}, nil
}
func remove(d string) (any, error) {
	h, ds, e := ownRoots()
	if e != nil {
		return nil, e
	}
	defer setClose(h)
	if len(ds) != 1 {
		return nil, errors.New("need exactly one owned root")
	}
	id, e := instance(h, &ds[0])
	if e != nil {
		return nil, e
	}
	if e = intent(d, "remove"); e != nil {
		return nil, e
	}
	p := [4]uint32{8, 5, 1, 0}
	r, _, e := setup.NewProc("SetupDiSetClassInstallParamsW").Call(h, uintptr(unsafe.Pointer(&ds[0])), uintptr(unsafe.Pointer(&p[0])), 16)
	if r == 0 {
		return nil, winerr("remove parameters", e)
	}
	r, _, e = setup.NewProc("SetupDiCallClassInstaller").Call(5, h, uintptr(unsafe.Pointer(&ds[0])))
	if r == 0 {
		return nil, winerr("remove owned root", e)
	}
	return map[string]any{"remove_requested": true, "instance": id}, nil
}
func uninstallPackage(d, name string, want string) (any, error) {
	h, ds, e := ownRoots()
	if e != nil {
		return nil, e
	}
	setClose(h)
	if len(ds) != 0 {
		return nil, errors.New("remove owned root before its package")
	}
	name = filepath.Base(name)
	if !strings.HasPrefix(strings.ToLower(name), "oem") || !strings.HasSuffix(strings.ToLower(name), ".inf") {
		return nil, errors.New("only an owned published OEM INF may be removed")
	}
	middle := name[3 : len(name)-4]
	if middle == "" {
		return nil, errors.New("invalid published INF")
	}
	for _, c := range middle {
		if c < '0' || c > '9' {
			return nil, errors.New("invalid published INF")
		}
	}
	got, e := digest(filepath.Join(`C:\Windows\INF`, name))
	if e != nil || got != want {
		return nil, errors.New("published INF does not match exact G95 package")
	}
	if e = intent(d, "uninstall-package"); e != nil {
		return nil, e
	}
	r, _, e := setup.NewProc("SetupUninstallOEMInfW").Call(uintptr(unsafe.Pointer(wide(name))), 0, 0)
	if r == 0 {
		return nil, winerr("uninstall owned package", e)
	}
	return map[string]any{"uninstalled": name}, nil
}
func interfaces(g *GUID) ([]string, error) {
	var n uint32
	r, _, _ := cfg.NewProc("CM_Get_Device_Interface_List_SizeW").Call(uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(g)), 0, 0)
	if r != 0 {
		return nil, fmt.Errorf("interface list size CR%x", r)
	}
	if n == 0 {
		return []string{}, nil
	}
	if n > 65536 {
		return nil, errors.New("excessive interface list")
	}
	b := make([]uint16, n)
	r, _, _ = cfg.NewProc("CM_Get_Device_Interface_ListW").Call(uintptr(unsafe.Pointer(g)), 0, uintptr(unsafe.Pointer(&b[0])), uintptr(n), 0)
	if r != 0 {
		return nil, fmt.Errorf("interface list CR%x", r)
	}
	return multi(b), nil
}

func childTree() (any, error) {
	h, ds, e := ownRoots()
	if e != nil {
		return nil, e
	}
	defer setClose(h)
	out := []any{}
	if len(ds) == 0 {
		return map[string]any{"tree": out}, nil
	}
	var walk func(uint32, int) error
	nodes := 0
	walk = func(inst uint32, depth int) error {
		nodes++
		if nodes > 16 || depth > 8 {
			return errors.New("unexpected owned device tree size")
		}
		b := make([]uint16, 512)
		cr, _, _ := cfg.NewProc("CM_Get_Device_IDW").Call(uintptr(inst), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
		if cr != 0 {
			return fmt.Errorf("CM device ID CR%x", cr)
		}
		var state, problem uint32
		cr, _, _ = cfg.NewProc("CM_Get_DevNode_Status").Call(uintptr(unsafe.Pointer(&state)), uintptr(unsafe.Pointer(&problem)), uintptr(inst), 0)
		out = append(out, map[string]any{"depth": depth, "id": syscall.UTF16ToString(b), "status": state, "problem": problem, "CM_result": cr})
		var child uint32
		cr, _, _ = cfg.NewProc("CM_Get_Child").Call(uintptr(unsafe.Pointer(&child)), uintptr(inst), 0)
		if cr != 0 {
			return nil
		}
		for {
			if e := walk(child, depth+1); e != nil {
				return e
			}
			var next uint32
			cr, _, _ = cfg.NewProc("CM_Get_Sibling").Call(uintptr(unsafe.Pointer(&next)), uintptr(child), 0)
			if cr != 0 {
				break
			}
			child = next
		}
		return nil
	}
	if e = walk(ds[0].Inst, 0); e != nil {
		return nil, e
	}
	return map[string]any{"tree": out}, nil
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

type ifaceData struct {
	Size     uint32
	Class    GUID
	Flags    uint32
	Reserved uintptr
}

func hidCaps() (any, error) {
	parent, ds, e := ownRoots()
	if e != nil {
		return nil, e
	}
	defer setClose(parent)
	if len(ds) != 1 {
		return nil, errors.New("need one owned source root")
	}
	hid := syscall.NewLazyDLL("hid.dll")
	if e = hid.Load(); e != nil {
		return nil, e
	}
	var guid GUID
	hid.NewProc("HidD_GetHidGuid").Call(uintptr(unsafe.Pointer(&guid)))
	h, _, e := setup.NewProc("SetupDiGetClassDevsW").Call(uintptr(unsafe.Pointer(&guid)), 0, 0, 0x12)
	if h == ^uintptr(0) {
		return nil, winerr("list HID interfaces", e)
	}
	defer setClose(h)
	out := []any{}
	for i := uint32(0); ; i++ {
		it := ifaceData{Size: 32}
		r, _, e := setup.NewProc("SetupDiEnumDeviceInterfaces").Call(h, 0, uintptr(unsafe.Pointer(&guid)), uintptr(i), uintptr(unsafe.Pointer(&it)))
		if r == 0 {
			if errors.Is(e, syscall.Errno(259)) {
				break
			}
			return nil, winerr("enum HID interfaces", e)
		}
		var need uint32
		setup.NewProc("SetupDiGetDeviceInterfaceDetailW").Call(h, uintptr(unsafe.Pointer(&it)), 0, 0, uintptr(unsafe.Pointer(&need)), 0)
		if need < 8 || need > 65536 {
			return nil, errors.New("invalid interface detail size")
		}
		b := make([]byte, need)
		binary.LittleEndian.PutUint32(b, 8)
		d := devInfo{Size: 32}
		r, _, e = setup.NewProc("SetupDiGetDeviceInterfaceDetailW").Call(h, uintptr(unsafe.Pointer(&it)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&need)), uintptr(unsafe.Pointer(&d)))
		if r == 0 {
			return nil, winerr("HID interface detail", e)
		}
		if !isDescendant(d.Inst, ds[0].Inst) {
			continue
		}
		path := textAt(uintptr(unsafe.Pointer(&b[4])))
		fh, e := syscall.CreateFile(wide(path), 0, 3, nil, 3, 0, 0)
		if e != nil {
			return nil, e
		}
		result, e := func() (any, error) {
			defer syscall.CloseHandle(fh)
			var prep uintptr
			r, _, e := hid.NewProc("HidD_GetPreparsedData").Call(uintptr(fh), uintptr(unsafe.Pointer(&prep)))
			if r == 0 {
				return nil, winerr("HidD_GetPreparsedData", e)
			}
			defer hid.NewProc("HidD_FreePreparsedData").Call(prep)
			var caps [64]byte
			status, _, _ := hid.NewProc("HidP_GetCaps").Call(prep, uintptr(unsafe.Pointer(&caps[0])))
			if uint32(status) != 0x00110000 {
				return nil, fmt.Errorf("HidP_GetCaps status%x", status)
			}
			u := func(at int) uint16 { return binary.LittleEndian.Uint16(caps[at:]) }
			feature := []byte{2, 0}
			ok, _, err := hid.NewProc("HidD_GetFeature").Call(uintptr(fh), uintptr(unsafe.Pointer(&feature[0])), 2)
			row := map[string]any{"usage": u(0), "usage_page": u(2), "input_report_bytes": u(4), "output_report_bytes": u(6), "feature_report_bytes": u(8), "link_collections": u(44), "input_button_caps": u(46), "input_value_caps": u(48), "feature_value_caps": u(60), "max_contact_feature_ok": ok != 0, "max_contact_feature": []uint32{uint32(feature[0]), uint32(feature[1])}}
			if ok == 0 {
				row["feature_error"] = err.Error()
			}
			row["interface_path"] = path
			count := u(48)
			if count == 0 || count > 512 {
				return nil, errors.New("unexpected owned input value-cap count")
			}
			raw := make([]byte, int(count)*72)
			reported := count
			hs, _, _ := hid.NewProc("HidP_GetValueCaps").Call(0, uintptr(unsafe.Pointer(&raw[0])), uintptr(unsafe.Pointer(&reported)), prep)
			if uint32(hs) != 0x00110000 || reported != count {
				return nil, fmt.Errorf("HidP_GetValueCaps status%x count%d/%d", hs, reported, count)
			}
			valueCaps := []any{}
			for at := 0; at < len(raw); at += 72 {
				b := raw[at : at+72]
				v16 := func(i int) uint16 { return binary.LittleEndian.Uint16(b[i:]) }
				v32 := func(i int) uint32 { return binary.LittleEndian.Uint32(b[i:]) }
				valueCaps = append(valueCaps, map[string]any{"usage_page": v16(0), "report_id": b[2], "link_collection": v16(6), "is_range": b[12], "absolute": b[15], "bit_size": v16(18), "report_count": v16(20), "units_exponent_raw": v32(32), "units": v32(36), "logical_min": int32(v32(40)), "logical_max": int32(v32(44)), "physical_min": int32(v32(48)), "physical_max": int32(v32(52)), "usage_or_min": v16(56), "usage_max": v16(58)})
			}
			row["input_values"] = valueCaps

			return row, nil
		}()
		if e != nil {
			return nil, e
		}
		out = append(out, result)
		runtime.KeepAlive(b)
	}
	return map[string]any{"owned_HID_interfaces": out}, nil
}
func sourceStatus() (any, error) {
	paths, e := interfaces(&sourceGUID)
	if e != nil {
		return nil, e
	}
	if len(paths) != 1 {
		return nil, fmt.Errorf("expected one G95 interface; got %d", len(paths))
	}
	h, e := syscall.CreateFile(wide(paths[0]), 0x80000000, 0, nil, 3, 0, 0)
	if e != nil {
		return nil, e
	}
	defer syscall.CloseHandle(h)
	in := make([]byte, 16)
	binary.LittleEndian.PutUint32(in, 16)
	binary.LittleEndian.PutUint32(in[4:], 1)
	copy(in[8:], []byte("OPG95HD1"))
	out := make([]byte, 160)
	var n uint32
	e = syscall.DeviceIoControl(h, 0x226400, &in[0], 16, &out[0], 160, &n, nil)
	if e != nil {
		return nil, e
	}
	if n != 160 {
		return nil, errors.New("source response size differs")
	}
	return parseStatus(out)
}
func parseStatus(out []byte) (map[string]any, error) {
	if len(out) != 160 || binary.LittleEndian.Uint32(out) != 160 || binary.LittleEndian.Uint32(out[4:]) != 1 || string(out[8:16]) != "OPG95HD1" || strings.TrimRight(string(out[112:128]), "\x00") != "G95-stream1" {
		return nil, errors.New("source status identity/size mismatch")
	}
	names := []string{"kernel_build", "processors", "IRQL", "firmware_bytes", "firmware_match", "D0", "started", "create_status", "start_status", "D0_entries", "D0_exits", "feature_callbacks", "live_attempts", "reports_accepted", "last_submit_status", "max_contacts", "raw_X_max", "raw_Y_max", "report_bytes", "descriptor_bytes", "mapping_qualified"}
	v := map[string]any{"sequence": binary.LittleEndian.Uint64(out[104:]), "build": "G95-stream1"}
	for i, name := range names {
		v[name] = binary.LittleEndian.Uint32(out[16+i*4:])
	}
	for i, n := range []string{"live_complete", "live_error", "stop_attempts", "stop_accepted", "accepted_mask", "accepted_generation", "reports_submitted", "reserved"} {
		v[n] = binary.LittleEndian.Uint32(out[128+i*4:])
	}
	return v, nil
}

type ReceiverReady struct {
	TrialMode            string
	Token                string
	PID                  uint32
	Window               uintptr
	Tick                 uint64
	Class, Title         string
	Width, Height        int32
	Foreground, DPIAware bool
}

func receiverGuard(path string) (ReceiverReady, error) {
	var r ReceiverReady
	b, e := os.ReadFile(path)
	if e != nil {
		return r, e
	}
	if e = json.Unmarshal(b, &r); e != nil {
		return r, e
	}
	if len(r.Token) != 32 || r.Class != "OpenG95PointerReceiver" || r.Title != "G95 pointer receiver "+r.Token || r.Window == 0 || r.PID == 0 || !r.DPIAware {
		return r, errors.New("invalid receiver identity or DPI contract")
	}
	for _, c := range r.Token {
		if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return r, errors.New("invalid receiver token")
		}
	}
	now, _, _ := kernel.NewProc("GetTickCount64").Call()
	if uint64(now) < r.Tick || uint64(now)-r.Tick > 30000 {
		return r, errors.New("receiver readiness expired")
	}
	var pid uint32
	user.NewProc("GetWindowThreadProcessId").Call(r.Window, uintptr(unsafe.Pointer(&pid)))
	fg, _, _ := user.NewProc("GetForegroundWindow").Call()
	valid, _, _ := user.NewProc("IsWindow").Call(r.Window)
	text := func(proc string) string {
		var b [256]uint16
		n, _, _ := user.NewProc(proc).Call(r.Window, uintptr(unsafe.Pointer(&b[0])), 256)
		if n >= 256 {
			return ""
		}
		return syscall.UTF16ToString(b[:n])
	}
	width, _, _ := user.NewProc("GetSystemMetrics").Call(0)
	height, _, _ := user.NewProc("GetSystemMetrics").Call(1)
	if valid == 0 || fg != r.Window || pid != r.PID || text("GetClassNameW") != r.Class || text("GetWindowTextW") != r.Title || r.Width != int32(width) || r.Height != int32(height) {
		return r, errors.New("owned full-screen receiver must be foreground")
	}
	var rectangle struct{ Left, Top, Right, Bottom int32 }
	ok, _, _ := user.NewProc("GetWindowRect").Call(r.Window, uintptr(unsafe.Pointer(&rectangle)))
	if ok == 0 || rectangle.Left != 0 || rectangle.Top != 0 || rectangle.Right != r.Width || rectangle.Bottom != r.Height {
		return r, errors.New("owned receiver must cover the full display")
	}
	r.Foreground = true
	return r, nil
}

func adminMain() (any, error) {
	if e := fullOSGuard(); e != nil {
		return nil, e
	}
	if len(os.Args) < 2 {
		return nil, errors.New("need mode")
	}
	if runtime.GOARCH != "arm64" || runtime.NumCPU() != 8 {
		return nil, errors.New("requires physical eight-CPU ARM64 phone")
	}
	if _, e := inventory(); e != nil {
		return nil, e
	}
	mode := os.Args[1]
	switch mode {
	case "inventory":
		return inventory()
	case "roots":
		return roots()
	case "tree":
		return childTree()
	case "hid-caps":
		return hidCaps()
	case "status":
		return sourceStatus()
	case "hw-status", "snapshot", "pmic", "session":
		if len(os.Args) != 2 {
			return nil, errors.New("read mode takes no paths")
		}
		return hardware(mode, "", "")
	case "live", "live-stop", "live-close", "hardware-episode":
		if len(os.Args) != 4 {
			return nil, errors.New("live requires fresh receiver readiness and exclusive result path")
		}
		return hardware(mode, os.Args[2], os.Args[3])
	}
	if len(os.Args) != 4 && !(mode == "uninstall-package" && len(os.Args) == 5) {
		return nil, errors.New("mutation needs exact manifest path and SHA256")
	}
	m, d, e := checkManifest(os.Args[2], os.Args[3])
	if e != nil {
		return nil, e
	}
	switch mode {
	case "stage":
		return stage(d)
	case "create":
		return create(d)
	case "bind":
		if e := syscall.NewLazyDLL("newdev.dll").NewProc("UpdateDriverForPlugAndPlayDevicesW").Find(); e != nil {
			return nil, e
		}
		return bind(d)
	case "remove":
		return remove(d)
	case "uninstall-package":
		return uninstallPackage(d, os.Args[4], m.Files["OpenG95.inf"])
	}
	return nil, errors.New("unsupported mode")
}
func main() {
	v, e := adminMain()
	r := map[string]any{"ok": e == nil, "result": v}
	if e != nil {
		r["error"] = e.Error()
	}
	json.NewEncoder(os.Stdout).Encode(r)
	if e != nil {
		os.Exit(1)
	}
}
