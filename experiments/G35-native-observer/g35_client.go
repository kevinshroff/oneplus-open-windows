//go:build windows

// SPDX-License-Identifier: MIT
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
	"unicode/utf16"
	"unsafe"
)

const magic uint64 = 0x314f52463533474f
const ioctlStatus uintptr = 0x226000
const ioctlSnapshot uintptr = 0x226004
const ioctlPMIC uintptr = 0x226008
const firmwareSHA = "c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01"
const device = `\\.\OpenG35`
const service = "OpenG35"

var kernel = syscall.NewLazyDLL("kernel32.dll")
var advapi = syscall.NewLazyDLL("advapi32.dll")

type registerField struct {
	Name    string
	Address uint64
}
type Status struct {
	Size           uint32 `json:"size"`
	Version        uint32 `json:"version"`
	Magic          string `json:"magic"`
	KernelBuild    uint32 `json:"kernel_build"`
	Processors     uint32 `json:"processors"`
	IRQL           uint32 `json:"irql"`
	FirmwareBytes  uint32 `json:"firmware_bytes"`
	FirmwareMatch  uint32 `json:"firmware_match"`
	RegisterCount  uint32 `json:"register_count"`
	FirmwareStatus string `json:"firmware_status"`
	MapCalls       uint32 `json:"map_calls"`
	Sequence       uint64 `json:"sequence"`
	InterruptTime  uint64 `json:"interrupt_time"`
	BuildID        string `json:"build_id"`
}

func utf(s string) *uint16 {
	p, e := syscall.UTF16PtrFromString(s)
	if e != nil {
		panic(e)
	}
	return p
}
func ptr(b []byte) uintptr {
	if len(b) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&b[0]))
}
func callError(op string, e error) error {
	if e == nil || e == syscall.Errno(0) {
		return fmt.Errorf("%s failed without Win32 error", op)
	}
	return fmt.Errorf("%s: %w", op, e)
}
func openDevice(path string) (uintptr, error) {
	r, _, e := kernel.NewProc("CreateFileW").Call(uintptr(unsafe.Pointer(utf(path))), 0x80000000, 0, 0, 3, 0, 0)
	if r == ^uintptr(0) {
		return 0, callError("CreateFile", e)
	}
	return r, nil
}
func closeHandle(h uintptr) {
	if h != 0 {
		kernel.NewProc("CloseHandle").Call(h)
	}
}
func request() []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b, 16)
	binary.LittleEndian.PutUint32(b[4:], 1)
	binary.LittleEndian.PutUint64(b[8:], magic)
	return b
}
func ioctl(h, code uintptr, input []byte, n int) ([]byte, uint32, error) {
	out := make([]byte, n)
	var got uint32
	r, _, e := kernel.NewProc("DeviceIoControl").Call(h, code, ptr(input), uintptr(len(input)), ptr(out), uintptr(len(out)), uintptr(unsafe.Pointer(&got)), 0)
	runtime.KeepAlive(input)
	runtime.KeepAlive(out)
	if r == 0 {
		return out, got, callError("DeviceIoControl", e)
	}
	if got > uint32(n) {
		return nil, got, errors.New("output length exceeds buffer")
	}
	return out[:got], got, nil
}
func parseStatus(b []byte) (Status, error) {
	if len(b) < 80 {
		return Status{}, errors.New("short status")
	}
	u := func(i int) uint32 { return binary.LittleEndian.Uint32(b[i:]) }
	q := func(i int) uint64 { return binary.LittleEndian.Uint64(b[i:]) }
	s := Status{u(0), u(4), fmt.Sprintf("0x%x", q(8)), u(16), u(20), u(24), u(28), u(32), u(36), fmt.Sprintf("0x%x", u(40)), u(44), q(48), q(56), strings.TrimRight(string(b[64:80]), "\x00")}
	if s.Size != 80 || s.Version != 1 || q(8) != magic || s.BuildID != "G35-kmdf-obs1" || s.RegisterCount != uint32(registerCount) {
		return s, errors.New("driver ABI/build differs")
	}
	return s, nil
}
func getStatus(h uintptr) (Status, error) {
	b, n, e := ioctl(h, ioctlStatus, request(), 80)
	if e != nil {
		return Status{}, e
	}
	if n != 80 {
		return Status{}, errors.New("status byte count")
	}
	return parseStatus(b)
}
func firmwareGuard() error {
	if runtime.GOARCH != "arm64" {
		return errors.New("ARM64 phone only")
	}
	b := make([]byte, 4096)
	r, _, e := kernel.NewProc("GetSystemFirmwareTable").Call(0x41435049, 0x54445344, ptr(b), uintptr(len(b)))
	runtime.KeepAlive(b)
	if r == 0 || r > uintptr(len(b)) {
		return callError("GetSystemFirmwareTable", e)
	}
	h := sha256.Sum256(b[:r])
	if r != 576 || hex.EncodeToString(h[:]) != firmwareSHA {
		return errors.New("protected G17 firmware identity mismatch")
	}
	return nil
}
func checkStatus(s Status) error {
	if s.Processors != 8 || s.IRQL != 0 || s.FirmwareMatch != 1 || s.FirmwareBytes != 576 || s.FirmwareStatus != "0x0" {
		return fmt.Errorf("phone/firmware guard: %+v", s)
	}
	return nil
}
func scm() (uintptr, error) {
	r, _, e := advapi.NewProc("OpenSCManagerW").Call(0, 0, 3)
	if r == 0 {
		return 0, callError("OpenSCManager", e)
	}
	return r, nil
}
func closeService(h uintptr) {
	if h != 0 {
		advapi.NewProc("CloseServiceHandle").Call(h)
	}
}
func openService(m uintptr, rights uintptr) (uintptr, error) {
	r, _, e := advapi.NewProc("OpenServiceW").Call(m, uintptr(unsafe.Pointer(utf(service))), rights)
	if r == 0 {
		return 0, callError("OpenService", e)
	}
	return r, nil
}
func state(h uintptr) (uint32, error) {
	b := make([]byte, 36)
	var needed uint32
	r, _, e := advapi.NewProc("QueryServiceStatusEx").Call(h, 0, ptr(b), uintptr(len(b)), uintptr(unsafe.Pointer(&needed)))
	if r == 0 {
		return 0, callError("QueryServiceStatusEx", e)
	}
	return binary.LittleEndian.Uint32(b[4:]), nil
}
func load(path, want string) (any, error) {
	if e := firmwareGuard(); e != nil {
		return nil, e
	}
	if !filepath.IsAbs(path) || len(want) != 64 {
		return nil, errors.New("absolute driver path and exact SHA256 required")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != want {
		return nil, errors.New("signed driver hash mismatch")
	}
	m, e := scm()
	if e != nil {
		return nil, e
	}
	defer closeService(m)
	if h, e := openService(m, 4); e == nil {
		closeService(h)
		return nil, errors.New("service already exists; inspect before another start")
	} else if !errors.Is(e, syscall.Errno(1060)) {
		return nil, e
	}
	h, _, ce := advapi.NewProc("CreateServiceW").Call(m, uintptr(unsafe.Pointer(utf(service))), uintptr(unsafe.Pointer(utf("OnePlus Open G35 Lab Diagnostic"))), 0x10034, 1, 3, 1, uintptr(unsafe.Pointer(utf(path))), 0, 0, 0, 0, 0)
	if h == 0 {
		return nil, callError("CreateService", ce)
	}
	defer closeService(h)
	r, _, se := advapi.NewProc("StartServiceW").Call(h, 0, 0)
	st, qe := state(h)
	result := map[string]any{"service_created": true, "service": service, "driver_sha256": want, "state": st, "query_error": fmt.Sprint(qe), "start_success": r != 0, "start_error": fmt.Sprint(se)}
	if r == 0 {
		return result, callError("StartService: do not retry without querying existing service", se)
	}
	return result, nil
}
func serviceBinary(h uintptr) (string, error) {
	var n uint32
	advapi.NewProc("QueryServiceConfigW").Call(h, 0, 0, uintptr(unsafe.Pointer(&n)))
	if n < 64 || n > 65536 {
		return "", errors.New("service config size")
	}
	b := make([]byte, n)
	r, _, e := advapi.NewProc("QueryServiceConfigW").Call(h, ptr(b), uintptr(n), uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return "", callError("QueryServiceConfig", e)
	}
	if binary.LittleEndian.Uint32(b) != 1 || binary.LittleEndian.Uint32(b[4:]) != 3 {
		return "", errors.New("not this demand-start kernel service")
	}
	at := uintptr(binary.LittleEndian.Uint64(b[16:]))
	base := ptr(b)
	if at < base || at >= base+uintptr(len(b)) || at%2 != 0 {
		return "", errors.New("service config pointer")
	}
	off := int(at - base)
	words := []uint16{}
	for off+1 < len(b) {
		v := binary.LittleEndian.Uint16(b[off:])
		if v == 0 {
			path := string(utf16.Decode(words))
			path = strings.Trim(path, "\"")
			path = strings.TrimPrefix(path, `\??\`)
			return path, nil
		}
		words = append(words, v)
		off += 2
	}
	return "", errors.New("unterminated service image path")
}
func stop(want string) (any, error) {
	if e := firmwareGuard(); e != nil {
		return nil, e
	}
	if len(want) != 64 {
		return nil, errors.New("stop needs exact installed-driver SHA256")
	}
	m, e := scm()
	if e != nil {
		return nil, e
	}
	defer closeService(m)
	h, e := openService(m, 0x10025)
	if e != nil {
		return nil, e
	}
	defer closeService(h)
	path, e := serviceBinary(h)
	if e != nil {
		return nil, e
	}
	data, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	hash := sha256.Sum256(data)
	if hex.EncodeToString(hash[:]) != want {
		return nil, errors.New("installed driver hash differs; refuse stop/delete")
	}
	st, e := state(h)
	if e != nil {
		return nil, e
	}
	if st != 1 {
		b := make([]byte, 28)
		r, _, ce := advapi.NewProc("ControlService").Call(h, 1, ptr(b))
		if r == 0 {
			return nil, callError("ControlService STOP", ce)
		}
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			st, e = state(h)
			if e != nil {
				return nil, e
			}
			if st == 1 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if st != 1 {
			return map[string]any{"state": st}, errors.New("unload not terminal; inspect same service")
		}
	}
	r, _, de := advapi.NewProc("DeleteService").Call(h)
	if r == 0 {
		return nil, callError("DeleteService", de)
	}
	return map[string]any{"stopped": true, "delete_requested": true}, nil
}
func selftest() (any, error) {
	h, e := openDevice(device)
	if e != nil {
		return nil, e
	}
	defer func() { closeHandle(h) }()
	before, e := getStatus(h)
	if e != nil {
		return nil, e
	}
	if e = checkStatus(before); e != nil {
		return nil, e
	}
	type test struct {
		Name  string
		Code  uintptr
		Input []byte
		Out   int
		Want  uint32
	}
	bad := request()
	bad[8] ^= 1
	badSize := request()
	badSize[0] = 20
	badVersion := request()
	badVersion[4] = 2
	tests := []test{{"long-input", ioctlStatus, append(request(), 0), 80, 87}, {"wrong-size", ioctlStatus, badSize, 80, 87}, {"wrong-version", ioctlStatus, badVersion, 80, 87}, {"empty-output", ioctlStatus, request(), 0, 122}, {"empty-input", ioctlStatus, nil, 80, 87}, {"short-input", ioctlStatus, request()[:8], 80, 87}, {"wrong-magic", ioctlStatus, bad, 80, 87}, {"short-status-output", ioctlStatus, request(), 79, 122}, {"short-snapshot-output", ioctlSnapshot, request(), 87 + 4*registerCount, 122}, {"unknown-ioctl", 0x2263fc, request(), 80, 1}}
	tests = append(tests, test{"short-pmic-output", ioctlPMIC, request(), 1727, 122})
	rows := []map[string]any{}
	for _, t := range tests {
		_, n, e := ioctl(h, t.Code, t.Input, t.Out)
		if !errors.Is(e, syscall.Errno(t.Want)) || n != 0 {
			return rows, fmt.Errorf("negative case %s: got%d error%v want%d", t.Name, n, e, t.Want)
		}
		rows = append(rows, map[string]any{"case": t.Name, "expected_error": t.Want, "no_output_bytes": true})
	}
	second, e := openDevice(device)
	if e == nil {
		closeHandle(second)
		return rows, errors.New("exclusive handle guard failed")
	}
	if !errors.Is(e, syscall.Errno(5)) {
		return rows, fmt.Errorf("exclusive open: %w", e)
	}
	rows = append(rows, map[string]any{"case": "exclusive-open", "expected_error": 5})
	closeHandle(h)
	h = 0
	runtime.LockOSThread()
	anonymousOK := func() error {
		defer runtime.UnlockOSThread()
		r, _, e := advapi.NewProc("ImpersonateAnonymousToken").Call(^uintptr(1))
		if r == 0 {
			return callError("ImpersonateAnonymousToken", e)
		}
		defer func() {
			r, _, _ := advapi.NewProc("RevertToSelf").Call()
			if r == 0 {
				os.Exit(1)
			}
		}()
		v, e := openDevice(device)
		if e == nil {
			closeHandle(v)
			return errors.New("anonymous device open succeeded")
		}
		if !errors.Is(e, syscall.Errno(5)) {
			return fmt.Errorf("anonymous open: %w", e)
		}
		return nil
	}()
	if anonymousOK != nil {
		return rows, anonymousOK
	}
	rows = append(rows, map[string]any{"case": "anonymous-open", "expected_error": 5})
	h, e = openDevice(device)
	if e != nil {
		return rows, e
	}
	after, e := getStatus(h)
	if e != nil {
		return rows, e
	}
	if after.MapCalls != before.MapCalls {
		return rows, errors.New("invalid requests unexpectedly mapped MMIO")
	}
	return map[string]any{"passed": true, "cases": rows, "map_calls_before": before.MapCalls, "map_calls_after": after.MapCalls, "status": after}, nil
}
func capturePMIC(h uintptr) (map[string]any, error) {
	b, n, e := ioctl(h, ioctlPMIC, request(), 1728)
	if e != nil {
		return nil, e
	}
	if n != 1728 {
		return nil, errors.New("PMIC response size differs")
	}
	s, e := parseStatus(b)
	if e != nil {
		return nil, e
	}
	if e = checkStatus(s); e != nil {
		return nil, e
	}
	u := func(i int) uint32 { return binary.LittleEndian.Uint32(b[i:]) }
	q := func(i int) uint64 { return binary.LittleEndian.Uint64(b[i:]) }
	count := u(160)
	if count > 128 {
		return nil, errors.New("PMIC trace count exceeds fixed buffer")
	}
	trace := make([]map[string]any, 0, count)
	for i := uint32(0); i < count; i++ {
		at := 164 + int(i)*12
		trace = append(trace, map[string]any{"kind": u(at), "address": fmt.Sprintf("0x%x", u(at+4)), "value": u(at + 8)})
	}
	bytesAt := func(start, end int) []uint32 {
		r := make([]uint32, end-start)
		for i, v := range b[start:end] {
			r[i] = uint32(v)
		}
		return r
	}
	completion := make([]uint32, 5)
	for i := 0; i < 5; i++ {
		completion[i] = u(104 + i*4)
	}
	r := map[string]any{"status": s, "operation_code": u(80), "stage": u(84), "register_reads": u(88), "observer_write_attempts": u(92), "polls": u(96), "observer_READ_commands": u(100), "completion": completion, "revision": bytesAt(124, 132), "anchor": bytesAt(132, 140), "identity": bytesAt(140, 148), "pmic_status_raw": uint32(b[148]), "configuration": bytesAt(149, 157), "trace": trace, "fixed_registers_unchanged": u(1700), "attempt": u(1704), "elapsed_ticks": q(1712), "counter_frequency": q(1720)}
	return r, nil
}
func run() (any, error) {
	if len(os.Args) < 2 {
		return nil, errors.New("usage: load ABS_SYS SHA256 | probe | snapshot | selftest | stop SHA256 | absent")
	}
	cmd := os.Args[1]
	if cmd == "load" {
		if len(os.Args) != 4 {
			return nil, errors.New("load needs path and hash")
		}
		return load(os.Args[2], os.Args[3])
	}
	if cmd == "stop" {
		if len(os.Args) != 3 {
			return nil, errors.New("stop needs exact signed-driver hash")
		}
		return stop(os.Args[2])
	}
	if cmd == "absent" {
		h, e := openDevice(device)
		if e == nil {
			closeHandle(h)
			return nil, errors.New("device still exists")
		}
		if !errors.Is(e, syscall.Errno(2)) {
			return nil, e
		}
		m, e := scm()
		if e != nil {
			return nil, e
		}
		defer closeService(m)
		v, e := openService(m, 4)
		if e == nil {
			closeService(v)
			return nil, errors.New("service still exists")
		}
		if !errors.Is(e, syscall.Errno(1060)) {
			return nil, e
		}
		return map[string]any{"device_absent": true, "service_absent": true}, nil
	}
	if cmd == "selftest" {
		return selftest()
	}
	h, e := openDevice(device)
	if e != nil {
		return nil, e
	}
	defer closeHandle(h)
	switch cmd {
	case "pmic":
		r, e := capturePMIC(h)
		if e != nil {
			return r, e
		}
		if r["operation_code"] != uint32(0) || r["fixed_registers_unchanged"] != uint32(1) {
			return r, errors.New("PMIC observation failed; inspect the saved result without retrying")
		}
		return r, nil
	case "budget":
		before, e := getStatus(h)
		if e != nil {
			return nil, e
		}
		r, e := capturePMIC(h)
		if e != nil {
			return r, e
		}
		after, e := getStatus(h)
		if e != nil {
			return r, e
		}
		if r["operation_code"] != uint32(1002) || before.MapCalls != after.MapCalls || len(r["trace"].([]map[string]any)) != 0 {
			return r, errors.New("two-capture lifetime budget guard failed")
		}
		return map[string]any{"passed": true, "denied_code": r["operation_code"], "map_calls_before": before.MapCalls, "map_calls_after": after.MapCalls, "observer_READ_commands": r["observer_READ_commands"]}, nil
	case "probe":
		s, e := getStatus(h)
		if e != nil {
			return nil, e
		}
		return s, checkStatus(s)
	case "snapshot":
		b, n, e := ioctl(h, ioctlSnapshot, request(), 88+registerCount*4)
		if e != nil {
			return nil, e
		}
		if n != uint32(88+registerCount*4) {
			return nil, errors.New("snapshot byte count")
		}
		s, e := parseStatus(b)
		if e != nil {
			return nil, e
		}
		if e = checkStatus(s); e != nil {
			return nil, e
		}
		if binary.LittleEndian.Uint32(b[80:]) != uint32(registerCount) {
			return nil, errors.New("snapshot register count")
		}
		values := []map[string]any{}
		for i, f := range registerFields {
			values = append(values, map[string]any{"name": f.Name, "address": fmt.Sprintf("0x%x", f.Address), "value": binary.LittleEndian.Uint32(b[88+i*4:])})
		}
		return map[string]any{"status": s, "fixed_register_reads": registerCount, "register_writes": 0, "values": values}, nil
	default:
		return nil, errors.New("unknown operation")
	}
}
func main() {
	result, e := run()
	out := map[string]any{"result": result, "ok": e == nil}
	if e != nil {
		out["error"] = e.Error()
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
	if e != nil {
		os.Exit(1)
	}
}
