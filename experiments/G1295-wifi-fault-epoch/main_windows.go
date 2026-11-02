// Source only: default inert. Fixed reads; never interrupts, resumes, executes commands or writes target memory.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

type guid struct {
	A    uint32
	B, C uint16
	D    [8]byte
}

var clientID = guid{0x27fe5639, 0x8407, 0x4f47, [8]byte{0x83, 0x64, 0xee, 0x11, 0x8f, 0xb0, 0x8a, 0xc8}}
var controlID = guid{0x5182e668, 0x105e, 0x416e, [8]byte{0xad, 0x92, 0x24, 0xef, 0x80, 0x04, 0x24, 0xba}}
var symbolsID = guid{0x8c31e98c, 0x983a, 0x48a5, [8]byte{0x90, 0x16, 0x6f, 0xe5, 0xd6, 0x67, 0xa9, 0x50}}
var spacesID = guid{0xd98ada1f, 0x29e9, 0x4ef5, [8]byte{0xa6, 0xc0, 0xe5, 0x33, 0x49, 0x88, 0x32, 0x12}}

//go:uintptrescapes
func call(o uintptr, slot int, args ...uintptr) uint32 {
	v := *(*uintptr)(unsafe.Pointer(o))
	fn := *(*uintptr)(unsafe.Pointer(v + uintptr(slot)*unsafe.Sizeof(uintptr(0))))
	r, _, _ := syscall.SyscallN(fn, append([]uintptr{o}, args...)...)
	return uint32(r)
}
func require(ok bool, why string) {
	if !ok {
		panic(why)
	}
}
func check(where string, hr uint32) {
	require(hr == 0, fmt.Sprintf("%s HRESULT=%08x; target remains held", where, hr))
}

type proof struct {
	Phase                     string            `json:"phase"`
	ActionLedgerFile          string            `json:"action_ledger_file"`
	RootNormalBoot            bool              `json:"root_qualifies_actual_fresh_normal_boot"`
	BARQualified              bool              `json:"root_qualifies_current_endpoint_BAR0_resource"`
	BARBase                   string            `json:"BAR0_resource_base"`
	BARBytes                  uint64            `json:"BAR0_resource_bytes"`
	NoDiagnosticSinceBoundary bool              `json:"root_attests_no_root_selected_force_native_diagnostic_reset_or_error_clear_in_selected_interval"`
	Schema                    string            `json:"schema"`
	BootID                    uint32            `json:"boot_id"`
	Session                   string            `json:"phone_session"`
	Created                   string            `json:"created_utc"`
	Nonce                     string            `json:"root_nonce"`
	Image                     string            `json:"image_sha256"`
	NT                        string            `json:"nt_base"`
	PC                        string            `json:"held_pc"`
	OwnerBase                 string            `json:"owner_base"`
	OwnerSize                 uint32            `json:"owner_size"`
	OwnerTimestamp            uint32            `json:"owner_timestamp"`
	OwnerChecksum             uint32            `json:"owner_checksum"`
	OwnedBreak                bool              `json:"root_owns_break6"`
	CurrentTables             bool              `json:"root_qualifies_current_tables_and_resource_owner"`
	PhysicalAccess            bool              `json:"root_qualifies_fixed_physical_device_ranges_uncached"`
	Evidence                  map[string]string `json:"actual_evidence_sha256"`
}

func hex64(s string) uint64 {
	require(regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(s), "16hex address required")
	v, e := strconv.ParseUint(s, 16, 64)
	require(e == nil, "address")
	return v
}
func main() {
	execute := flag.Bool("execute-reviewed-reads", false, "Root selects fixed read-only observation")
	pf := flag.String("proof", "", "Actual fresh root admission JSON")
	ph := flag.String("proof-sha256", "", "Exact root-reviewed admission hash")
	result := flag.String("result", "", "Exclusive new JSONL")
	flag.Parse()
	if !*execute {
		fmt.Println("INERT: no debugger connection or target read; root actual proof and explicit selection required")
		return
	}
	require(runtime.GOARCH == "amd64" && flag.NArg() == 0, "AMD64/no positional arguments required")
	raw, e := os.ReadFile(*pf)
	require(e == nil, "Actual proof missing")
	h := sha256.Sum256(raw)
	require(hex.EncodeToString(h[:]) == *ph, "Proof hash changed")
	var p proof
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	require(dec.Decode(&p) == nil, "Proof schema")
	require(p.Schema == "G1295-root-phase-fault-epoch/1" && p.BootID > 161 && p.OwnedBreak && p.CurrentTables && p.PhysicalAccess, "Current root resource/access/hold admission required")
	require(regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(p.Image) && p.RootNormalBoot && p.Session != "00000000000000000000000000000000", "Actual fresh normal image/session proof; Boot161 cannot be reused")
	re32 := regexp.MustCompile(`^[0-9a-f]{32}$`)
	re64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	require(re32.MatchString(p.Session) && re32.MatchString(p.Nonce), "Fresh actual session/nonce")
	created, e := time.Parse(time.RFC3339Nano, p.Created)
	age := time.Since(created)
	require(e == nil && age >= 0 && age < 5*time.Minute, "Proof older than five minutes or future timestamp")
	ledger := admitPhase(p, re64, created)
	require(p.BARQualified && p.NoDiagnosticSinceBoundary && p.BARBase == "0000000063e00000" && p.BARBytes >= 0x140 && p.BARBytes <= 0x1000000, "Fresh allocated endpoint BAR0 resource/unforced-history proof required")
	nt, pc, ob := hex64(p.NT), hex64(p.PC), hex64(p.OwnerBase)
	require(nt >= 0xffff000000000000 && ob >= 0xffff000000000000 && nt&0xfff == 0 && ob&0xfff == 0 && p.OwnerSize > 0, "Kernel/owner identity")
	f, e := os.OpenFile(*result, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	require(e == nil, "Exclusive result required")
	defer f.Close()
	emit := func(v map[string]any) {
		v["boot_id"] = p.BootID
		v["observation_phase"] = p.Phase
		v["phone_session"] = p.Session
		v["root_nonce"] = p.Nonce
		v["utc"] = time.Now().UTC().Format(time.RFC3339Nano)
		b, e := json.Marshal(v)
		require(e == nil, "JSON")
		b = append(b, '\n')
		n, e := f.Write(b)
		require(e == nil && n == len(b) && f.Sync() == nil, "Persist result")
		os.Stdout.Write(b)
	}
	defer func() {
		if x := recover(); x != nil {
			emit(map[string]any{"phase": "refused_or_failed", "error": fmt.Sprint(x), "target_writes": 0, "interrupt_resume_commands": 0})
			os.Exit(1)
		}
	}()
	emit(map[string]any{"phase": "begin", "proof_sha256": *ph, "boot_session_resource_identity": "root_attested_hash_bound; not inferred from SCM", "target_writes": 0, "interrupt_resume_commands": 0})
	consumePhase(p, ledger, emit)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	dll, e := syscall.LoadDLL(`C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbgeng.dll`)
	require(e == nil, "dbgeng missing")
	defer dll.Release()
	connect, e := dll.FindProc("DebugConnect")
	require(e == nil, "DebugConnect missing")
	transport, _ := syscall.BytePtrFromString("npipe:server=localhost,pipe=OpenG80")
	var client, control, spaces, symbols uintptr
	hr, _, _ := connect.Call(uintptr(unsafe.Pointer(transport)), uintptr(unsafe.Pointer(&clientID)), uintptr(unsafe.Pointer(&client)))
	runtime.KeepAlive(transport)
	check("DebugConnect", uint32(hr))
	require(client != 0, "client")
	defer call(client, 2)
	query := func(id *guid, dst *uintptr) {
		check("QueryInterface", call(client, 0, uintptr(unsafe.Pointer(id)), uintptr(unsafe.Pointer(dst))))
		require(*dst != 0, "interface")
	}
	query(&controlID, &control)
	defer call(control, 2)
	check("ConnectSessionNoHistory", call(client, 21, 1, 0))
	query(&spacesID, &spaces)
	defer call(spaces, 2)
	query(&symbolsID, &symbols)
	defer call(symbols, 2)
	held := func() {
		var s uint32
		check("ExecutionStatus", call(control, 49, uintptr(unsafe.Pointer(&s))))
		require(s&0x1f == 6, "Preexisting BREAK6 required; remains held")
	}
	eval := func(expr string) uint64 {
		held()
		s, _ := syscall.BytePtrFromString(expr)
		var v [32]byte
		var rest uint32
		check("Evaluate fixed identity", call(control, 63, uintptr(unsafe.Pointer(s)), 4, uintptr(unsafe.Pointer(&v[0])), uintptr(unsafe.Pointer(&rest))))
		runtime.KeepAlive(s)
		require(binary.LittleEndian.Uint32(v[28:]) == 4, "INT64")
		return binary.LittleEndian.Uint64(v[:8])
	}
	identity := func() {
		held()
		require(eval("@pc") == pc && eval("@@masm(nt!DebugService2)") == nt+0x201400, "Held PC/kernel changed")
		name, _ := syscall.BytePtrFromString("OpenG184")
		var idx uint32
		var base uint64
		check("Loaded root owner", call(symbols, 14, uintptr(unsafe.Pointer(name)), 0, uintptr(unsafe.Pointer(&idx)), uintptr(unsafe.Pointer(&base))))
		runtime.KeepAlive(name)
		require(base == ob, "Root owner base changed")
		var m [64]byte
		check("Owner parameters", call(symbols, 17, 1, uintptr(unsafe.Pointer(&base)), 0, uintptr(unsafe.Pointer(&m[0]))))
		require(binary.LittleEndian.Uint64(m[:8]) == ob && binary.LittleEndian.Uint32(m[8:12]) == p.OwnerSize && binary.LittleEndian.Uint32(m[12:16]) == p.OwnerTimestamp && binary.LittleEndian.Uint32(m[16:20]) == p.OwnerChecksum && binary.LittleEndian.Uint32(m[20:24])&1 == 0, "Loaded owner identity changed")
	}
	identity()
	active := false
	read := func(a uint64, label string) uint32 {
		require(allowed(a, active), "Physical address outside current allowlist")
		identity()
		var b [4]byte
		var got uint32
		hr := call(spaces, 42, uintptr(a), 2, uintptr(unsafe.Pointer(&b[0])), 4, uintptr(unsafe.Pointer(&got)))
		runtime.KeepAlive(b)
		emit(map[string]any{"phase": "physical_read", "label": label, "address": fmt.Sprintf("%016x", a), "bytes": 4, "actual_bytes": got, "hresult": fmt.Sprintf("%08x", hr), "raw_hex": hex.EncodeToString(b[:]), "SDK_slot": 42, "DEBUG_PHYSICAL_UNCACHED": 2})
		require(hr == 0 && got == 4, "Full S_OK physical read required; no fallback/retry")
		return binary.LittleEndian.Uint32(b[:])
	}
	clocks := func() []uint32 {
		v := make([]uint32, len(activeAddresses))
		for i, a := range activeAddresses {
			v[i] = read(a, fmt.Sprintf("active_guard_%d", i))
		}
		require(activeReady(v), "Active clock/reset/PERST guard refused; no PCIe access")
		emit(map[string]any{"phase": "GPIO83_observation", "input_level": v[19] & 1, "configuration": v[18], "runtime_low_required": false, "firmware_ready_inferred": false, "role": "early_CNSS_device_identifier; runtime_observation_only"})
		return v
	}
	before := clocks()
	active = true

	rootID := read(0x60000000, "root_id")
	require(rootID&0xffff == 0x17cb && rootID != 0xffffffff, "Root ID")
	require(((read(0x6000000c, "root_header")>>16)&0x7f) == 1, "Root type1")
	rootLink := read(0x60000080, "root_link_access_gate")
	ltssm := read(0x1c001b0, "root_LTSSM_access_gate")
	require(rootLink != 0xffffffff && rootLink&(1<<29) != 0 && ltssm != 0xffffffff, "Root link access unavailable; no endpoint/BAR read")
	require(read(0x60100000, "endpoint_id") == 0x110717cb, "Endpoint identity unavailable")
	require(((read(0x6010000c, "endpoint_header")>>16)&0x7f) == 0, "Endpoint type0")
	cmd := read(0x60100004, "endpoint_command_access_gate")
	require(cmd != 0xffffffff && cmd&2 != 0, "Endpoint memory decode disabled/unavailable; no BAR read")
	require(read(0x60100040, "endpoint_PM_capability_gate")&0xff == 1, "Previously qualified PM capability moved; refuse")
	pm := read(0x60100044, "endpoint_PMCSR_D0_access_gate")
	require(pm != 0xffffffff && pm&3 == 0, "Endpoint not D0/unavailable; no BAR read")
	low := read(0x60100010, "BAR0_low_binding")
	high := read(0x60100014, "BAR0_high_binding")
	require(low != 0xffffffff && high != 0xffffffff && low&7 == 4, "Expected64bit memory BAR0")
	bar := (uint64(high) << 32) | uint64(low&0xfffffff0)
	require(bar == 0x63e00000, "Current BAR0 does not match root-attested fixed resource; no alternate address")
	bound := true // Permission only for the eight fixed DWORDs after all source-bound access and BAR checks.
	readBound := func(a uint64, label string) uint32 {
		require(bound && faultAllowed(a), "Fault-register allowlist")
		identity()
		var b [4]byte
		var got uint32
		hr := call(spaces, 42, uintptr(a), 2, uintptr(unsafe.Pointer(&b[0])), 4, uintptr(unsafe.Pointer(&got)))
		runtime.KeepAlive(b)
		emit(map[string]any{"phase": "unforced_fault_read", "label": label, "address": fmt.Sprintf("%016x", a), "bytes": 4, "actual_bytes": got, "hresult": fmt.Sprintf("%08x", hr), "raw_hex": hex.EncodeToString(b[:]), "SDK_slot": 42, "DEBUG_PHYSICAL_UNCACHED": 2})
		require(hr == 0 && got == 4, "Full S_OK fixed fault read required; no fallback/retry")
		v := binary.LittleEndian.Uint32(b[:])
		require(v != 0xffffffff, "All-ones fault register unavailable/opaque; do not decode as fault")
		return v
	}
	status := readBound(bar+0x48, "MHISTATUS")
	bhi := readBound(bar+0x28, "BHIOFF")
	require(bhi == 0x100, "Unexpected BHIOFF; no dynamic BHI address/scan")
	ee := readBound(bar+0x128, "BHI_EXECENV")
	bhiStatus := readBound(bar+0x12c, "BHI_STATUS")
	errorCode := readBound(bar+0x130, "BHI_ERRCODE")
	error1 := readBound(bar+0x134, "BHI_ERRDBG1")
	error2 := readBound(bar+0x138, "BHI_ERRDBG2")
	error3 := readBound(bar+0x13c, "BHI_ERRDBG3")
	statusAfter := readBound(bar+0x48, "MHISTATUS_after")
	eeAfter := readBound(bar+0x128, "BHI_EXECENV_after")
	require(readBound(bar+0x28, "BHIOFF_after") == bhi, "BHI base changed; unqualified")
	bound = false
	require(read(0x60100010, "BAR0_low_after") == low && read(0x60100014, "BAR0_high_after") == high && read(0x60100000, "endpoint_id_after") == 0x110717cb, "BAR/endpoint binding changed")
	cmdAfter := read(0x60100004, "endpoint_command_after")
	pmAfter := read(0x60100044, "endpoint_PMCSR_after")
	require(cmdAfter == cmd && pmAfter == pm, "Endpoint access state changed")
	rootAfter := read(0x60000080, "root_link_after")
	require(rootAfter != 0xffffffff && rootAfter&(1<<29) != 0, "Root link changed/unavailable")
	active = false
	after := clocks()
	identity()
	require(equalWords(before, after), "Active safety guard changed; unqualified")
	emit(map[string]any{"phase": "complete_held", "BAR0_resource_base": p.BARBase, "MHI_status_raw": status, "MHI_status_after": statusAfter, "MHI_state_bits": (status >> 8) & 0xff, "MHI_SYSERR": (status >> 2) & 1, "MHI_READY": status & 1, "EE_raw": ee, "EE_after": eeAfter, "BHI_status_raw": bhiStatus, "BHI_status_top2": bhiStatus >> 30, "BHI_error_code_raw": errorCode, "BHI_error_debug_raw": []uint32{error1, error2, error3}, "status_EE_stable": status == statusAfter && ee == eeAfter, "error_values_do_not_prove_fault_epoch_or_cause": true, "comparison_bounds": "PRE_HOST_INIT vs POST_STALL bounds assignment interval only; neither phase proves executed assertion", "gpio83_input_changed": (before[19]^after[19])&1 != 0, "target_writes": 0, "interrupt_resume_commands": 0, "root_may_review_and_resume": true})
}
