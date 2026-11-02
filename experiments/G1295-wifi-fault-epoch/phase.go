package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

type actionLedger struct {
	Schema                    string  `json:"schema"`
	BootID                    uint32  `json:"boot_id"`
	Session                   string  `json:"phone_session"`
	Image                     string  `json:"image_sha256"`
	Phase                     string  `json:"phase"`
	Created                   string  `json:"created_utc"`
	NativeInitCalls           *uint32 `json:"native_init_calls"`
	ExplicitScanCalls         *uint32 `json:"explicit_scan_calls"`
	RootForceCalls            *uint32 `json:"root_force_calls"`
	RootNativeDiagnosticCalls *uint32 `json:"root_native_diagnostic_calls"`
	RootResetCalls            *uint32 `json:"root_reset_calls"`
	RootStatusClearCalls      *uint32 `json:"root_status_clear_calls"`
	WLANServiceStart          *uint32 `json:"wlan_service_start"`
	WLANServiceState          string  `json:"wlan_service_state"`
	RootProvesNoNativeInit    bool    `json:"root_proves_no_native_init_in_actual_boot"`
	InitOutcomeRecorded       bool    `json:"actual_single_init_outcome_recorded"`
	FailureBoundaryRecorded   bool    `json:"actual_post_init_failure_boundary_recorded"`
	AcceptedBootReceiptSHA    string  `json:"accepted_boot_receipt_sha256"`
	NormalBootAdmissionSHA    string  `json:"normal_boot_admission_sha256"`
	NativeInitSelectionSHA    string  `json:"native_init_selection_sha256"`
	NativeInitOutcomeSHA      string  `json:"native_init_outcome_sha256"`
	FailedScanLogSHA          string  `json:"failed_scan_log_sha256"`
	PreHostInitStateSHA       string  `json:"pre_host_init_state_sha256"`
	PrePhaseResultSHA         string  `json:"pre_phase_result_sha256"`
	PrePhaseMarkerSHA         string  `json:"pre_phase_marker_sha256"`
}
type phaseIntent struct {
	Schema    string `json:"schema"`
	BootID    uint32 `json:"boot_id"`
	Session   string `json:"phone_session"`
	Image     string `json:"image_sha256"`
	Phase     string `json:"phase"`
	Nonce     string `json:"root_nonce"`
	LedgerSHA string `json:"action_ledger_sha256"`
}

func markerPath(boot uint32, phase string) string {
	// Fixed per-user host payload directory. No caller-selected marker path or new directory creation.
	home, e := os.UserHomeDir()
	require(e == nil && home != "", "Host profile unavailable")
	return filepath.Join(home, "Downloads", "Open-G17", "payloads", fmt.Sprintf("G1295-Boot-%d-%s.once.json", boot, phase))
}
func admitPhase(p proof, re64 *regexp.Regexp, proofTime time.Time) actionLedger {
	require(p.Phase == "PRE_HOST_INIT" || p.Phase == "POST_STALL", "Explicit supported phase required")
	raw, e := os.ReadFile(p.ActionLedgerFile)
	require(e == nil, "Actual action ledger missing")
	h := sha256.Sum256(raw)
	require(hex.EncodeToString(h[:]) == p.Evidence["action_ledger"], "Actual action ledger hash mismatch")
	var l actionLedger
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	require(d.Decode(&l) == nil, "Action ledger schema")
	require(d.Decode(new(any)) == io.EOF, "Trailing action ledger JSON")
	require(l.Schema == "G1295-actual-boot-action-ledger/1" && l.BootID == p.BootID && l.BootID > 161 && l.Session == p.Session && l.Image == p.Image && l.Phase == p.Phase, "Action ledger is not actual matching fresh phase/boot/image/session")
	created, e := time.Parse(time.RFC3339Nano, l.Created)
	require(e == nil && !created.After(proofTime) && proofTime.Sub(created) < 5*time.Minute, "Stale/future action ledger")
	require(l.NativeInitCalls != nil && l.ExplicitScanCalls != nil && l.RootForceCalls != nil && l.RootNativeDiagnosticCalls != nil && l.RootResetCalls != nil && l.RootStatusClearCalls != nil && l.WLANServiceStart != nil, "Explicit actual ledger scalar counts/start required; null is not zero")
	require(*l.RootForceCalls == 0 && *l.RootNativeDiagnosticCalls == 0 && *l.RootResetCalls == 0 && *l.RootStatusClearCalls == 0, "Selected interval contains a root diagnostic/force/reset/clear; not this experiment")
	keys := []string{"context", "current_tables", "loaded_owner", "endpoint_BAR0_resource", "accepted_boot_receipt", "normal_boot_admission", "action_ledger"}
	require(re64.MatchString(l.AcceptedBootReceiptSHA) && l.AcceptedBootReceiptSHA == p.Evidence["accepted_boot_receipt"] && re64.MatchString(l.NormalBootAdmissionSHA) && l.NormalBootAdmissionSHA == p.Evidence["normal_boot_admission"], "Actual normal boot/image receipt binding missing")
	if p.Phase == "PRE_HOST_INIT" {
		require(*l.NativeInitCalls == 0 && *l.ExplicitScanCalls == 0 && *l.WLANServiceStart == 4 && l.WLANServiceState == "Stopped" && l.RootProvesNoNativeInit, "PRE requires actual Start4/Stopped and no native init/scan in fresh boot")
		require(!l.InitOutcomeRecorded && !l.FailureBoundaryRecorded && l.NativeInitSelectionSHA == "" && l.NativeInitOutcomeSHA == "" && l.FailedScanLogSHA == "" && l.PrePhaseResultSHA == "" && l.PrePhaseMarkerSHA == "", "PRE cannot contain fabricated future init/failure evidence")
		require(l.PreHostInitStateSHA == p.Evidence["pre_host_init_state"] && re64.MatchString(l.PreHostInitStateSHA), "Actual pre-host-init state evidence missing")
		keys = append(keys, "pre_host_init_state")
	} else {
		require(*l.NativeInitCalls == 1 && *l.ExplicitScanCalls == 1 && l.InitOutcomeRecorded && l.FailureBoundaryRecorded && !l.RootProvesNoNativeInit, "POST requires actual one-init/one-scan outcome and failure boundary")
		require(l.PreHostInitStateSHA == "", "POST uses actual outcome, not a reused PRE state attestation")
		for k, v := range map[string]string{"native_init_selection": l.NativeInitSelectionSHA, "native_init_outcome": l.NativeInitOutcomeSHA, "failed_scan_log": l.FailedScanLogSHA, "pre_phase_result": l.PrePhaseResultSHA, "pre_phase_marker": l.PrePhaseMarkerSHA} {
			require(re64.MatchString(v) && p.Evidence[k] == v, "POST missing actual bound evidence: "+k)
			keys = append(keys, k)
		}
		// PRE may have safely refused access; a real retained PRE result is still required. Never invent a baseline.
		raw, e := os.ReadFile(markerPath(p.BootID, "PRE_HOST_INIT"))
		require(e == nil, "Actual prior PRE phase marker missing")
		h := sha256.Sum256(raw)
		require(hex.EncodeToString(h[:]) == l.PrePhaseMarkerSHA, "Prior PRE marker changed")
		var m phaseIntent
		require(json.Unmarshal(raw, &m) == nil && m.Schema == "G1295-host-phase-once/1" && m.BootID == p.BootID && m.Session == p.Session && m.Image == p.Image && m.Phase == "PRE_HOST_INIT" && m.Nonce != p.Nonce, "PRE marker belongs to another boot/session/image")
	}
	require(len(keys) == len(p.Evidence), "Unexpected/missing phase evidence keys")
	for _, k := range keys {
		require(re64.MatchString(p.Evidence[k]), "Missing actual evidence hash: "+k)
	}
	return l
}
func consumePhase(p proof, l actionLedger, emit func(map[string]any)) {
	require(l.BootID == p.BootID && p.BootID > 161, "Boot161 phase use forbidden")
	if p.Phase == "PRE_HOST_INIT" {
		_, e := os.Stat(markerPath(p.BootID, "POST_STALL"))
		require(os.IsNotExist(e), "PRE cannot follow consumed POST")
	}
	m := phaseIntent{Schema: "G1295-host-phase-once/1", BootID: p.BootID, Session: p.Session, Image: p.Image, Phase: p.Phase, Nonce: p.Nonce, LedgerSHA: p.Evidence["action_ledger"]}
	raw, e := json.Marshal(m)
	require(e == nil, "Intent JSON")
	path := markerPath(p.BootID, p.Phase)
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	require(e == nil, "Phase already consumed or marker directory unavailable; no retry")
	n, we := f.Write(raw)
	se := f.Sync()
	ce := f.Close()
	require(we == nil && n == len(raw) && se == nil && ce == nil, "Intent persistence failed; preserve consumed marker")
	h := sha256.Sum256(raw)
	emit(map[string]any{"phase": "phase_consumed_before_debugger_connect", "marker_path": path, "marker_sha256": hex.EncodeToString(h[:]), "calls_max_for_phase": 1, "read_outcome_not_yet_known": true})
}
