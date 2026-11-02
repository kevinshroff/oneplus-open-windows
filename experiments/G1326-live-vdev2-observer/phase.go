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
	NativeCallKnowledge       string            `json:"native_call_count_knowledge"`
	ScanCallKnowledge         string            `json:"explicit_scan_count_knowledge"`
	Schema                    string            `json:"schema"`
	BootID                    uint32            `json:"boot_id"`
	Session                   string            `json:"phone_session"`
	Image                     string            `json:"image_sha256"`
	Phase                     string            `json:"phase"`
	Created                   string            `json:"created_utc"`
	NativeInitCalls           *uint32           `json:"native_init_calls_started"`
	ExplicitScanCalls         *uint32           `json:"explicit_scan_calls"`
	RootForceCalls            *uint32           `json:"root_force_calls"`
	RootNativeDiagnosticCalls *uint32           `json:"root_native_diagnostic_calls"`
	RootResetCalls            *uint32           `json:"root_reset_calls"`
	RootStatusClearCalls      *uint32           `json:"root_status_clear_calls"`
	RootWindowWrites          *uint32           `json:"root_window_write_calls"`
	InitInProgress            bool              `json:"native_initialization_in_progress"`
	InitOutcomeRecorded       bool              `json:"actual_single_init_outcome_recorded"`
	FailureBoundaryRecorded   bool              `json:"actual_post_init_failure_boundary_recorded"`
	NoUnload                  bool              `json:"root_proves_original_driver_no_unload_in_selected_interval"`
	NoGPU                     bool              `json:"root_proves_gpu_owner_broker_absent_stopped4"`
	Evidence                  map[string]string `json:"actual_evidence_sha256"`
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
	home, e := os.UserHomeDir()
	require(e == nil && home != "", "Host profile unavailable")
	return filepath.Join(home, "Downloads", "Open-G17", "payloads", fmt.Sprintf("WiFi-LiveVdev2-Boot-%d-%s.once.json", boot, phase))
}
func strictJSON(raw []byte, target any) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	require(d.Decode(target) == nil, "Strict JSON schema")
	require(d.Decode(new(any)) == io.EOF, "Trailing JSON document")
}
func hashFile(path string) (string, []byte) {
	raw, e := os.ReadFile(path)
	require(e == nil, "Actual local evidence file missing")
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), raw
}
func validLedger(p proof, l actionLedger, proofTime time.Time) {
	require(p.Phase == "ARM_LIVE_VDEV2" || p.Phase == "PRE_LIVE_VDEV2" || p.Phase == "POST_STALL", "Only new live phases are supported; old PRE refused")
	require(l.Schema == "wifi-live-vdev2-action-ledger/1" && l.BootID == p.BootID && p.BootID > 165 && l.Session == p.Session && l.Image == p.Image && l.Phase == p.Phase, "Matching fresh phase/boot/image/session required")
	created, e := time.Parse(time.RFC3339Nano, l.Created)
	require(e == nil && !created.After(proofTime) && proofTime.Sub(created) < 5*time.Minute, "Stale/future ledger")
	require(l.RootForceCalls != nil && l.RootNativeDiagnosticCalls != nil && l.RootResetCalls != nil && l.RootStatusClearCalls != nil && l.RootWindowWrites != nil, "Missing/null explicit action counts")
	require(*l.RootForceCalls == 0 && *l.RootNativeDiagnosticCalls == 0 && *l.RootResetCalls == 0 && *l.RootStatusClearCalls == 0 && *l.RootWindowWrites == 0, "No force/native diagnostics/reset/clear/window writes in interval")
	require(l.NoUnload && l.NoGPU, "Current original driver no-unload interval and GPU exclusion required")
	keys := []string{"context", "current_tables", "loaded_owner", "loaded_original_driver", "accepted_boot_receipt", "normal_boot_admission", "native_init_selection", "boundary_source", "action_ledger"}
	if p.Phase != "ARM_LIVE_VDEV2" {
		keys = append(keys, "source_resource_origin_contract")
	}
	if p.Phase == "POST_STALL" {
		require(l.NativeCallKnowledge == "ACTUAL_COMPLETED_OUTCOME" && l.ScanCallKnowledge == "ACTUAL_COMPLETED_OUTCOME" && l.NativeInitCalls != nil && *l.NativeInitCalls == 1 && l.ExplicitScanCalls != nil && *l.ExplicitScanCalls == 1 && !l.InitInProgress && l.InitOutcomeRecorded && l.FailureBoundaryRecorded, "POST requires actual completed one-init/one-scan failure outcome")
		require(!p.BoundaryQualified && !p.LoadHoldQualified, "POST cannot reuse a PRE or load hold qualification")
		keys = append(keys, "native_init_outcome", "failed_scan_log", "pre_phase_result", "pre_phase_marker", "arm_marker")
	} else {
		require(!l.InitOutcomeRecorded && !l.FailureBoundaryRecorded && !l.InitInProgress, "ARM/PRE do not fabricate native in-call status or future outcomes")
		for _, x := range []struct {
			knowledge string
			count     *uint32
		}{{l.NativeCallKnowledge, l.NativeInitCalls}, {l.ScanCallKnowledge, l.ExplicitScanCalls}} {
			if x.knowledge == "NOT_OBSERVED_AT_STOP" {
				require(x.count == nil, "Unknown count must remain null, never zero")
			} else {
				require(x.knowledge == "ACTUAL_CALL_BEGIN_JOURNAL" && x.count != nil && *x.count <= 1, "Actual journal or explicitly unknown count required")
			}
		}
		if p.Phase == "PRE_LIVE_VDEV2" {
			require(p.BoundaryQualified && !p.LoadHoldQualified, "PRE requires owned source boundary, not a load hold")
			keys = append(keys, "arm_marker", "owned_boundary_stop")
		} else {
			require(p.LoadHoldQualified && !p.BoundaryQualified, "ARM requires actual owned module-load hold")
			keys = append(keys, "owned_load_stop")
		}
	}
	re64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	require(len(p.Evidence) == len(keys) && len(l.Evidence) == len(keys)-1, "Unexpected/missing phase evidence keys")
	for _, k := range keys {
		require(re64.MatchString(p.Evidence[k]), "Missing actual proof hash: "+k)
		if k != "action_ledger" {
			require(l.Evidence[k] == p.Evidence[k], "Ledger/proof evidence mismatch: "+k)
		}
	}
}
func verifyPriorMarker(p proof, phase, key string) phaseIntent {
	h, raw := hashFile(markerPath(p.BootID, phase))
	require(h == p.Evidence[key], "Prior phase marker hash changed")
	var m phaseIntent
	strictJSON(raw, &m)
	require(m.Schema == "wifi-live-vdev2-host-once/1" && m.BootID == p.BootID && m.Session == p.Session && m.Image == p.Image && m.Phase == phase && m.Nonce != p.Nonce, "Prior marker wrong phase/boot/image/session/nonce")
	return m
}
func admitPhase(p proof, proofTime time.Time) actionLedger {
	h, raw := hashFile(p.ActionLedgerFile)
	require(h == p.Evidence["action_ledger"], "Action ledger hash changed")
	var l actionLedger
	strictJSON(raw, &l)
	validLedger(p, l, proofTime)
	if p.Phase != "ARM_LIVE_VDEV2" {
		verifyPriorMarker(p, "ARM_LIVE_VDEV2", "arm_marker")
	}
	if p.Phase == "POST_STALL" {
		verifyPriorMarker(p, "PRE_LIVE_VDEV2", "pre_phase_marker")
	}
	return l
}
func consumePhase(p proof, l actionLedger, emit func(map[string]any)) {
	require(l.BootID == p.BootID && p.BootID > 165, "Consumed historical boots forbidden")
	if p.Phase != "POST_STALL" {
		_, e := os.Stat(markerPath(p.BootID, "POST_STALL"))
		require(os.IsNotExist(e), "Cannot arm/baseline after POST")
	}
	if p.Phase == "ARM_LIVE_VDEV2" {
		_, e := os.Stat(markerPath(p.BootID, "PRE_LIVE_VDEV2"))
		require(os.IsNotExist(e), "Cannot rearm after baseline")
	}
	m := phaseIntent{Schema: "wifi-live-vdev2-host-once/1", BootID: p.BootID, Session: p.Session, Image: p.Image, Phase: p.Phase, Nonce: p.Nonce, LedgerSHA: p.Evidence["action_ledger"]}
	raw, e := json.Marshal(m)
	require(e == nil, "Intent JSON")
	path := markerPath(p.BootID, p.Phase)
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	require(e == nil, "Phase consumed or fixed host marker directory unavailable; no retry")
	n, we := f.Write(raw)
	se := f.Sync()
	ce := f.Close()
	require(we == nil && n == len(raw) && se == nil && ce == nil, "Intent persistence failed; preserve consumed marker")
	h := sha256.Sum256(raw)
	emit(map[string]any{"phase": "phase_consumed_before_debugger_connect", "marker_path": path, "marker_sha256": hex.EncodeToString(h[:]), "calls_max_for_phase": 1, "read_outcome_not_yet_known": true})
}
