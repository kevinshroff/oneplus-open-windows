package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func modelProof() map[string]any {
	raw := make([]byte, 9116)
	copy(raw, "OADP")
	h := sha256.Sum256(raw)
	return map[string]any{"ok": true, "report": map[string]any{
		"report_valid": true, "stable_double_read": true, "table_sha256": hex.EncodeToString(h[:]), "raw_table_base64": base64.StdEncoding.EncodeToString(raw),
		"fault": 0, "fatal_restore": false, "flags": 255, "phase": []int{3, 3}, "PAS_sequence_accepted": true, "DTB_sequence_accepted": true, "main_public_success": true, "main_enabled": true,
		"hook_stores": 2, "PAS_entered_stages": 6, "PAS_returned_stages": 6, "SCM_error": map[string]any{"report_valid": true, "stable_double_read": true, "fatal_restore": false, "hook_stores": 2, "parser_fault": 0},
	}}
}
func TestBootProofGate(t *testing.T) {
	for _, mutation := range []string{"valid", "ok", "report_valid", "stable_double_read", "fault", "fatal_restore", "flags", "phase", "PAS_sequence_accepted", "DTB_sequence_accepted", "main_public_success", "main_enabled", "hook_stores", "PAS_entered_stages", "PAS_returned_stages", "table_sha256", "raw_table_base64", "scmStable", "scmFatal", "scmHook", "scmParser"} {
		t.Run(mutation, func(t *testing.T) {
			p := modelProof()
			r := p["report"].(map[string]any)
			s := r["SCM_error"].(map[string]any)
			switch mutation {
			case "valid":
			case "ok":
				p["ok"] = false
			case "report_valid", "stable_double_read", "PAS_sequence_accepted", "DTB_sequence_accepted", "main_public_success", "main_enabled":
				r[mutation] = false
			case "fatal_restore":
				r[mutation] = true
			case "fault", "flags", "hook_stores", "PAS_entered_stages", "PAS_returned_stages":
				r[mutation] = 1
			case "phase":
				r[mutation] = []int{3, 2}
			case "table_sha256":
				r[mutation] = "00"
			case "raw_table_base64":
				r[mutation] = "AQID"
			case "scmStable":
				s["stable_double_read"] = false
			case "scmFatal":
				s["fatal_restore"] = true
			case "scmHook":
				s["hook_stores"] = 1
			case "scmParser":
				s["parser_fault"] = 1
			}
			b, e := json.Marshal(p)
			if e != nil {
				t.Fatal(e)
			}
			_, e = bootProof(b)
			if (e == nil) != (mutation == "valid") {
				t.Fatal("proof gate", mutation, e)
			}
		})
	}
}
