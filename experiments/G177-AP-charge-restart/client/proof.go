package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

func bootProof(b []byte) (string, error) {
	var p struct {
		OK     bool `json:"ok"`
		Report struct {
			Valid       bool      `json:"report_valid"`
			Stable      bool      `json:"stable_double_read"`
			SHA         string    `json:"table_sha256"`
			Raw         string    `json:"raw_table_base64"`
			Fault       uint32    `json:"fault"`
			Fatal       bool      `json:"fatal_restore"`
			Flags       uint32    `json:"flags"`
			Phase       [2]uint32 `json:"phase"`
			Sequence    bool      `json:"PAS_sequence_accepted"`
			Dtb         bool      `json:"DTB_sequence_accepted"`
			Main        bool      `json:"main_public_success"`
			MainEnabled bool      `json:"main_enabled"`
			Hook        uint32    `json:"hook_stores"`
			Entered     uint32    `json:"PAS_entered_stages"`
			Returned    uint32    `json:"PAS_returned_stages"`
			SCM         struct {
				Valid  bool   `json:"report_valid"`
				Stable bool   `json:"stable_double_read"`
				Fatal  bool   `json:"fatal_restore"`
				Hook   uint32 `json:"hook_stores"`
				Parser uint32 `json:"parser_fault"`
			} `json:"SCM_error"`
		} `json:"report"`
	}
	if e := json.Unmarshal(b, &p); e != nil {
		return "", e
	}
	r := p.Report
	if !p.OK || !r.Valid || !r.Stable || r.Fault != 0 || r.Fatal || r.Flags != 255 || r.Phase != [2]uint32{3, 3} || !r.Sequence || !r.Dtb || !r.Main || !r.MainEnabled || r.Hook != 2 || r.Entered != 6 || r.Returned != 6 || !r.SCM.Valid || !r.SCM.Stable || r.SCM.Fatal || r.SCM.Hook != 2 || r.SCM.Parser != 0 {
		return "", fmt.Errorf("complete fresh G155 diagnostic and restored hooks required")
	}
	raw, e := base64.StdEncoding.DecodeString(r.Raw)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(raw)
	if len(raw) != 9116 || string(raw[:4]) != "OADP" || hex.EncodeToString(h[:]) != r.SHA {
		return "", fmt.Errorf("G155 raw report digest binding")
	}
	return r.SHA, nil
}
