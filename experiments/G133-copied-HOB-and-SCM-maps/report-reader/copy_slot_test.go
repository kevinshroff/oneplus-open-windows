package main

import (
	"strings"
	"testing"
)

func TestCopyAndSlotRejectContradictoryCompletion(t *testing.T) {
	s := positive("Success")
	cases := map[string]string{
		"missing_copy_row":        strings.Replace(s, "K133_hob_storage_matches=1", "OLD_hob_storage_matches=1", 1),
		"duplicate_copy_row":      s + "K133_hob_storage_matches=1 base=C0000000 limit=C0001000\nDSP_start=not_armed request_count=0\n",
		"end_before_base":         strings.Replace(s, "limit=C0001000", "limit=BFFFFFFF", 1),
		"unbounded_copy":          strings.Replace(s, "limit=C0001000", "limit=C0200000", 1),
		"walk_past_storage":       strings.Replace(s, "walked_bytes=104", "walked_bytes=4096", 1),
		"no_end":                  strings.Replace(s, "overlaps=1 end=1", "overlaps=1 end=0", 1),
		"zero_hobs":               strings.Replace(s, "K133_hob_count=3", "K133_hob_count=0", 1),
		"table_slot_disagreement": strings.Replace(s, "slot=C510E178", "slot=C510E180", 1),
		"GCD_does_not_cover":      strings.Replace(s, "bytes=1000 type=2", "bytes=170 type=2", 1),
		"GCD_wrong_type":          strings.Replace(s, "bytes=1000 type=2", "bytes=1000 type=1", 1),
		"EFI_wrong_type":          strings.Replace(s, "pages=1 type=4", "pages=1 type=0", 1),
		"EFI_page_overflow":       strings.Replace(s, "pages=1 type=4", "pages=FFFFFFFFFFFFFFFF type=4", 1),
		"duplicate_slot_map":      s + "K133_scm_efi base=C510E000 pages=1 type=4 attr=8\nDSP_start=not_armed request_count=0\n",
		"SCM_map_failed":          strings.Replace(s, "K133_scm_gcd_status=Success", "K133_scm_gcd_status=Not Found", 1),
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := decodeReport(packet(text)); e == nil {
				t.Fatal("accepted contradictory inventory")
			}
		})
	}
}
func TestPublishedMapAttributesGrantNothing(t *testing.T) {
	text := strings.ReplaceAll(positive("Success"), "attr=8", "attr=20008")
	r, e := decodeReport(packet(text))
	if e != nil || !r.ScmMapsObserved || !r.HobStorageBounded || r.ScmHookEligible || r.KernelMemoryEligible {
		t.Fatalf("%+v %v", r, e)
	}
}
func TestMissingQueriesRemainInspectable(t *testing.T) {
	s := positive("Success")
	s = strings.Replace(s, "queries_complete=1", "queries_complete=0", 1)
	s = strings.Replace(s, "K133_hob_storage_matches=1 base=C0000000 limit=C0001000", "K133_hob_storage_matches=0 base=C0000000 limit=0", 1)
	s = strings.Replace(s, "K133_hob_count=3 walked_bytes=104 overlaps=1 end=1", "K133_hob_count=0 walked_bytes=0 overlaps=0 end=0", 1)
	s = strings.Replace(s, "K133_scm locate=Success table=C510E140 slot=C510E178", "K133_scm locate=Not Found table=0 slot=0", 1)
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		if !strings.HasPrefix(line, "K133_scm_gcd") && !strings.HasPrefix(line, "K133_scm_efi base=") {
			lines = append(lines, line)
		}
	}
	s = strings.Replace(strings.Join(lines, "\n"), "K133_scm_efi_matches=1", "K133_scm_efi_matches=0", 1)
	r, e := decodeReport(packet(s))
	if e != nil || !r.ReportValid || r.KernelQueriesComplete || r.HobStorageBounded || r.ScmMapsObserved || r.KernelMemoryEligible || r.ScmHookEligible {
		t.Fatalf("%+v %v", r, e)
	}
}
