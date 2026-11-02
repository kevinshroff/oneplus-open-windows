package main

import (
	"strings"
	"testing"
)

func TestFootprintRejectsStaleOrArmedReports(t *testing.T) {
	s := positive("Success")
	cases := map[string]string{
		"stale":          strings.Replace(s, "OPEN-KERNEL-FOOTPRINT G131 version=1\n", "", 1),
		"duplicate":      s + "OPEN-KERNEL-FOOTPRINT G131 version=1\nDSP_start=not_armed request_count=0\n",
		"missing_done":   strings.Replace(s, "K131_DONE", "OLD_DONE", 1),
		"PAS":            strings.Replace(s, "PAS_allowed=0", "PAS_allowed=1", 1),
		"duplicate_call": strings.Replace(s, "K131_DONE", "K131_ERROR duplicate_call\nK131_DONE", 1),
		"counter":        strings.Replace(s, "K131_image_overlaps=0", "K131_image_overlaps=18446744073709551616", 1),
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := decodeReport(packet(text)); e == nil {
				t.Fatal("accepted invalid footprint")
			}
		})
	}
}
func TestFootprintFactsNeverGrantEligibility(t *testing.T) {
	for _, text := range []string{
		positive("Success"),
		strings.Replace(positive("Success"), "queries_complete=1", "queries_complete=0", 1),
		strings.Replace(positive("Success"), "K131_image_overlaps=0", "K131_image_overlaps=2", 1),
	} {
		r, e := decodeReport(packet(text))
		if e != nil || !r.ReportValid || r.KernelMemoryEligible || r.DisplayOwnershipQualified || r.DSPStarted {
			t.Fatalf("%+v %v", r, e)
		}
		if r.KernelQueriesComplete != strings.Contains(text, "queries_complete=1") {
			t.Fatal("query completeness changed")
		}
	}
}
func TestFootprintLargerBodyLimit(t *testing.T) {
	s := positive("Success")
	marker := "FINAL file_status="
	text := strings.Replace(s, marker, strings.Repeat("# diagnostic context\n", 1000)+marker, 1)
	if len(text) <= 24*1024 || len(text) > 32*1024 {
		t.Fatal("large fixture bounds")
	}
	if _, e := decodeReport(packet(text)); e != nil {
		t.Fatal(e)
	}
	text = strings.Replace(s, marker, strings.Repeat("x", 32*1024)+"\n"+marker, 1)
	if _, e := decodeReport(packet(text)); e == nil {
		t.Fatal("accepted oversized body")
	}
}
