package main

import (
	"strings"
	"testing"
)

func TestRAMUpdaterRejectsPhysicalWrongBuildCPUAndTable(t *testing.T) {
	good := ramUpdateEnvironment{26100, 8, `\Device\Ramdisk{26cb3452-bca7-422f-a7c7-52804e844e68}`, "ramdisk(0)", 576, ramUpdateDSDT}
	if e := validateRAMUpdateEnvironment(good); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"physical", "malformedRAM", "build", "cpu", "boot", "bootSubstring", "tableSize", "tableHash"} {
		t.Run(kind, func(t *testing.T) {
			e := good
			switch kind {
			case "physical":
				e.XDevice = `\Device\HarddiskVolume6`
			case "malformedRAM":
				e.XDevice += `\physical`
			case "build":
				e.Build++
			case "cpu":
				e.CPUs = 1
			case "boot":
				e.BootDevice = "multi(0)disk(0)rdisk(0)partition(6)"
			case "bootSubstring":
				e.BootDevice = "prefix ramdisk(0) suffix"
			case "tableSize":
				e.DSDTBytes = 730
			case "tableHash":
				e.DSDTSHA = strings.Repeat("0", 64)
			}
			if validateRAMUpdateEnvironment(e) == nil {
				t.Fatal("accepted incompatible environment")
			}
		})
	}
}

func TestRAMUpdaterPinsForwardAndInverseImages(t *testing.T) {
	p := WIMPlan{Version: "G21-trial-wim-v1", Name: trialWIMName, BeforeBytes: ramWIMOldSize, AfterBytes: ramWIMNewSize, BeforeSHA: ramWIMBefore, AfterSHA: ramWIMAfter}
	q := p
	q.BeforeBytes, q.AfterBytes, q.BeforeSHA, q.AfterSHA = p.AfterBytes, p.BeforeBytes, p.AfterSHA, p.BeforeSHA
	for _, good := range []WIMPlan{p, q} {
		if e := validateRAMWIMPair(good); e != nil {
			t.Fatal(e)
		}
		for _, kind := range []string{"name", "version", "beforeSize", "afterSize", "beforeSHA", "afterSHA"} {
			bad := good
			switch kind {
			case "name":
				bad.Name = "G18-maintenance.wim"
			case "version":
				bad.Version += "x"
			case "beforeSize":
				bad.BeforeBytes++
			case "afterSize":
				bad.AfterBytes++
			case "beforeSHA":
				bad.BeforeSHA = strings.Repeat("0", 64)
			case "afterSHA":
				bad.AfterSHA = strings.Repeat("0", 64)
			}
			if validateRAMWIMPair(bad) == nil {
				t.Fatal("accepted unqualified image pair", kind)
			}
		}
	}
}

func TestRAMUpdaterRejectsPathEscapeAliasesAndAlternateStreams(t *testing.T) {
	for _, good := range []string{`X:\OpenG17\payloads\G65-forward.json`, `x:\openg18\G65-update.journal.JSON`} {
		if _, e := ramJSONParent(good); e != nil {
			t.Fatal(e)
		}
	}
	for _, bad := range []string{`C:\OpenG17\payloads\p.json`, `X:\OpenG17\payloads2\p.json`, `X:\OpenG17\payloads\..\p.json`, `X:\OpenG17\payloads\sub\p.json`, `X:\OpenG17\payloads\p.json:stream`, `X:\OpenG17\payloads\p.json.`, `X:\OpenG17\payloads\p.json `, `X:/OpenG17/payloads/p.json`, `\\?\X:\OpenG17\payloads\p.json`, `X:\OpenG18\`, `X:\OpenG18\.json`, `X:\OpenG18\p.exe`} {
		if _, e := ramJSONParent(bad); e == nil {
			t.Fatal("accepted escaped/aliased path", bad)
		}
	}
	if _, _, e := validateRAMUpdatePaths(`X:\OpenG17\payloads\p.json`, `x:\openg17\PAYLOADS\P.JSON`); e == nil {
		t.Fatal("accepted case alias")
	}
}
