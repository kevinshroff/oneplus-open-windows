package main

import (
	"fmt"
	"strings"
)

const (
	ramUpdateDSDT = "c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01"
	ramWIMBefore  = "de32242eb883ed45d1d29db52190ef5161da6845cccbad40c7cf821a0866b9dc"
	ramWIMAfter   = "2bfb6b1b9ab14e01d724c69ce26cfd6afb6716cb5ad658b1e3c658b348158694"
	ramWIMOldSize = uint64(595963755)
	ramWIMNewSize = uint64(597504805)
)

type ramUpdateEnvironment struct {
	Build, CPUs         uint32
	XDevice, BootDevice string
	DSDTBytes           int
	DSDTSHA             string
}

func validateRAMUpdateEnvironment(e ramUpdateEnvironment) error {
	if e.Build != 26100 || e.CPUs != 8 || !validRAMDevice(e.XDevice) || !strings.EqualFold(e.BootDevice, "ramdisk(0)") || e.DSDTBytes != 576 || e.DSDTSHA != ramUpdateDSDT {
		return fmt.Errorf("requires the original-table eight-CPU build26100 RAM maintenance environment")
	}
	return nil
}

// This command qualifies one retained, fully audited image pair in either
// direction. It does not make the physical-root updater less restrictive.
func validateRAMWIMPair(p WIMPlan) error {
	forward := p.BeforeBytes == ramWIMOldSize && p.AfterBytes == ramWIMNewSize && p.BeforeSHA == ramWIMBefore && p.AfterSHA == ramWIMAfter
	inverse := p.BeforeBytes == ramWIMNewSize && p.AfterBytes == ramWIMOldSize && p.BeforeSHA == ramWIMAfter && p.AfterSHA == ramWIMBefore
	if p.Version != "G21-trial-wim-v1" || p.Name != trialWIMName || (!forward && !inverse) {
		return fmt.Errorf("RAM updater accepts only the retained G70 image pair")
	}
	return nil
}

// Plans and journals must be flat JSON files in a directory whose final NT
// path is independently verified on RAM. Reject aliases before opening files.
func ramJSONParent(path string) (string, error) {
	for _, parent := range []string{`X:\OpenG17\payloads`, `X:\OpenG18`} {
		prefix := parent + `\`
		if !strings.HasPrefix(strings.ToLower(path), strings.ToLower(prefix)) {
			continue
		}
		name := path[len(prefix):]
		if len(name) < 6 || len(name) > 100 || !strings.HasSuffix(strings.ToLower(name), ".json") || name[0] == '.' {
			break
		}
		for _, c := range name {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
				return "", fmt.Errorf("RAM JSON filename character")
			}
		}
		return parent, nil
	}
	return "", fmt.Errorf("requires a flat RAM payload JSON path")
}

func validateRAMUpdatePaths(plan, journal string) (string, string, error) {
	p, e := ramJSONParent(plan)
	if e != nil {
		return "", "", e
	}
	j, e := ramJSONParent(journal)
	if e != nil {
		return "", "", e
	}
	if strings.EqualFold(plan, journal) {
		return "", "", fmt.Errorf("distinct RAM plan and journal required")
	}
	return p, j, nil
}
