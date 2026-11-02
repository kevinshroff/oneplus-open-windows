// SPDX-License-Identifier: MIT
package main

import (
	"errors"
	"regexp"
	"strings"
)

const trialDSDT = "1682de06510a8dc8f1d82a10be035e3ac9e8ecbd5b116f0ad160d8f43e1832f1"
const packageSHA = "26b0a84d18d8d6d460cefbca609f3975783a0b28d7f4e0cbdddc6dca4017a757"
const packageDir = `X:\OpenG17\payloads\G68-G67-package`
const hardwareID = `ACPI\OPEN0067`

type Environment struct {
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	CPUs       int    `json:"cpus"`
	Build      uint32 `json:"build"`
	SystemRoot string `json:"systemroot"`
	XDevice    string `json:"x_device"`
	BootDevice string `json:"system_boot_device"`
	DSDTBytes  int    `json:"DSDT_bytes"`
	DSDTSHA    string `json:"DSDT_sha256"`
}

var ramName = regexp.MustCompile(`(?i)^\\Device\\Ramdisk\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$`)

func allowedRAM(e Environment) error {
	if e.OS != "windows" || e.Arch != "arm64" || e.CPUs != 8 || e.Build != 26100 || !strings.EqualFold(e.SystemRoot, `X:\Windows`) || !ramName.MatchString(e.XDevice) || !strings.EqualFold(strings.TrimSpace(e.BootDevice), "ramdisk(0)") || e.DSDTBytes != 742 || e.DSDTSHA != trialDSDT {
		return errors.New("G68 setup requires the exact ARM64/eight-CPU/26100 G67 RAM trial, X RAM mapping, boot witness and742byte table hash")
	}
	return nil
}
func goodToken(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
