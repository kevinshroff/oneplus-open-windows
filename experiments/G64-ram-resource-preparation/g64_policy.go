// SPDX-License-Identifier: MIT
package main

import (
	"errors"
	"regexp"
	"strings"
)

const trialDSDT = "cdc95eadbedcaf60088741e36803b9c96297ccc72afa48b2adb5d9b9c3205ece"
const packageSHA = "db82ea3d266206c41401e6274f77a2d763dadf4a93f2687dbf83d70eed253dd9"
const packageDir = `X:\OpenG17\payloads\G64-G63-package`
const hardwareID = `ACPI\OPEN0063`

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
	if e.OS != "windows" || e.Arch != "arm64" || e.CPUs != 8 || e.Build != 26100 || !strings.EqualFold(e.SystemRoot, `X:\Windows`) || !ramName.MatchString(e.XDevice) || !strings.EqualFold(strings.TrimSpace(e.BootDevice), "ramdisk(0)") || e.DSDTBytes != 730 || e.DSDTSHA != trialDSDT {
		return errors.New("G64 setup requires the exact ARM64/eight-CPU/26100 G63 RAM trial, X RAM mapping, boot witness and730byte table hash")
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
