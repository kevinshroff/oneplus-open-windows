// SPDX-License-Identifier: MIT
package main

import (
	"errors"
	"regexp"
	"strings"
)

const trialDSDT = "4079f58af46d7c8e262973283a055ac0c7cc3d5208165cfb599884e621e75f39"
const packageSHA = "a380536307155d4c9362884ad31aad11a396640d53ac057c9a6978c07050959a"
const packageDir = `X:\OpenG17\payloads\G70-clock-package`
const hardwareID = `ACPI\OPEN0070`

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
	if e.OS != "windows" || e.Arch != "arm64" || e.CPUs != 8 || e.Build != 26100 || !strings.EqualFold(e.SystemRoot, `X:\Windows`) || !ramName.MatchString(e.XDevice) || !strings.EqualFold(strings.TrimSpace(e.BootDevice), "ramdisk(0)") || e.DSDTBytes != 768 || e.DSDTSHA != trialDSDT {
		return errors.New("G70 setup requires the exact ARM64/eight-CPU/26100 G70 RAM trial, X RAM mapping, boot witness and768byte table hash")
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
