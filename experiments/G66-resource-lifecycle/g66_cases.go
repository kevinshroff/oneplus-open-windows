// SPDX-License-Identifier: MIT
// Pure guard cases; no native API, device or filesystem operation.
package main

import (
	"fmt"
	"strings"
)

func main() {
	e := Environment{"windows", "arm64", 8, 26100, `X:\Windows`, `\Device\Ramdisk{d9b257fc-684e-4dcb-ab79-03cfa2f6b750}`, "ramdisk(0)", 730, trialDSDT}
	on := Node{`ACPI\OPEN0063\0`, 8, 0, "OpenG63"}
	off := on
	off.Status = 0
	off.Problem = 22
	nonce := strings.Repeat("a", 32)
	p := Result{"disable", nonce, e, on, off, "CM_Disable_DevNode", 4, 0, true, true}
	count := 0
	check := func(want bool, mode string, env Environment, n Node, token string, prior *Result) {
		count++
		if (authorize(mode, token, env, n, prior) == nil) != want {
			panic(fmt.Sprintf("guard case%d mode%s", count, mode))
		}
	}
	check(true, "disable", e, on, nonce, nil)
	check(true, "enable", e, off, nonce, &p)
	for _, mode := range []string{"disable", "enable"} {
		n := on
		var prior *Result
		if mode == "enable" {
			n = off
			prior = &p
		}
		for _, field := range []string{"OS", "arch", "CPUs", "build", "root", "mapping", "boot", "tableSize", "tableHash"} {
			x := e
			switch field {
			case "OS":
				x.OS = "linux"
			case "arch":
				x.Arch = "amd64"
			case "CPUs":
				x.CPUs = 1
			case "build":
				x.Build++
			case "root":
				x.SystemRoot = `C:\Windows`
			case "mapping":
				x.XDevice = `\Device\HarddiskVolume6`
			case "boot":
				x.BootDevice = "multi(0)disk(0)rdisk(0)partition(6)"
			case "tableSize":
				x.DSDTBytes = 576
			case "tableHash":
				x.DSDTSHA = strings.Repeat("0", 64)
			}
			check(false, mode, x, n, nonce, prior)
		}
		for _, bad := range []string{"", strings.Repeat("A", 32), strings.Repeat("a", 31), strings.Repeat("a", 33), `..\escape`} {
			check(false, mode, e, n, bad, prior)
		}
		for _, instance := range []string{`ACPI\QCOMFFEB\0`, `ACPI\OPEN0063\1`, `ACPI\OPEN0063\0\child`, ""} {
			x := n
			x.Instance = instance
			check(false, mode, e, x, nonce, prior)
		}
		for _, service := range []string{"", "OpenG64", "storufs"} {
			x := n
			x.Service = service
			check(false, mode, e, x, nonce, prior)
		}
	}
	check(false, "disable", e, off, nonce, nil)
	check(false, "disable", e, on, nonce, &p)
	check(false, "enable", e, on, nonce, &p)
	check(false, "enable", e, off, nonce, nil)
	for _, mode := range []string{"restart", "remove", "enable-all", ""} {
		check(false, mode, e, on, nonce, nil)
	}
	for _, field := range []string{"mode", "nonce", "api", "flags1", "persistent", "CR", "changed", "verified", "before", "after", "environment"} {
		q := p
		switch field {
		case "mode":
			q.Mode = "enable"
		case "nonce":
			q.Nonce = strings.Repeat("b", 32)
		case "api":
			q.API = "other"
		case "flags1":
			q.Flags = 1
		case "persistent":
			q.Flags = 12
		case "CR":
			q.CR = 1
		case "changed":
			q.APIReportedSuccess = false
		case "verified":
			q.Verified = false
		case "before":
			q.Before = off
		case "after":
			q.After = on
		case "environment":
			q.Environment.XDevice = `\Device\Ramdisk{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}`
		}
		check(false, "enable", e, off, nonce, &q)
	}
	fmt.Printf("{\"passed\":true,\"cases\":%d,\"native_operations\":0}\n", count)
}
