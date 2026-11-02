package main

import (
	"net"
	"testing"
)

func TestFullOSConfigBoundary(t *testing.T) {
	c := Config{Node: "phone", StateDir: `C:\OpenG81\state`, PayloadDir: `C:\OpenG81\payloads`, URL: "http://192.0.2.10:50117", ConfigurePhoneIP: true}
	if e := fullOSConfig(c, "arm64", `C:\Windows`, "C:"); e != nil {
		t.Fatal(e)
	}
	for _, x := range []struct{ arch, root, drive string }{{"amd64", `C:\Windows`, "C:"}, {"arm64", `X:\Windows`, "X:"}, {"arm64", `D:\Windows`, "D:"}} {
		if fullOSConfig(c, x.arch, x.root, x.drive) == nil {
			t.Fatal("wrong environment admitted", x)
		}
	}
	for _, which := range []string{"node", "state", "payload", "url", "network"} {
		x := c
		switch which {
		case "node":
			x.Node = "host"
		case "state":
			x.StateDir = `X:\OpenG17\state`
		case "payload":
			x.PayloadDir = `C:\OpenG81\payloads\..\escape`
		case "url":
			x.URL = "http://127.0.0.1:50117"
		case "network":
			x.ConfigurePhoneIP = false
		}
		if fullOSConfig(x, "arm64", `C:\Windows`, "C:") == nil {
			t.Fatal("wrong config admitted", which)
		}
	}
}
func TestFullOSVolumeBoundary(t *testing.T) {
	kind := "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
	id := "1c68511e-28af-a8c9-dd6f-e3303d568c04"
	if e := fullOSVolume(`\Device\HarddiskVolume6`, "super", kind, id, 0x2208000, 0x440000000); e != nil {
		t.Fatal(e)
	}
	for _, device := range []string{"6", `\Device\Ramdisk{fake}`, `\Device\HarddiskVolume`, `\Device\HarddiskVolume0`, `\Device\HarddiskVolume6\other`} {
		if fullOSVolume(device, "super", kind, id, 0x2208000, 0x440000000) == nil {
			t.Fatal("bad device admitted", device)
		}
	}
	if fullOSVolume(`\Device\HarddiskVolume40`, "modem_a", kind, id, 0x2208000, 0x440000000) == nil {
		t.Fatal("wrong partition admitted")
	}
	if fullOSVolume(`\Device\HarddiskVolume6`, "super", kind, "5982c0bf-b83f-025d-4354-68009ba0a5d1", 0x2208000, 0x440000000) == nil {
		t.Fatal("wrong GUID admitted")
	}
	if fullOSVolume(`\Device\HarddiskVolume6`, "super", kind, id, 0x2208001, 0x440000000) == nil {
		t.Fatal("wrong extent admitted")
	}
}

func TestPreconfiguredUSBAddress(t *testing.T) {
	for _, x := range []struct {
		address string
		want    bool
	}{{"192.0.2.10/16", true}, {"192.0.2.10/24", false}, {"192.0.2.10/16", false}, {"127.0.0.1/8", false}, {"fe80::1/64", false}} {
		ip, n, e := net.ParseCIDR(x.address)
		if e != nil {
			t.Fatal(e)
		}
		a := &net.IPNet{IP: ip, Mask: n.Mask}
		if fullOSUSBAddress([]net.Addr{a}) != x.want {
			t.Fatal(x)
		}
	}
	if fullOSUSBAddress(nil) {
		t.Fatal("empty interface addresses")
	}
}
