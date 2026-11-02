package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func fullOSConfig(c Config, arch, root, drive string) error {
	if arch != "arm64" || !strings.EqualFold(root, `C:\Windows`) || !strings.EqualFold(drive, "C:") || c.Node != "phone" {
		return fmt.Errorf("requires installed ARM64 Windows on C:")
	}
	if !strings.EqualFold(c.StateDir, `C:\OpenG81\state`) || !strings.EqualFold(c.PayloadDir, `C:\OpenG81\payloads`) || c.URL != "http://192.0.2.10:50117" || !c.ConfigurePhoneIP {
		return fmt.Errorf("requires dedicated full-OS paths and USB relay")
	}
	return nil
}
func fullOSVolume(device, name, kind, unique string, offset, size uint64) error {
	if !strings.HasPrefix(strings.ToLower(device), `\device\harddiskvolume`) {
		return fmt.Errorf("installed OS device is not a physical volume")
	}
	tail := strings.TrimPrefix(strings.ToLower(device), `\device\harddiskvolume`)
	n, e := strconv.Atoi(tail)
	if e != nil || n < 1 || name != "super" || kind != "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7" || unique != "1c68511e-28af-a8c9-dd6f-e3303d568c04" || offset != 0x2208000 || size != 0x440000000 {
		return fmt.Errorf("installed OS volume identity mismatch")
	}
	return nil
}

// A preconfigured address avoids invoking netsh before NSI/RPC is available.
func fullOSUSBAddress(addresses []net.Addr) bool {
	for _, a := range addresses {
		ip, network, e := net.ParseCIDR(a.String())
		if e != nil {
			continue
		}
		ones, bits := network.Mask.Size()
		if ip.Equal(net.IPv4(169, 254, 2, 10)) && ones == 16 && bits == 32 {
			return true
		}
	}
	return false
}
