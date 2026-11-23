// SPDX-License-Identifier: MIT
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	ioctlStatus = 0x00226000
	ioctlPause  = 0x0022A004
	ioctlResume = 0x0022A008

	scManagerAllAccess         = 0xF003F
	serviceAllAccess           = 0xF01FF
	serviceKernelDriver        = 0x00000001
	serviceDemandStart         = 0x00000003
	serviceErrorNormal         = 0x00000001
	serviceControlStop         = 0x00000001
	errServiceExists           = syscall.Errno(1073)
	errServiceAlreadyRunning   = syscall.Errno(1056)
)

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procDeviceIoControl  = kernel32.NewProc("DeviceIoControl")
	advapi32             = syscall.NewLazyDLL("advapi32.dll")
	procOpenSCManagerW   = advapi32.NewProc("OpenSCManagerW")
	procCreateServiceW   = advapi32.NewProc("CreateServiceW")
	procOpenServiceW     = advapi32.NewProc("OpenServiceW")
	procStartServiceW    = advapi32.NewProc("StartServiceW")
	procControlService   = advapi32.NewProc("ControlService")
	procDeleteService    = advapi32.NewProc("DeleteService")
	procCloseSvcHandle   = advapi32.NewProc("CloseServiceHandle")

	stateNames      = []string{"IDLE", "SET_FV", "PRE_OFF", "GAP_WAIT", "ENABLING", "CHARGING", "DISABLING", "HOLD_FULL", "SAFETY_HOLD", "PAUSED"}
	safetyNames     = []string{"OK", "NO_USB", "TEMP", "OVERVOLT", "IMBALANCE", "GAUGE_ERR", "OPERATOR_PAUSE"}
	glinkPhaseNames = []string{"NEW", "NEGOTIATING", "OPENING", "READY", "CLOSING", "CLOSED", "FAILED"}
)

type serviceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

func nameOf(arr []string, i uint32) string {
	if int(i) < len(arr) {
		return arr[i]
	}
	return fmt.Sprintf("UNKNOWN(%d)", i)
}

func startDriver(sysPath string) error {
	scm, _, e := procOpenSCManagerW.Call(0, 0, scManagerAllAccess)
	if scm == 0 {
		return fmt.Errorf("OpenSCManagerW: %v", e)
	}
	defer procCloseSvcHandle.Call(scm)

	namePtr, _ := syscall.UTF16PtrFromString("OpenChargerKeeper")
	pathPtr, _ := syscall.UTF16PtrFromString(sysPath)

	svc, _, e := procCreateServiceW.Call(
		scm,
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(namePtr)),
		serviceAllAccess,
		serviceKernelDriver,
		serviceDemandStart,
		serviceErrorNormal,
		uintptr(unsafe.Pointer(pathPtr)),
		0, 0, 0, 0, 0,
	)
	if svc == 0 {
		if e == errServiceExists {
			svc, _, e = procOpenServiceW.Call(scm, uintptr(unsafe.Pointer(namePtr)), serviceAllAccess)
			if svc == 0 {
				return fmt.Errorf("OpenServiceW: %v", e)
			}
		} else {
			return fmt.Errorf("CreateServiceW: %v", e)
		}
	}
	defer procCloseSvcHandle.Call(svc)

	r, _, e := procStartServiceW.Call(svc, 0, 0)
	if r == 0 && e != errServiceAlreadyRunning {
		return fmt.Errorf("StartServiceW: %v", e)
	}
	return nil
}

func stopDriver() error {
	scm, _, e := procOpenSCManagerW.Call(0, 0, scManagerAllAccess)
	if scm == 0 {
		return fmt.Errorf("OpenSCManagerW: %v", e)
	}
	defer procCloseSvcHandle.Call(scm)

	namePtr, _ := syscall.UTF16PtrFromString("OpenChargerKeeper")
	svc, _, e := procOpenServiceW.Call(scm, uintptr(unsafe.Pointer(namePtr)), serviceAllAccess)
	if svc == 0 {
		return fmt.Errorf("OpenServiceW: %v", e)
	}
	defer procCloseSvcHandle.Call(svc)

	var st serviceStatus
	_, _, _ = procControlService.Call(svc, serviceControlStop, uintptr(unsafe.Pointer(&st)))
	_, _, _ = procDeleteService.Call(svc)
	return nil
}

func queryDriver(ioctl uint32) {
	p, err := syscall.UTF16PtrFromString(`\\.\OpenChargerKeeper`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "utf16: %v\n", err)
		os.Exit(1)
	}
	access := uint32(syscall.GENERIC_READ)
	if ioctl != ioctlStatus {
		access |= syscall.GENERIC_WRITE
	}
	h, err := syscall.CreateFile(p, access, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open \\\\.\\OpenChargerKeeper: %v\n", err)
		os.Exit(1)
	}
	defer syscall.CloseHandle(h)

	buf := make([]byte, 512)
	var got uint32
	r1, _, e1 := procDeviceIoControl.Call(uintptr(h), uintptr(ioctl), 0, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&got)), 0)
	if r1 == 0 {
		fmt.Fprintf(os.Stderr, "DeviceIoControl: %v\n", e1)
		os.Exit(1)
	}
	u32 := func(off int) uint32 { return binary.LittleEndian.Uint32(buf[off : off+4]) }
	i32 := func(off int) int32 { return int32(binary.LittleEndian.Uint32(buf[off : off+4])) }
	u64 := func(off int) uint64 { return binary.LittleEndian.Uint64(buf[off : off+8]) }

	tOff := 104
	out := map[string]any{
		"bytes":          got,
		"kernel_build":   u32(12),
		"cpus":           u32(16),
		"admitted":       u32(20),
		"admission_code": u32(24),
		"glink_phase":    nameOf(glinkPhaseNames, u32(28)),
		"glink_fault":    u32(32),
		"policy_state":   nameOf(stateNames, u32(36)),
		"safety_reason":  nameOf(safetyNames, u32(40)),
		"fv_programmed":  u32(44),
		"paused":         u32(48),
		"enable_count":   u32(52),
		"disable_count":  u32(56),
		"safety_trips":   u32(60),
		"gauge_ok":       u32(64),
		"gauge_fail":     u32(68),
		"now_us":         u64(72),
		"timer_ticks":    u64(80),
		"glink_tx":       u64(88),
		"glink_rx":       u64(96),
		"telemetry": map[string]any{
			"valid":      u32(tOff + 0),
			"usb_online": u32(tOff + 4),
			"usb_type":   u32(tOff + 8),
			"volt_mv":    []uint32{u32(tOff + 12), u32(tOff + 16)},
			"temp_c":     []float64{float64(int32(u32(tOff+20))-2731) / 10.0, float64(int32(u32(tOff+24))-2731) / 10.0},
			"soc_pct":    []uint32{u32(tOff + 28), u32(tOff + 32)},
			"rem_mah":    []uint32{u32(tOff + 36), u32(tOff + 40)},
			"full_mah":   []uint32{u32(tOff + 44), u32(tOff + 48)},
			"curr_ma":    []int32{i32(tOff + 52), i32(tOff + 56)},
			"flags":      []uint32{u32(tOff + 60), u32(tOff + 64)},
		},
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func main() {
	ioctl := uint32(ioctlStatus)
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "start":
			if len(os.Args) < 3 {
				fmt.Fprintf(os.Stderr, "usage: ck-status start <path-to-OpenChargerKeeper.sys>\n")
				os.Exit(2)
			}
			if err := startDriver(os.Args[2]); err != nil {
				fmt.Fprintf(os.Stderr, "start failed: %v\n", err)
				os.Exit(1)
			}
			time.Sleep(1500 * time.Millisecond)
			queryDriver(ioctlStatus)
			return
		case "stop":
			if err := stopDriver(); err != nil {
				fmt.Fprintf(os.Stderr, "stop failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("stopped")
			return
		case "pause":
			ioctl = ioctlPause
		case "resume":
			ioctl = ioctlResume
		case "status":
			ioctl = ioctlStatus
		default:
			fmt.Fprintf(os.Stderr, "usage: ck-status [status|pause|resume|start <sys>|stop]\n")
			os.Exit(2)
		}
	}
	queryDriver(ioctl)
}
