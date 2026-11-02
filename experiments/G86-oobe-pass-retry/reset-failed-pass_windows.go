// Live G82 forensic capture, before changing queue files or restarting setup.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func ptr(s string) *uint16 { p, e := syscall.UTF16PtrFromString(s); must(e); return p }
func guid(b []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint16(b[4:]), binary.LittleEndian.Uint16(b[6:]), b[8:10], b[10:16])
}
func guard() {
	if runtime.GOARCH != "arm64" || !strings.EqualFold(os.Getenv("SystemRoot"), `C:\Windows`) {
		panic("installed ARM64 Windows required")
	}
	var mini syscall.Handle
	e0 := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, ptr(`SYSTEM\CurrentControlSet\Control\MiniNT`), 0, syscall.KEY_READ, &mini)
	if e0 == nil {
		syscall.RegCloseKey(mini)
		panic("refuse PE")
	}
	if e0 != syscall.ERROR_FILE_NOT_FOUND && e0 != syscall.ERROR_PATH_NOT_FOUND {
		panic(e0)
	}
	b := make([]uint16, 32768)
	n, _, e := kernel.NewProc("QueryDosDeviceW").Call(uintptr(unsafe.Pointer(ptr("C:"))), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	if n == 0 || n > uintptr(len(b)) || !strings.HasPrefix(strings.ToLower(syscall.UTF16ToString(b[:n])), `\device\harddiskvolume`) {
		panic(fmt.Sprint("RAM identity: ", e))
	}
	h, err := syscall.CreateFile(ptr(`\\.\C:`), syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0)
	must(err)
	defer syscall.CloseHandle(h)
	raw := make([]byte, 4096)
	var got uint32
	must(syscall.DeviceIoControl(h, 0x70048, nil, 0, &raw[0], uint32(len(raw)), &got, nil))
	if got < 144 || binary.LittleEndian.Uint32(raw) != 1 || binary.LittleEndian.Uint64(raw[8:]) != 0x2208000 || binary.LittleEndian.Uint64(raw[16:]) != 0x440000000 || guid(raw[32:48]) != "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7" || guid(raw[48:64]) != "1c68511e-28af-a8c9-dd6f-e3303d568c04" {
		panic("C: target identity")
	}
}

func digest(p string) (string, int64, error) {
	f, e := os.Open(p)
	if e != nil {
		return "", 0, e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, (128<<20)+1))
	if n > 128<<20 {
		return "", n, fmt.Errorf("file size guard")
	}
	return hex.EncodeToString(h.Sum(nil)), n, e
}

func value(root, path, name string) (uint32, []byte, error) {
	var k syscall.Handle
	e := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, ptr(root+`\`+path), 0, syscall.KEY_READ, &k)
	if e != nil {
		return 0, nil, e
	}
	defer syscall.RegCloseKey(k)
	var kind, size uint32
	e = syscall.RegQueryValueEx(k, ptr(name), nil, &kind, nil, &size)
	if e != nil {
		return kind, nil, e
	}
	if size > 4096 {
		panic("registry size guard")
	}
	b := make([]byte, size)
	if size == 0 {
		return kind, b, nil
	}
	e = syscall.RegQueryValueEx(k, ptr(name), nil, &kind, &b[0], &size)
	return kind, b[:size], e
}
func expectDWORD(root, path, name string, want uint32) {
	kind, b, e := value(root, path, name)
	must(e)
	if kind != 4 || len(b) != 4 || binary.LittleEndian.Uint32(b) != want {
		panic("registry DWORD precondition: " + path + `\` + name)
	}
}
func expectString(root, path, name, want string) {
	kind, b, e := value(root, path, name)
	must(e)
	if kind != 1 || len(b)%2 != 0 {
		panic("registry string type")
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	if !strings.EqualFold(syscall.UTF16ToString(u), want) {
		panic("registry string precondition: " + path + `\` + name)
	}
}
func absent(root, path, name string) {
	_, _, e := value(root, path, name)
	if e != syscall.ERROR_FILE_NOT_FOUND {
		panic("registry absence precondition: " + path + `\` + name)
	}
}

func pin(path, want string) {
	sha, _, e := digest(path)
	must(e)
	if sha != want {
		panic("pinned input identity")
	}
}
func main() {
	guard()
	if len(os.Args) != 1 {
		panic("no arbitrary input")
	}
	pin(`C:\OpenG81\payloads\G86-before-SMI-retry.zip`, "adc6820e44edbefa770ea7e2435282e38c3d25b8d97b1b04214f2ae791ec2124")
	pin(`C:\Windows\Panther\unattend.xml`, "5d4dfc787419d6e031ccd4307655ffe3d8c40652c683f3afbb3ffec721256794")
	pin(`C:\OpenG81\open-control-arm64-G85.exe`, "373ae0aabc835c23bbd827ce6ca28d210024baba45d9c77cf71fde96a31db0c6")
	pin(`C:\OpenG81\run-setup-G85.cmd`, "5b0cfb01da2b468ca6d0c61019c616a091bb27db002b3523389080e09afbb8f4")
	expectDWORD("SYSTEM", `Setup\Status\UnattendPasses`, "oobeSystem", 1)
	expectDWORD("SYSTEM", `Setup\Status\UnattendPasses`, "specialize", 9)
	expectDWORD("SYSTEM", `Setup\Status\SysprepStatus`, "GeneralizationState", 7)
	expectDWORD("SYSTEM", `Setup\Status\ChildCompletion`, "setup.exe", 3)
	expectDWORD("SYSTEM", "Setup", "SystemSetupInProgress", 0)
	expectDWORD("SYSTEM", "Setup", "OOBEInProgress", 1)
	expectString("SYSTEM", "Setup", "CmdLine", `oobe\windeploy.exe`)
	for _, a := range [][]string{
		{"add", `HKLM\SYSTEM\Setup\Status\UnattendPasses`, "/v", "oobeSystem", "/t", "REG_DWORD", "/d", "0", "/f"},
		{"add", `HKLM\SYSTEM\Setup`, "/v", "CmdLine", "/t", "REG_SZ", "/d", `cmd.exe /d /c C:\OpenG81\run-setup-G85.cmd`, "/f"},
	} {
		out, e := exec.Command(`C:\Windows\System32\reg.exe`, a...).CombinedOutput()
		fmt.Print(string(out))
		must(e)
	}
	expectDWORD("SYSTEM", `Setup\Status\UnattendPasses`, "oobeSystem", 0)
	expectDWORD("SYSTEM", `Setup\Status\UnattendPasses`, "specialize", 9)
	expectDWORD("SYSTEM", `Setup\Status\SysprepStatus`, "GeneralizationState", 7)
	expectDWORD("SYSTEM", `Setup\Status\ChildCompletion`, "setup.exe", 3)
	expectString("SYSTEM", "Setup", "CmdLine", `cmd.exe /d /c C:\OpenG81\run-setup-G85.cmd`)
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": "native_failed_pass_retry_prepared", "oobeSystem_before": 1, "oobeSystem_after": 0, "successful_specialize_pass_preserved": 9, "successful_setup_completion_preserved": 3, "GenState_preserved": 7, "other_explicit_registry_change": "diagnostic CmdLine", "completion_or_ImageState_faked": false, "GPT_firmware_format_operations": 0}))
}
