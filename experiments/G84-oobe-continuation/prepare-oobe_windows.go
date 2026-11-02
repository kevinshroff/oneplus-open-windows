// Exact-device offline setup queue recovery. No firmware/GPT/format operations.
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
	if runtime.GOARCH != "arm64" || !strings.EqualFold(os.Getenv("SystemRoot"), `X:\Windows`) {
		panic("ARM64 RAM PE required")
	}
	must(exec.Command(`X:\Windows\System32\reg.exe`, "query", `HKLM\SYSTEM\CurrentControlSet\Control\MiniNT`).Run())
	b := make([]uint16, 32768)
	n, _, e := kernel.NewProc("QueryDosDeviceW").Call(uintptr(unsafe.Pointer(ptr("X:"))), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	if n == 0 || n > uintptr(len(b)) || !strings.HasPrefix(strings.ToLower(syscall.UTF16ToString(b[:n])), `\device\ramdisk{`) {
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

func reg(args ...string) {
	b, e := exec.Command(`X:\Windows\System32\reg.exe`, args...).CombinedOutput()
	fmt.Printf("REG %s\n%s", strings.Join(args, " "), b)
	must(e)
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

func checkHash(path, want string) {
	sha, _, e := digest(path)
	must(e)
	if sha != want {
		panic("pinned source identity: " + path)
	}
}
func copyNew(src, dst, want string) {
	checkHash(src, want)
	in, e := os.Open(src)
	must(e)
	defer in.Close()
	out, e := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(e)
	_, e = io.Copy(out, in)
	must(e)
	must(out.Sync())
	must(out.Close())
	checkHash(dst, want)
}

const original = `C:\Windows\System32\config\SYSTEM`
const originalSHA = "2958433ebad46e32d43f21173fd1367c5976d8be610352bb283f6f53d3661eec"
const wrapper = `cmd.exe /d /c C:\OpenG81\run-setup-G83.cmd`

func edit(path, key string) {
	reg("load", `HKLM\`+key, path)
	defer reg("unload", `HKLM\`+key)
	expectDWORD(key, "Select", "Current", 1)
	expectDWORD(key, `Setup\Status\SysprepStatus`, "GeneralizationState", 7)
	expectDWORD(key, `Setup\Status\ChildCompletion`, "setup.exe", 3)
	expectDWORD(key, "Setup", "SetupPhase", 4)
	expectDWORD(key, "Setup", "SetupType", 2)
	expectDWORD(key, "Setup", "SystemSetupInProgress", 0)
	expectDWORD(key, "Setup", "OOBEInProgress", 1)
	expectString(key, "Setup", "CmdLine", `oobe\windeploy.exe`)
	absent(key, "Setup", "CreateNewQueueOnFirstBoot")
	reg("add", `HKLM\`+key+`\Setup`, "/v", "CmdLine", "/t", "REG_SZ", "/d", wrapper, "/f")
	expectString(key, "Setup", "CmdLine", wrapper)
	expectDWORD(key, `Setup\Status\SysprepStatus`, "GeneralizationState", 7)
	expectDWORD(key, `Setup\Status\ChildCompletion`, "setup.exe", 3)
	expectDWORD(key, "Setup", "SystemSetupInProgress", 0)
}
func main() {
	guard()
	if len(os.Args) != 2 {
		panic("fixed mode required")
	}
	checkHash(original, originalSHA)
	checkHash(`C:\OpenG81\open-control-arm64-G82.exe`, "bdcc52b51696f3427efcf7e3a160e9560b42d813a5fb3d546a55c2997281f057")
	checkHash(`C:\OpenG81\run-setup-G83.cmd`, "cf8916e54f5a6762cd6f0d7fa21260133b5c5dfc95c694a7f78e635bc905a3b2")
	checkHash(`C:\OpenG81\agent.json`, "50aade04c11f3138dabf69553a8b7b4f31d2265c35a5664220614c696ffb6bf4")
	path := `X:\OpenG17\payloads\G84-SYSTEM-trial`
	switch os.Args[1] {
	case "trial":
		copyNew(original, path, originalSHA)
		edit(path, "G84Trial")
	case "apply":
		copyNew(original, `C:\OpenG81\before-G84-SYSTEM`, originalSHA)
		path = original
		edit(path, "G84Actual")
	default:
		panic("unknown mode")
	}
	sha, n, e := digest(path)
	must(e)
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"path": path, "sha256": sha, "bytes": n, "changed_value": "Setup/CmdLine only", "completion_state_writes": 0, "raw_firmware_GPT_format_operations": 0}))
}
