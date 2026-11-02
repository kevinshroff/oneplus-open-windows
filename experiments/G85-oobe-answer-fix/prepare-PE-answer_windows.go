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

const ram = `X:\OpenG17\payloads\`
const root = `C:\OpenG81\`
const correctedSHA = "5d4dfc787419d6e031ccd4307655ffe3d8c40652c683f3afbb3ffec721256794"
const answerSHA = "51568cb14dc9df1e23f4a3049d04d3800867674237c3a4e3eee049a352039503"
const workerSHA = "373ae0aabc835c23bbd827ce6ca28d210024baba45d9c77cf71fde96a31db0c6"
const wrapperSHA = "5b0cfb01da2b468ca6d0c61019c616a091bb27db002b3523389080e09afbb8f4"

func edit(path, key string) {
	reg("load", `HKLM\`+key, path)
	defer reg("unload", `HKLM\`+key)
	expectDWORD(key, "Select", "Current", 1)
	expectDWORD(key, `Setup\Status\SysprepStatus`, "GeneralizationState", 7)
	expectDWORD(key, `Setup\Status\ChildCompletion`, "setup.exe", 3)
	expectDWORD(key, "Setup", "SystemSetupInProgress", 0)
	expectDWORD(key, "Setup", "OOBEInProgress", 1)
	expectString(key, "Setup", "CmdLine", `oobe\windeploy.exe`)
	reg("add", `HKLM\`+key+`\Setup`, "/v", "CmdLine", "/t", "REG_SZ", "/d", `cmd.exe /d /c C:\OpenG81\run-setup-G85.cmd`, "/f")
	expectDWORD(key, `Setup\Status\SysprepStatus`, "GeneralizationState", 7)
	expectDWORD(key, `Setup\Status\ChildCompletion`, "setup.exe", 3)
	expectDWORD(key, "Setup", "SystemSetupInProgress", 0)
}
func writeExact(path string, data []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	n, e := f.WriteAt(data, 0)
	if e != nil {
		return e
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	if e = f.Truncate(int64(len(data))); e != nil {
		return e
	}
	return f.Sync()
}
func main() {
	guard()
	if len(os.Args) != 2 {
		panic("fixed mode required")
	}
	pins := map[string]string{"C:\\Windows\\System32\\config\\SYSTEM": "a0bc45097a8cd18fd5a2617c7202ae7924161cec436c144aa3fd74c6f6887e5d", "C:\\Windows\\System32\\config\\SYSTEM.LOG1": "039c0b2e9084c2edcff66601ff5188324968c66068df78d2b6880defe1d985e1", "C:\\Windows\\System32\\config\\SYSTEM.LOG2": "ac79927ab594fb382cc059479e2b19365faa93b17ce1d6b99dfb58fbff867720"}
	for p, sha := range pins {
		checkHash(p, sha)
	}
	checkHash(`C:\Windows\Panther\unattend.xml`, answerSHA)
	checkHash(ram+`G85-corrected-unattend.xml`, correctedSHA)
	checkHash(ram+`G85-run-setup.cmd`, wrapperSHA)
	checkHash(ram+`G85-fullOS-agent.exe`, workerSHA)
	checkHash(root+`agent.json`, "50aade04c11f3138dabf69553a8b7b4f31d2265c35a5664220614c696ffb6bf4")
	path := ram + `G85-SYSTEM-trial`
	switch os.Args[1] {
	case "trial":
		base := ram + `G85-after-force-replay\SYSTEM`
		sha, _, e := digest(base)
		must(e)
		copyNew(base, path, sha)
		edit(path, "G85Trial")
	case "apply":
		saved := root + `before-G85-offline`
		must(os.Mkdir(saved, 0700))
		for _, n := range []string{"SYSTEM", "SYSTEM.LOG1", "SYSTEM.LOG2"} {
			p := `C:\Windows\System32\config\` + n
			copyNew(p, saved+`\`+n, pins[p])
		}
		copyNew(`C:\Windows\Panther\unattend.xml`, saved+`\unattend.xml`, answerSHA)
		copyNew(ram+`G85-fullOS-agent.exe`, root+`open-control-arm64-G85.exe`, workerSHA)
		copyNew(ram+`G85-run-setup.cmd`, root+`run-setup-G85.cmd`, wrapperSHA)
		fixed, e := os.ReadFile(ram + `G85-corrected-unattend.xml`)
		must(e)
		must(writeExact(`C:\Windows\Panther\unattend.xml`, fixed))
		checkHash(`C:\Windows\Panther\unattend.xml`, correctedSHA)
		path = `C:\Windows\System32\config\SYSTEM`
		edit(path, "G85Actual")
	default:
		panic("unknown mode")
	}
	sha, n, e := digest(path)
	must(e)
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": os.Args[1], "path": path, "sha256": sha, "bytes": n, "explicit_registry_changes": "CmdLine only", "completion_or_ImageState_changes": 0, "TPM_GPT_firmware_or_format_operations": 0}))
}
