// Exact-device startup wrapper repair. Never loads installed hives or changes setup state.
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
const target = `C:\OpenG17\run-agent.cmd`
const saved = root + `before-G87-startup`
const oldSHA = "a2a5fd3e0a56fa9d6b5c3ef47b6fa0dd87912172cf919f0e8449bde71e678767"
const newSHA = "f0672b7641fbe490eb79a441b372f1b14d1524cbec0337cc03f31fd940a16f86"
const taskSHA = "fec33f77c947bb2f4b36190f5ddbe513951e72c27b2f403d53801d2294fc927c"
const workerSHA = "373ae0aabc835c23bbd827ce6ca28d210024baba45d9c77cf71fde96a31db0c6"
const configSHA = "50aade04c11f3138dabf69553a8b7b4f31d2265c35a5664220614c696ffb6bf4"

func writeExisting(path string, data []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY, 0)
	if e != nil { return e }
	defer f.Close()
	n, e := f.WriteAt(data, 0)
	if e != nil { return e }
	if n != len(data) { return io.ErrShortWrite }
	if e = f.Truncate(int64(len(data))); e != nil { return e }
	return f.Sync()
}

func validateFreshState(mode string) {
	// Every pin comes from the new, independently retained post-desktop capture.
	// Native load/query/unload touches only a new copy on verified RAM X:.
	pins := map[string]string{"C:\\Windows\\System32\\config\\SYSTEM":"7cfadc49fb20185ad71b522b5ccff1ba401969501f7c9c75fcd1fbebff8ec2d7", "C:\\Windows\\System32\\config\\SYSTEM.LOG1":"227230fb5d2a0361aca3868cfddd9f2fab9323d8de17c4b8d7c1abc8c896a239", "C:\\Windows\\System32\\config\\SYSTEM.LOG2":"8ec5c38766a472a958d88d2efaad2b53cf461e40c96422d826ac18ec6c0d3dff", "C:\\Windows\\System32\\config\\SOFTWARE":"45b6cf1954674ec61ded2a98c52b70b35a31b96b54afe886a93f0e187194a56a", "C:\\Windows\\System32\\config\\SOFTWARE.LOG1":"24569a38bae369dcd573e0e9ba933767e7867e000fab7da419c1dc5fee5e6e34", "C:\\Windows\\System32\\config\\SOFTWARE.LOG2":"146d761f0252b00189e4323803d4d2f7200d937bacfb891a78fae31a48c9083f"}
	for path, sha := range pins { checkHash(path, sha) }
	const replaySHA = "d14dda88e8ee82cbd21a40bfa0f49177358d16031a5f9ab13c5c57ade3d004f6"
	path := ram + `G87-SYSTEM-startup-check-` + mode
	for _, suffix := range []string{"", ".LOG1", ".LOG2"} {
		if _, e := os.Stat(path + suffix); !os.IsNotExist(e) { panic("preserve existing RAM hive family") }
	}
	copyNew(ram + `G87-post-desktop-replay\SYSTEM`, path, replaySHA)
	defer func() { for _, suffix := range []string{"", ".LOG1", ".LOG2"} { os.Remove(path + suffix) } }()
	const key = "G87StartupRAM"
	reg("load", `HKLM\` + key, path)
	defer reg("unload", `HKLM\` + key)
	expectDWORD(key, "Setup", "SystemSetupInProgress", 0)
	expectDWORD(key, "Setup", "OOBEInProgress", 0)
	expectDWORD(key, "Setup", "SetupType", 0)
	expectDWORD(key, "Setup", "SetupPhase", 0)
	expectDWORD(key, "Setup\\Status\\SysprepStatus", "GeneralizationState", 7)
	expectDWORD(key, "Setup\\Status\\ChildCompletion", "setup.exe", 3)
	expectDWORD(key, "Setup\\Status\\ChildCompletion", "oobeldr.exe", 3)
	expectDWORD(key, "Setup\\Status\\ChildCompletion", "SetupFinalTasks", 3)
	expectDWORD(key, "Setup\\Status\\UnattendPasses", "specialize", 9)
	expectDWORD(key, "Setup\\Status\\UnattendPasses", "oobeSystem", 9)
	expectString(key, "Setup", "CmdLine", "")
}

func main() {
	guard()
	if len(os.Args) != 2 { panic("fixed verify/apply/undo mode required") }
	mode := os.Args[1]
	if mode != "verify" && mode != "apply" && mode != "undo" { panic("unknown mode") }
	checkHash(`C:\Windows\System32\Tasks\OpenControl`, taskSHA)
	checkHash(root + `open-control-arm64-G85.exe`, workerSHA)
	checkHash(root + `agent.json`, configSHA)
	if mode == "undo" {
		checkHash(target, newSHA)
		checkHash(saved + `\run-agent.cmd`, oldSHA)
		data, e := os.ReadFile(saved + `\run-agent.cmd`); must(e)
		must(writeExisting(target, data))
		checkHash(target, oldSHA)
	} else {
		checkHash(target, oldSHA)
		checkHash(ram + `G87-run-agent.cmd`, newSHA)
		validateFreshState(mode)
		if mode == "apply" {
			must(os.Mkdir(saved, 0700))
			copyNew(target, saved + `\run-agent.cmd`, oldSHA)
			copyNew(`C:\Windows\System32\Tasks\OpenControl`, saved + `\OpenControl.xml`, taskSHA)
			data, e := os.ReadFile(ram + `G87-run-agent.cmd`); must(e)
			if e = writeExisting(target, data); e != nil {
				old, e2 := os.ReadFile(saved + `\run-agent.cmd`); must(e2)
				must(writeExisting(target, old))
				checkHash(target, oldSHA)
				panic(e)
			}
			checkHash(target, newSHA)
		}
	}
	sha, n, e := digest(target); must(e)
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{
		"mode": mode, "target": target, "sha256": sha, "bytes": n,
		"installed_registry_writes": 0, "setup_or_ImageState_writes": 0,
		"task_definition_changes": 0, "worker_binary_changes": 0,
		"firmware_GPT_format_operations": 0,
	}))
}
