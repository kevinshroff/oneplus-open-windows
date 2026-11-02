// G82: pinned files and five typed values; all device/hive guards precede edits.
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

type item struct {
	Source string `json:"source"`
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA    string `json:"sha256"`
}

var fixed = []item{{Source: "G82-fullOS-agent.exe", Name: "open-control-arm64-G82.exe", Bytes: 9233920, SHA: "bdcc52b51696f3427efcf7e3a160e9560b42d813a5fb3d546a55c2997281f057"}, {Source: "G82-run-setup.cmd", Name: "run-setup-G82.cmd", Bytes: 565, SHA: "6059544f7dfa6666652511d4adc702802f54d16a2b12108bb0d8ba02612ab6bf"}, {Source: "G82-before-setup.zip", Name: "before-G82-setup.zip", Bytes: 2053006, SHA: "cf82cd31299215f682316f329285422a390c1e506e99bf8ef543ec62170b06dc"}}

func checkHash(p, want string) {
	sha, _, e := digest(p)
	must(e)
	if sha != want {
		panic("pinned hash mismatch: " + p)
	}
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

const nic = `ControlSet001\Services\Tcpip\Parameters\Interfaces\{50d561fb-94dc-4295-87cd-e78f0135d5a6}`

func edit(path, key string) {
	reg("load", `HKLM\`+key, path)
	defer reg("unload", `HKLM\`+key)
	expectDWORD(key, "Select", "Current", 1)
	expectDWORD(key, `Setup\Status\SysprepStatus`, "GeneralizationState", 4)
	expectDWORD(key, `Setup\Status\ChildCompletion`, "setup.exe", 1)
	expectDWORD(key, "Setup", "SetupPhase", 4)
	expectDWORD(key, "Setup", "SetupType", 2)
	expectDWORD(key, "Setup", "SystemSetupInProgress", 1)
	expectDWORD(key, "Setup", "OOBEInProgress", 1)
	expectString(key, "Setup", "CmdLine", `oobe\windeploy.exe`)
	expectString(key, `ControlSet001\Enum\ROOT\KDNIC\0000`, "Driver", `{4d36e972-e325-11ce-bfc1-08002be10318}\0000`)
	expectString(key, `ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000`, "MatchingDeviceId", `root\kdnic`)
	expectString(key, `ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000`, "NetCfgInstanceId", `{50D561FB-94DC-4295-87CD-E78F0135D5A6}`)
	expectDWORD(key, nic, "EnableDHCP", 1)
	absent(key, nic, "IPAddress")
	absent(key, nic, "SubnetMask")
	for _, v := range []struct{ path, name, kind, data string }{
		{`Setup\Status\ChildCompletion`, "setup.exe", "REG_DWORD", "0"},
		{"Setup", "CmdLine", "REG_SZ", `cmd.exe /d /c C:\OpenG81\run-setup-G82.cmd`},
		{nic, "EnableDHCP", "REG_DWORD", "0"},
		{nic, "IPAddress", "REG_MULTI_SZ", "192.0.2.10"},
		{nic, "SubnetMask", "REG_MULTI_SZ", "255.255.0.0"},
	} {
		reg("add", `HKLM\`+key+`\`+v.path, "/v", v.name, "/t", v.kind, "/d", v.data, "/f")
	}
	expectDWORD(key, `Setup\Status\ChildCompletion`, "setup.exe", 0)
	expectDWORD(key, `Setup\Status\SysprepStatus`, "GeneralizationState", 4)
	expectDWORD(key, nic, "EnableDHCP", 0)
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
func main() {
	guard()
	if len(os.Args) != 2 {
		panic("fixed mode required")
	}
	mode := os.Args[1]
	ram := `X:\OpenG17\payloads\`
	root := `C:\OpenG81\`
	switch mode {
	case "trial":
		base := ram + `G82-SYSTEM-base`
		checkHash(base, "f64779a63964193942d5cdd7639fe232d911b70c24e084c90d985316c56f3a00")
		dst := ram + `G82-SYSTEM-trial`
		copyNew(base, dst, "f64779a63964193942d5cdd7639fe232d911b70c24e084c90d985316c56f3a00")
		edit(dst, "G82TrialSystem")
		sha, n, e := digest(dst)
		must(e)
		must(json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": "five_value_RAM_trial_complete", "path": dst, "sha256": sha, "bytes": n, "installed_OS_writes": 0}))
	case "stage":
		checkHash(root+`agent.json`, "50aade04c11f3138dabf69553a8b7b4f31d2265c35a5664220614c696ffb6bf4")
		for _, x := range fixed {
			checkHash(ram+x.Source, x.SHA)
			if _, e := os.Lstat(root + x.Name); !os.IsNotExist(e) {
				panic("preserve existing staged file")
			}
		}
		for _, x := range fixed {
			copyNew(ram+x.Source, root+x.Name, x.SHA)
		}
		fmt.Println("G82_THREE_NEW_FILES_STAGED_NO_HIVE_EDITS")
	case "apply":
		checkHash(root+`agent.json`, "50aade04c11f3138dabf69553a8b7b4f31d2265c35a5664220614c696ffb6bf4")
		for _, x := range fixed {
			checkHash(root+x.Name, x.SHA)
		}
		checkHash(`C:\Windows\System32\config\SYSTEM`, "ddacc82523ef6fe23d6a627ab0e187b0a05713f003f35c00f8ad6489a469c5fe")
		checkHash(`C:\Windows\System32\config\SYSTEM.LOG1`, "a708c2b28364ba5a85e391f2712de4799fe43ac4024c394f791e61bdc52e7ba9")
		checkHash(`C:\Windows\System32\config\SYSTEM.LOG2`, "41ae17aa1f17366a1f42576adb856d33797eefe37dd7f4101e8fd20cdee06355")
		edit(`C:\Windows\System32\config\SYSTEM`, "G82ActualSystem")
		sha, n, e := digest(`C:\Windows\System32\config\SYSTEM`)
		must(e)
		must(json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": "five_value_installed_SYSTEM_edit_complete", "sha256": sha, "bytes": n, "raw_partition_writes": 0, "firmware_or_GPT_changes": 0}))
	default:
		panic("unknown mode")
	}
}
