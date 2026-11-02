// Exact-device offline setup queue recovery. No firmware/GPT/format operations.
package main

import (
	"archive/zip"
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

const ram = `X:\OpenG17\payloads\`
const root = `C:\OpenG81\`
const archiveSHA = "427f38f4f501a65cc15ec15ca7cfd8357c654d8e24972b1fba2cad4a620eaba7"

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
	absent(key, "Setup", "CreateNewQueueOnFirstBoot")
	expectDWORD(key, `ControlSet001\Services\Tcpip\Parameters\Interfaces\{50d561fb-94dc-4295-87cd-e78f0135d5a6}`, "EnableDHCP", 0)
	reg("add", `HKLM\`+key+`\Setup\Status\ChildCompletion`, "/v", "setup.exe", "/t", "REG_DWORD", "/d", "0", "/f")
	reg("add", `HKLM\`+key+`\Setup`, "/v", "CmdLine", "/t", "REG_SZ", "/d", `cmd.exe /d /c C:\OpenG81\run-setup-G82.cmd`, "/f")
	reg("add", `HKLM\`+key+`\Setup`, "/v", "CreateNewQueueOnFirstBoot", "/t", "REG_DWORD", "/d", "1", "/f")
	expectDWORD(key, `Setup\Status\ChildCompletion`, "setup.exe", 0)
	expectDWORD(key, "Setup", "CreateNewQueueOnFirstBoot", 1)
	expectDWORD(key, `Setup\Status\SysprepStatus`, "GeneralizationState", 4)
}
func result(phase, path string) {
	sha, n, e := digest(path)
	must(e)
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": phase, "path": path, "sha256": sha, "bytes": n, "firmware_GPT_or_format_operations": 0}))
}
func move(src, dst string) {
	r, _, e := kernel.NewProc("MoveFileExW").Call(uintptr(unsafe.Pointer(ptr(src))), uintptr(unsafe.Pointer(ptr(dst))), 0)
	if r == 0 {
		panic(e)
	}
}
func main() {
	guard()
	if len(os.Args) != 2 {
		panic("fixed mode required")
	}
	switch os.Args[1] {
	case "replay":
		zipPath := ram + `G83-after-restart-setup.zip`
		checkHash(zipPath, archiveSHA)
		dir := ram + `G83-baseline`
		must(os.Mkdir(dir, 0700))
		z, e := zip.OpenReader(zipPath)
		must(e)
		count := 0
		for _, it := range z.File {
			prefix := "C/Windows/System32/config/"
			if !strings.HasPrefix(it.Name, prefix) {
				continue
			}
			name := strings.TrimPrefix(it.Name, prefix)
			if !(name == "SYSTEM" || name == "SYSTEM.LOG1" || name == "SYSTEM.LOG2") || it.UncompressedSize64 > 128<<20 {
				panic("fixed hive entries")
			}
			in, e := it.Open()
			must(e)
			out, e := os.OpenFile(dir+`\`+name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			must(e)
			n, e := io.Copy(out, in)
			must(e)
			must(in.Close())
			must(out.Sync())
			must(out.Close())
			if uint64(n) != it.UncompressedSize64 {
				panic("extract length")
			}
			count++
		}
		must(z.Close())
		if count != 3 {
			panic("three hive files")
		}
		reg("load", `HKLM\G83Baseline`, dir+`\SYSTEM`)
		reg("query", `HKLM\G83Baseline\Setup\Status\ChildCompletion`)
		reg("unload", `HKLM\G83Baseline`)
		result("fresh_RAM_log_replay_no_OS_edits", dir+`\SYSTEM`)
	case "trial":
		src := ram + `G83-baseline\SYSTEM`
		sha, _, e := digest(src)
		must(e)
		dst := ram + `G83-SYSTEM-trial`
		copyNew(src, dst, sha)
		edit(dst, "G83TrialSystem")
		result("three_value_RAM_trial_no_OS_edits", dst)
	case "apply":
		for _, p := range []struct{ path, sha string }{{path: "C:\\Windows\\System32\\config\\SYSTEM", sha: "735902a3cde20a4b7e00bd7daa9329ababb34dbbd2945c11a0a47b7aace0f8b3"}, {path: "C:\\Windows\\System32\\config\\SYSTEM.LOG1", sha: "23a8dfa01b93cf8eec76079ec307d1308412a393faed9dde83d6cb7294bc48b1"}, {path: "C:\\Windows\\System32\\config\\SYSTEM.LOG2", sha: "9e45b61d835daa098019546359ac109738391d91f698cf521b1189e7963dcd8f"}, {path: "C:\\Windows\\Panther\\setupinfo", sha: "7e796d19b209d5df98178e792a5883c58660d24028f323d5941252725e0f6485"}, {path: "C:\\Windows\\Panther\\setupinfo.4d53424c4b425244.spl", sha: "c31a14efe4f5828aa37ac6bab0e778a780f98b0ef057a7190c2765fae7db375f"}} {
			checkHash(p.path, p.sha)
		}
		checkHash(root+`open-control-arm64-G82.exe`, "bdcc52b51696f3427efcf7e3a160e9560b42d813a5fb3d546a55c2997281f057")
		checkHash(root+`run-setup-G82.cmd`, "6059544f7dfa6666652511d4adc702802f54d16a2b12108bb0d8ba02612ab6bf")
		checkHash(root+`agent.json`, "50aade04c11f3138dabf69553a8b7b4f31d2265c35a5664220614c696ffb6bf4")
		saved := root + `queue-before-G83`
		if _, e := os.Lstat(saved); !os.IsNotExist(e) {
			panic("preserve prior queue capture")
		}
		copyNew(ram+`G83-after-restart-setup.zip`, root+`before-G83-queue.zip`, archiveSHA)
		must(os.Mkdir(saved, 0700))
		move(`C:\Windows\Panther\setupinfo`, saved+`\setupinfo`)
		// Roll back the first rename if the spill file cannot be preserved.
		func() {
			defer func() {
				if v := recover(); v != nil {
					move(saved+`\setupinfo`, `C:\Windows\Panther\setupinfo`)
					panic(v)
				}
			}()
			move(`C:\Windows\Panther\setupinfo.4d53424c4b425244.spl`, saved+`\setupinfo.4d53424c4b425244.spl`)
		}()
		checkHash(saved+`\setupinfo`, "7e796d19b209d5df98178e792a5883c58660d24028f323d5941252725e0f6485")
		checkHash(saved+`\setupinfo.4d53424c4b425244.spl`, "c31a14efe4f5828aa37ac6bab0e778a780f98b0ef057a7190c2765fae7db375f")
		edit(`C:\Windows\System32\config\SYSTEM`, "G83ActualSystem")
		result("three_value_queue_retry_and_two_preserved_blackboard_files", `C:\Windows\System32\config\SYSTEM`)
	default:
		panic("unknown mode")
	}
}
