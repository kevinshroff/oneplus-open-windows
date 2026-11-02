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

const answer = `C:\Windows\Panther\unattend.xml`
const beforeSHA = "51568cb14dc9df1e23f4a3049d04d3800867674237c3a4e3eee049a352039503"
const afterSHA = "5d4dfc787419d6e031ccd4307655ffe3d8c40652c683f3afbb3ffec721256794"
const backupSHA = "8251cb05e52bcd87b930f9e26ec835298237143434fdf8faa18ff4b26f3a43be"
const corrected = `C:\OpenG81\payloads\G85-corrected-unattend.xml`
const wrapperSHA = "cf4f4ffdbd5dbd90990712c7f68565b4a5c7efab11ff912d9980260a7beb7cb5"

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
	if len(os.Args) != 2 || (os.Args[1] != "preflight" && os.Args[1] != "apply") {
		panic("fixed mode required")
	}
	checkHash(`C:\OpenG81\payloads\G85-before-answer-fix.zip`, backupSHA)
	checkHash(answer, beforeSHA)
	checkHash(corrected, afterSHA)
	checkHash(`C:\OpenG81\payloads\G85-run-setup.cmd`, wrapperSHA)
	checkHash(`C:\OpenG81\open-control-arm64-G82.exe`, "bdcc52b51696f3427efcf7e3a160e9560b42d813a5fb3d546a55c2997281f057")
	expectDWORD("SYSTEM", `Setup\Status\SysprepStatus`, "GeneralizationState", 7)
	expectDWORD("SYSTEM", `Setup\Status\ChildCompletion`, "setup.exe", 3)
	expectDWORD("SYSTEM", "Setup", "SystemSetupInProgress", 0)
	expectDWORD("SYSTEM", "Setup", "OOBEInProgress", 1)
	expectString("SYSTEM", "Setup", "CmdLine", `oobe\windeploy.exe`)
	old, e := os.ReadFile(answer)
	must(e)
	fixed, e := os.ReadFile(corrected)
	must(e)
	f, e := os.OpenFile(answer, os.O_RDWR, 0)
	must(e)
	must(f.Close())
	if os.Args[1] == "preflight" {
		must(json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": "native_read_only_preflight", "answer_write_access_verified": true, "independent_backup_verified": true, "GenState": 7, "setup_completion": 3, "installed_edits": 0}))
		return
	}
	copyNew(answer, `C:\OpenG81\before-G85-unattend.xml`, beforeSHA)
	copyNew(`C:\OpenG81\payloads\G85-run-setup.cmd`, `C:\OpenG81\run-setup-G85.cmd`, wrapperSHA)
	if e = writeExact(answer, fixed); e != nil {
		restore := writeExact(answer, old)
		panic(fmt.Sprintf("XML write failed: %v; restore: %v", e, restore))
	}
	checkHash(answer, afterSHA)
	out, e := exec.Command(`C:\Windows\System32\reg.exe`, "add", `HKLM\SYSTEM\Setup`, "/v", "CmdLine", "/t", "REG_SZ", "/d", `cmd.exe /d /c C:\OpenG81\run-setup-G85.cmd`, "/f").CombinedOutput()
	fmt.Print(string(out))
	must(e)
	expectString("SYSTEM", "Setup", "CmdLine", `cmd.exe /d /c C:\OpenG81\run-setup-G85.cmd`)
	expectDWORD("SYSTEM", `Setup\Status\SysprepStatus`, "GeneralizationState", 7)
	expectDWORD("SYSTEM", `Setup\Status\ChildCompletion`, "setup.exe", 3)
	expectDWORD("SYSTEM", "Setup", "SystemSetupInProgress", 0)
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": "answer_fix_and_diagnostic_wrapper_applied", "answer_sha256": afterSHA, "removed_XML_elements": 1, "explicit_registry_changes": "CmdLine only", "completion_or_ImageState_changes": 0, "original_answer_preserved": true, "source_write_strategy": "in-place logical file update with verified backup; preserve existing ACL"}))
}
