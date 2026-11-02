// Fixed allowlist, read-only logical-file capture after the G81 full-OS trial.
// Only output is a new ZIP on the verified RAM WinPE X: volume.
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
func main() {
	guard()
	if len(os.Args) != 2 {
		panic("fixed group required")
	}
	group := os.Args[1]
	paths := []string{}
	switch group {
	case "setup":
		paths = []string{
			`C:\Windows\System32\config\SYSTEM`, `C:\Windows\System32\config\SYSTEM.LOG1`, `C:\Windows\System32\config\SYSTEM.LOG2`,
			`C:\Windows\Panther\setupact.log`, `C:\Windows\Panther\setuperr.log`,
			`C:\Windows\Panther\UnattendGC\setupact.log`, `C:\Windows\Panther\UnattendGC\setuperr.log`,
			`C:\OpenG81\setup-control.log`, `C:\OpenG81\setup-control-G85-agent.log`, `C:\OpenG81\state\agent.log`,
			`C:\Windows\bootstat.dat`, `C:\Windows\Panther\unattend.xml`, `C:\Windows\System32\winevt\Logs\System.evtx`,
			`C:\Windows\System32\Tasks\OpenControl`, `C:\OpenG17\run-agent.cmd`, `C:\OpenG17\console.log`,
			`C:\Windows\Panther\setupinfo`, `C:\Windows\Panther\setupinfo.4d53424c4b425244.spl`}
	case "software":
		paths = []string{`C:\Windows\System32\config\SOFTWARE`, `C:\Windows\System32\config\SOFTWARE.LOG1`, `C:\Windows\System32\config\SOFTWARE.LOG2`}
	case "binaries":
		paths = []string{`C:\Windows\System32\winlogon.exe`, `C:\Windows\System32\oobe\setup.exe`, `C:\Windows\System32\oobe\windeploy.exe`, `C:\Windows\System32\spbcd.dll`}
	default:
		panic("unknown capture group")
	}
	out := `X:\OpenG17\payloads\G87-post-desktop-` + group + `.zip`
	f, e := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(e)
	z := zip.NewWriter(f)
	records := []map[string]any{}
	for _, p := range paths {
		before, n, e := digest(p)
		if os.IsNotExist(e) {
			records = append(records, map[string]any{"source": p, "exists": false})
			continue
		}
		must(e)
		name := strings.ReplaceAll(strings.ReplaceAll(p, `:`, ``), `\`, `/`)
		dst, e := z.Create(name)
		must(e)
		src, e := os.Open(p)
		must(e)
		h := sha256.New()
		copied, e := io.Copy(io.MultiWriter(dst, h), src)
		must(e)
		must(src.Close())
		after, n2, e := digest(p)
		must(e)
		if n != copied || n != n2 || before != after || hex.EncodeToString(h.Sum(nil)) != before {
			panic("file changed during capture")
		}
		records = append(records, map[string]any{"source": p, "exists": true, "entry": name, "bytes": n, "sha256": before, "matching_reads": 3})
	}
	manifest := map[string]any{"group": group, "files": records, "source_access": "read-only logical Windows/WOF files", "source_writes": 0, "raw_writes": 0, "output": out}
	m, e := z.Create("manifest.json")
	must(e)
	must(json.NewEncoder(m).Encode(manifest))
	must(z.Close())
	must(f.Sync())
	must(f.Close())
	sha, n, e := digest(out)
	must(e)
	if n > 32<<20 {
		panic("transfer size guard")
	}
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"file": out, "bytes": n, "sha256": sha, "files": records, "raw_writes": 0, "source_writes": 0}))
}
