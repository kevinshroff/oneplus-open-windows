// Live G82 forensic capture, before changing queue files or restarting setup.
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
	"path/filepath"
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

func main() {
	guard()
	if len(os.Args) != 1 {
		panic("fixed capture only")
	}
	root := `C:\OpenG81\payloads\G85-before-answer-fix`
	must(os.Mkdir(root, 0700))
	for _, name := range []string{"SYSTEM", "SOFTWARE"} {
		out, e := exec.Command(`C:\Windows\System32\reg.exe`, "save", `HKLM\`+name, root+`\`+name).CombinedOutput()
		fmt.Printf("REG SAVE %s: %s", name, out)
		must(e)
	}
	output := root + `.zip`
	out, e := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(e)
	z := zip.NewWriter(out)
	records := []map[string]any{}
	var total int64
	add := func(path, entry string) error {
		sha, n, e := digest(path)
		if e != nil {
			return e
		}
		total += n
		if n > 128<<20 || total > 192<<20 {
			return fmt.Errorf("capture size guard")
		}
		in, e := os.Open(path)
		if e != nil {
			return e
		}
		defer in.Close()
		w, e := z.Create(entry)
		if e != nil {
			return e
		}
		h := sha256.New()
		n2, e := io.Copy(io.MultiWriter(w, h), in)
		if e != nil {
			return e
		}
		after, _, e := digest(path)
		if e != nil {
			return e
		}
		records = append(records, map[string]any{"entry": entry, "bytes": n, "sha256": sha, "three_matching_reads": n2 == n && sha == after && sha == hex.EncodeToString(h.Sum(nil))})
		return nil
	}
	for _, name := range []string{"SYSTEM", "SOFTWARE"} {
		must(add(root+`\`+name, name))
	}
	base := `C:\Windows\Panther`
	must(filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("unexpected reparse link")
		}
		rel, e := filepath.Rel(base, path)
		if e != nil {
			return e
		}
		return add(path, "Panther/"+strings.ReplaceAll(rel, `\`, `/`))
	}))
	m, e := z.Create("manifest.json")
	must(e)
	must(json.NewEncoder(m).Encode(map[string]any{"files": records, "installed_registry_edits": 0, "source_access": "reg save snapshots plus read-only Panther logical files"}))
	must(z.Close())
	must(out.Sync())
	must(out.Close())
	sha, n, e := digest(output)
	must(e)
	if n > 32<<20 {
		panic("transfer size guard")
	}
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"file": output, "bytes": n, "sha256": sha, "files": len(records), "installed_registry_edits": 0}))
}
