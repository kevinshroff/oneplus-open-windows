// Replay registry logs only into fresh, verified RAM copies; never load C: hives.
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
	n, e := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, e
}
func reg(args ...string) {
	b, e := exec.Command(`X:\Windows\System32\reg.exe`, args...).CombinedOutput()
	fmt.Printf("REG %s\n%s", strings.Join(args, " "), b)
	must(e)
}
func replay(root, name string) {
	key := `HKLM\G81RAM` + name
	reg("load", key, root+`\`+name)
	defer reg("unload", key)
	if name == "SYSTEM" {
		for _, sub := range []string{`\Setup`, `\Setup\Status\SysprepStatus`, `\Setup\Status\ChildCompletion`} {
			reg("query", key+sub)
		}
	} else {
		reg("query", key+`\Microsoft\Windows\CurrentVersion\Setup\State`)
	}
}
func main() {
	guard()
	if len(os.Args) != 1 {
		panic("no arbitrary inputs")
	}
	root := `X:\OpenG17\payloads\G81-after-dialog-replay`
	must(os.Mkdir(root, 0700))
	count := 0
	archives := map[string]string{"setup": "cf82cd31299215f682316f329285422a390c1e506e99bf8ef543ec62170b06dc", "software": "00f1502a60cbfd2253e1dd025ef68b4cebaa7bc58994a1c1e7ecbfd7139f8815"}
	for group, expected := range archives {
		src := `X:\OpenG17\payloads\G81-after-setup-` + group + `.zip`
		sha, _, e := digest(src)
		must(e)
		if sha != expected {
			panic("pinned capture archive identity")
		}
		z, e := zip.OpenReader(src)
		must(e)
		for _, item := range z.File {
			prefix := "C/Windows/System32/config/"
			if !strings.HasPrefix(item.Name, prefix) {
				continue
			}
			name := strings.TrimPrefix(item.Name, prefix)
			if !(name == "SYSTEM" || name == "SYSTEM.LOG1" || name == "SYSTEM.LOG2" || name == "SOFTWARE" || name == "SOFTWARE.LOG1" || name == "SOFTWARE.LOG2") || item.UncompressedSize64 > 128<<20 {
				panic("hive allowlist")
			}
			in, e := item.Open()
			must(e)
			out, e := os.OpenFile(root+`\`+name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			must(e)
			n, e := io.Copy(out, in)
			must(e)
			must(in.Close())
			must(out.Sync())
			must(out.Close())
			if uint64(n) != item.UncompressedSize64 {
				panic("extract length")
			}
			count++
		}
		must(z.Close())
	}
	if count != 6 {
		panic("six files required")
	}
	replay(root, "SYSTEM")
	replay(root, "SOFTWARE")
	output := root + `.zip`
	f, e := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(e)
	z := zip.NewWriter(f)
	files := []map[string]any{}
	for _, name := range []string{"SYSTEM", "SOFTWARE"} {
		p := root + `\` + name
		sha, n, e := digest(p)
		must(e)
		in, e := os.Open(p)
		must(e)
		out, e := z.Create(name)
		must(e)
		copied, e := io.Copy(out, in)
		must(e)
		must(in.Close())
		if n != copied {
			panic("copy length")
		}
		files = append(files, map[string]any{"entry": name, "bytes": n, "sha256": sha})
	}
	out, e := z.Create("manifest.json")
	must(e)
	must(json.NewEncoder(out).Encode(map[string]any{"files": files, "installed_hive_writes": 0, "registry_replay": "fresh RAM copies only"}))
	must(z.Close())
	must(f.Sync())
	must(f.Close())
	sha, n, e := digest(output)
	must(e)
	if n > 32<<20 {
		panic("transfer guard")
	}
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"file": output, "bytes": n, "sha256": sha, "installed_hive_writes": 0}))
}
