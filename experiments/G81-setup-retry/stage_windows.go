// First-install-only staging. Guarded RAM PE, exact OS partition, fixed files.
package main
import (
 "crypto/sha256"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "os"
 "os/exec"
 "runtime"
 "strings"
 "syscall"
 "unsafe"
)
type item struct {Source string `json:"source"`; Name string `json:"name"`; SHA string `json:"sha256"`; Bytes int `json:"bytes"`}
var kernel=syscall.NewLazyDLL("kernel32.dll")
var advapi=syscall.NewLazyDLL("advapi32.dll")
func must(e error){if e!=nil{panic(e)}}
func sha(b []byte) string {h:=sha256.Sum256(b);return hex.EncodeToString(h[:])}
func ptr(s string)*uint16 {p,e:=syscall.UTF16PtrFromString(s);must(e);return p}
func guid(b []byte) string {return fmt.Sprintf("%08x-%04x-%04x-%x-%x",binary.LittleEndian.Uint32(b),binary.LittleEndian.Uint16(b[4:]),binary.LittleEndian.Uint16(b[6:]),b[8:10],b[10:16])}
func guard(){
 if runtime.GOARCH!="arm64" || !strings.EqualFold(os.Getenv("SystemRoot"),`X:\Windows`){panic("ARM64 RAM PE required")}
 must(exec.Command(`X:\Windows\System32\reg.exe`,"query",`HKLM\SYSTEM\CurrentControlSet\Control\MiniNT`).Run())
 b:=make([]uint16,32768);n,_,e:=kernel.NewProc("QueryDosDeviceW").Call(uintptr(unsafe.Pointer(ptr("X:"))),uintptr(unsafe.Pointer(&b[0])),uintptr(len(b)))
 if n==0 || n>uintptr(len(b)) || !strings.HasPrefix(strings.ToLower(syscall.UTF16ToString(b[:n])),`\device\ramdisk{`){panic(fmt.Sprint("RAM identity: ",e))}
 h,err:=syscall.CreateFile(ptr(`\\.\C:`),syscall.GENERIC_READ,syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,nil,syscall.OPEN_EXISTING,0,0);must(err);defer syscall.CloseHandle(h)
 raw:=make([]byte,4096);var got uint32;must(syscall.DeviceIoControl(h,0x70048,nil,0,&raw[0],uint32(len(raw)),&got,nil))
 if got<144 || binary.LittleEndian.Uint32(raw)!=1 || binary.LittleEndian.Uint64(raw[8:])!=0x2208000 || binary.LittleEndian.Uint64(raw[16:])!=0x440000000 || guid(raw[32:48])!="ebd0a0a2-b9e5-4433-87c0-68b6b72699c7" || guid(raw[48:64])!="1c68511e-28af-a8c9-dd6f-e3303d568c04" {panic("C: target identity")}
}
func protect(root string) string {
 var sd uintptr
 r,_,e:=advapi.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW").Call(uintptr(unsafe.Pointer(ptr("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"))),1,uintptr(unsafe.Pointer(&sd)),0)
 if r==0{panic(e)};defer kernel.NewProc("LocalFree").Call(sd)
 r,_,e=advapi.NewProc("SetFileSecurityW").Call(uintptr(unsafe.Pointer(ptr(root))),0x80000004,sd);if r==0{panic(e)}
 b:=make([]byte,4096);var size uint32
 r,_,e=advapi.NewProc("GetFileSecurityW").Call(uintptr(unsafe.Pointer(ptr(root))),4,uintptr(unsafe.Pointer(&b[0])),uintptr(len(b)),uintptr(unsafe.Pointer(&size)));if r==0{panic(e)}
 var text uintptr;var chars uint32
 r,_,e=advapi.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW").Call(uintptr(unsafe.Pointer(&b[0])),1,4,uintptr(unsafe.Pointer(&text)),uintptr(unsafe.Pointer(&chars)));if r==0{panic(e)};defer kernel.NewProc("LocalFree").Call(text)
 if chars==0 || chars>4096{panic("SDDL length")};s:=syscall.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(text)),chars))
 i:=strings.IndexByte(s,'(');if i<0 || !strings.HasPrefix(s,"D:P"){panic("protected DACL missing")}
 body:=s[i:];if body!="(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" && body!="(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)" {panic("unexpected DACL: "+s)}
 return s
}
func main(){
 guard()
 raw,e:=os.ReadFile(`X:\OpenG17\payloads\G81-stage-manifest.json`);must(e);var items []item;must(json.Unmarshal(raw,&items));if len(items)!=3{panic("three fixed files required")}
 allowed:=map[string]string{"G81-fullOS-agent.exe":"open-control-arm64.exe","G81-fullOS-agent.json":"agent.json","G81-run-setup.cmd":"run-setup.cmd"};data:=map[string][]byte{}
 for _,x:=range items {want,ok:=allowed[x.Source];if !ok || want!=x.Name || x.Bytes<1 || x.Bytes>16<<20 || data[x.Name]!=nil{panic("manifest boundary")};b,e:=os.ReadFile(`X:\OpenG17\payloads\`+x.Source);must(e);if len(b)!=x.Bytes || sha(b)!=x.SHA{panic("source identity")};data[x.Name]=b}
 root:=`C:\OpenG81`;if _,e=os.Lstat(root);!os.IsNotExist(e){panic("preserve existing project directory")};must(os.Mkdir(root,0700));acl:=protect(root)
 for _,x:=range items {p:=root+`\`+x.Name;f,e:=os.OpenFile(p,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600);must(e);n,e:=f.Write(data[x.Name]);must(e);if n!=x.Bytes{panic("short copy")};must(f.Sync());must(f.Close());b,e:=os.ReadFile(p);must(e);if sha(b)!=x.SHA{panic("destination identity")}}
 b,e:=json.Marshal(map[string]any{"phase":"new_full_OS_control_files_staged_and_verified","root":root,"dacl":acl,"files":items,"raw_writes":0,"installed_OS_hive_writes":0});must(e);fmt.Println(string(b))
}
