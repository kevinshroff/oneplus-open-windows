// Capture logical files through Windows' filesystem, including WOF decompression.
// Inputs are a fixed allowlist, opened read-only; output is a new RAM-only ZIP.
package main

import (
 "archive/zip"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "io"
 "os"
 "os/exec"
 "runtime"
 "strings"
)
func must(e error) { if e!=nil { panic(e) } }
func digest(p string) (string,int64,error) {
 f,e:=os.Open(p);if e!=nil{return "",0,e};defer f.Close()
 h:=sha256.New();n,e:=io.Copy(h,f);return hex.EncodeToString(h.Sum(nil)),n,e
}
func main() {
 if runtime.GOARCH!="arm64" || !strings.EqualFold(os.Getenv("SystemRoot"),`X:\Windows`) {panic("ARM64 RAM PE guard")}
 must(exec.Command(`X:\Windows\System32\reg.exe`,"query",`HKLM\SYSTEM\CurrentControlSet\Control\MiniNT`).Run())
 if len(os.Args)!=2 {panic("setup or software bundle required")}
 group:=os.Args[1]
 if group=="replay-copies" {
  root:=`X:\OpenG17\payloads\G80-hive-replay-r3`
  must(os.Mkdir(root,0700));count:=0
  archives:=map[string]string{"setup":"b8bb9f73c844360ab0a2c2808aca90c6a552b824779711e44f8e8f6e0678109b","software":"f456033e8266dfeeaa76e4e36079edf954072d77bebee0874517fe3c5a7ed127"}
  for group,expected:=range archives {
   p:=`X:\OpenG17\payloads\G80-native-`+group+`.zip`;sha,_,e:=digest(p);must(e);if sha!=expected {panic("archive identity")}
   z,e:=zip.OpenReader(p);must(e)
   for _,item:=range z.File {
    prefix:="C/Windows/System32/config/";if !strings.HasPrefix(item.Name,prefix){continue};name:=strings.TrimPrefix(item.Name,prefix)
    allowed:=name=="SYSTEM" || name=="SYSTEM.LOG1" || name=="SYSTEM.LOG2" || name=="SOFTWARE" || name=="SOFTWARE.LOG1" || name=="SOFTWARE.LOG2"
    if !allowed || item.UncompressedSize64>128<<20 {panic("hive entry guard")}
    src,e:=item.Open();must(e);dst,e:=os.OpenFile(root+`\`+name,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600);must(e)
    n,e:=io.Copy(dst,src);must(e);must(src.Close());must(dst.Sync());must(dst.Close());if uint64(n)!=item.UncompressedSize64 {panic("extract size")};count++
   }
   must(z.Close())
  }
  if count!=6 {panic("six hive/log copies required")};fmt.Println("G80_SIX_HIVE_COPIES_EXTRACTED_TO_RAM");return
 }
 paths:=[]string{}
 switch group {
 case "setup":
  paths=[]string{`C:\Windows\System32\spbcd.dll`,`C:\Windows\System32\oobe\windeploy.exe`,`C:\Windows\System32\Sysprep\ActionFiles\Specialize.xml`,`C:\Windows\System32\config\SYSTEM`,`C:\Windows\System32\config\SYSTEM.LOG1`,`C:\Windows\System32\config\SYSTEM.LOG2`,`C:\Windows\Panther\setupact.log`,`C:\Windows\Panther\setuperr.log`,`S:\EFI\Microsoft\Boot\BCD`,`S:\EFI\Microsoft\Boot\BCD.LOG`}
 case "software":
  paths=[]string{`C:\Windows\System32\config\SOFTWARE`,`C:\Windows\System32\config\SOFTWARE.LOG1`,`C:\Windows\System32\config\SOFTWARE.LOG2`}
 default:panic("fixed capture group required")
 }
 output:=`X:\OpenG17\payloads\G80-native-`+group+`.zip`
 f,e:=os.OpenFile(output,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600);must(e)
 z:=zip.NewWriter(f);records:=[]map[string]any{}
 for _,p:=range paths {
  before,n,e:=digest(p);must(e);if n>128<<20 {panic("file size guard")}
  name:=strings.ReplaceAll(strings.ReplaceAll(p,`:`,``),`\`,`/`)
  dst,e:=z.Create(name);must(e);src,e:=os.Open(p);must(e)
  h:=sha256.New();copied,e:=io.Copy(io.MultiWriter(dst,h),src);must(e);must(src.Close())
  after,n2,e:=digest(p);must(e)
  if copied!=n || n2!=n || before!=after || hex.EncodeToString(h.Sum(nil))!=before {panic("source changed during capture")}
  records=append(records,map[string]any{"source":p,"entry":name,"bytes":n,"sha256":before,"source_access":"read-only logical file; three matching reads"})
 }
 manifest:=map[string]any{"group":group,"files":records,"raw_disk_writes":0,"source_writes":0,"output":output}
 w,e:=z.Create("manifest.json");must(e);must(json.NewEncoder(w).Encode(manifest))
 must(z.Close());must(f.Sync());must(f.Close())
 sha,n,e:=digest(output);must(e)
 result:=map[string]any{"file":output,"bytes":n,"sha256":sha,"files":len(records),"raw_disk_writes":0,"source_writes":0}
 b,e:=json.Marshal(result);must(e);fmt.Println(string(b))
}
