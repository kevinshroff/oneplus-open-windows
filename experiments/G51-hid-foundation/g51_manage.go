// Source-built native manager for the OnePlus Open G51 input foundation.
package main
import("crypto/sha256";"encoding/hex";"encoding/json";"errors";"fmt";"os";"runtime";"syscall";"unsafe")
var adv=syscall.NewLazyDLL("advapi32.dll")
var setup=syscall.NewLazyDLL("setupapi.dll")
var cfg=syscall.NewLazyDLL("cfgmgr32.dll")
var kernel=syscall.NewLazyDLL("kernel32.dll")
var user=syscall.NewLazyDLL("user32.dll")
func wide(s string)*uint16{p,e:=syscall.UTF16PtrFromString(s);if e!=nil{panic(e)};return p}
func winerr(where string,e error)error{if e==nil||e==syscall.Errno(0){return errors.New(where+": unknown Windows failure")};return fmt.Errorf("%s: %w",where,e)}
func textAt(p uintptr)string{if p==0{return ""};buf:=make([]uint16,0,128);for i:=uintptr(0);i<32768;i++{v:=*(*uint16)(unsafe.Pointer(p+i*2));if v==0{return syscall.UTF16ToString(buf)};buf=append(buf,v)};return "[unterminated]"}
func closeSvc(h uintptr){if h!=0{adv.NewProc("CloseServiceHandle").Call(h)}}
func service(name string)map[string]any{
 out:=map[string]any{"name":name};m,_,e:=adv.NewProc("OpenSCManagerW").Call(0,0,1);if m==0{out["error"]=winerr("OpenSCManager",e).Error();return out};defer closeSvc(m)
 h,_,e:=adv.NewProc("OpenServiceW").Call(m,uintptr(unsafe.Pointer(wide(name))),1|4);if h==0{out["present"]=false;out["error"]=e.Error();return out};defer closeSvc(h);out["present"]=true
 var need uint32;adv.NewProc("QueryServiceConfigW").Call(h,0,0,uintptr(unsafe.Pointer(&need)));if need<64||need>1<<20{out["config_error"]="unexpected config size";return out};b:=make([]byte,need);ok,_,e:=adv.NewProc("QueryServiceConfigW").Call(h,uintptr(unsafe.Pointer(&b[0])),uintptr(need),uintptr(unsafe.Pointer(&need)));if ok==0{out["config_error"]=e.Error();return out}
 out["type"]=*(*uint32)(unsafe.Pointer(&b[0]));out["start_type"]=*(*uint32)(unsafe.Pointer(&b[4]));out["error_control"]=*(*uint32)(unsafe.Pointer(&b[8]));out["binary"]=textAt(*(*uintptr)(unsafe.Pointer(&b[16])));out["load_group"]=textAt(*(*uintptr)(unsafe.Pointer(&b[24])))
 var status [7]uint32;ok,_,e=adv.NewProc("QueryServiceStatus").Call(h,uintptr(unsafe.Pointer(&status[0])));if ok!=0{out["state"]=status[1]}else{out["status_error"]=e.Error()};runtime.KeepAlive(b);return out
}
func file(path string)map[string]any{b,e:=os.ReadFile(path);if e!=nil{return map[string]any{"path":path,"present":false,"error":e.Error()}};s:=sha256.Sum256(b);return map[string]any{"path":path,"present":true,"bytes":len(b),"sha256":hex.EncodeToString(s[:])}}
func inventory()(any,error){
 var f [576]byte;r,_,e:=kernel.NewProc("GetSystemFirmwareTable").Call(0x41435049,0x54445344,uintptr(unsafe.Pointer(&f[0])),uintptr(len(f)));if r!=576{return nil,winerr("exact G17 DSDT",e)};s:=sha256.Sum256(f[:]);dsdt:=hex.EncodeToString(s[:]);if dsdt!="c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01"{return nil,errors.New("G17 DSDT identity mismatch")}
 a,_,_:=user.NewProc("GetSystemMetrics").Call(0);b,_,_:=user.NewProc("GetSystemMetrics").Call(1);d,_,_:=user.NewProc("GetSystemMetrics").Call(94)
 services:=[]any{};for _,n:=range []string{"vhf","mshidkmdf","Wdf01000","hidusb","mouhid","kbdhid"}{services=append(services,service(n))}
 files:=[]any{};for _,n:=range []string{"vhf.sys","mshidkmdf.sys","hidclass.sys","hidparse.sys","mouhid.sys","kbdhid.sys"}{files=append(files,file(`X:\Windows\System32\drivers\`+n))}
 return map[string]any{"DSDT_sha256":dsdt,"GOARCH":runtime.GOARCH,"display_pixels":[]uintptr{a,b},"SM_DIGITIZER":d,"services":services,"files":files,"setupapi_LoadLibrary":setup.Load()==nil,"cfgmgr32_LoadLibrary":cfg.Load()==nil,"native_mutations":0},nil
}
func main(){var v any;var e error;if len(os.Args)!=2||os.Args[1]!="inventory"{e=errors.New("usage: inventory")}else{v,e=inventory()};r:=map[string]any{"ok":e==nil,"result":v};if e!=nil{r["error"]=e.Error()};json.NewEncoder(os.Stdout).Encode(r);if e!=nil{os.Exit(1)}}
