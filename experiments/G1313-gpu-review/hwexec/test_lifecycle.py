"""Exercise actual extracted probe core with fake COM; never loads DbgEng."""
from pathlib import Path
import subprocess
import tempfile

src=Path(__file__).with_name('probe_windows.go').read_text()
core=src[src.index('type attempt struct'):src.index('func main()')]
fake=r'''
package main
import ("fmt"; "unsafe")
var scenario string
var objects,removed,queriesAfterRemoval int
var selected uint32
func need(where string,hr uint32){if hr!=0{panic(where)}}
func count(ctl uintptr)uint32{return uint32(objects)}
//go:uintptrescapes
func call(obj uintptr,slot int,args ...uintptr)uint32{
 if obj==1&&slot==72 {
  if scenario=="create-fails"{return 0x80004005}
  objects++;*(*uintptr)(unsafe.Pointer(args[2]))=2;return 0
 }
 if obj==1&&slot==73 {
  if args[0]!=2{panic("Removed foreign object")};removed++
  if scenario=="remove-fails"{return 0x80004005}
  objects--;return 0
 }
 if obj!=2{panic("Unexpected interface")}
 if objects==0{queriesAfterRemoval++;panic("Use after RemoveBreakpoint")}
 switch slot {
 case 6:
  *(*uint32)(unsafe.Pointer(args[0]))=0
  if scenario=="unexpected-enabled"{*(*uint32)(unsafe.Pointer(args[0]))=4}
 case 13:
  selected=uint32(args[0]);if args[1]!=4{panic("Not EXECUTE")}
  if scenario=="parameter-rejected"{return 0x80070057}
 case 4:
  *(*uint32)(unsafe.Pointer(args[0]))=1;*(*uint32)(unsafe.Pointer(args[1]))=0xaa64
  if scenario=="wrong-type"{*(*uint32)(unsafe.Pointer(args[0]))=0}
 case 12:
  *(*uint32)(unsafe.Pointer(args[0]))=selected;*(*uint32)(unsafe.Pointer(args[1]))=4
  if scenario=="bad-readback"{*(*uint32)(unsafe.Pointer(args[1]))=2}
 default:panic("Unexpected/enabling/releasing method")
 }
 return 0
}
func run(name string,wantPanic bool){
 scenario=name;objects=0;removed=0;queriesAfterRemoval=0
 var result attempt;panicked:=false
 func(){defer func(){if recover()!=nil{panicked=true}}();result=probe(1,4)}()
 if panicked!=wantPanic{panic("Wrong panic result: "+name)}
 wantRemoved:=1;if name=="create-fails"{wantRemoved=0}
 if removed!=wantRemoved||queriesAfterRemoval!=0{panic("Wrong lifetime: "+name)}
 if name!="remove-fails"&&objects!=0{panic("Leaked object: "+name)}
 if !wantPanic&&(!result.Removed||result.Accepted!=(name=="success")){panic("Named return/defer incorrect: "+name)}
 fmt.Println("PASS",name)
}
func main(){
 run("success",false);run("parameter-rejected",false)
 for _,name:=range []string{"create-fails","unexpected-enabled","wrong-type","bad-readback","remove-fails"}{run(name,true)}
}
'''
with tempfile.TemporaryDirectory(prefix='g1313-lifecycle-') as td:
 p=Path(td)/'main.go';p.write_text(fake+'\n'+core)
 subprocess.run(['go','run',str(p)],check=True)
print('Fake COM lifecycle only; native debugger execution remains untested.')
