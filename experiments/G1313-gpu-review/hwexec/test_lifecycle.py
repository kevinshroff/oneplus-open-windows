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
  if scenario=="enabled-after-set"&&selected!=0{*(*uint32)(unsafe.Pointer(args[0]))=4}
 case 13:
  selected=uint32(args[0]);if args[1]!=4{panic("Not EXECUTE")}
  if scenario=="parameter-rejected"{return 0x80070057}
 case 4:
  *(*uint32)(unsafe.Pointer(args[0]))=1;*(*uint32)(unsafe.Pointer(args[1]))=0xaa64
  if scenario=="wrong-type"{*(*uint32)(unsafe.Pointer(args[0]))=0}
 case 12:
  *(*uint32)(unsafe.Pointer(args[0]))=selected;*(*uint32)(unsafe.Pointer(args[1]))=4
  if scenario=="bad-readback"{*(*uint32)(unsafe.Pointer(args[1]))=2}
  if scenario=="size-canonicalization"{*(*uint32)(unsafe.Pointer(args[0]))=4}
 default:panic("Unexpected/enabling/releasing method")
 }
 return 0
}
func run(name string,wantPanic bool){
 scenario=name;objects=0;removed=0;queriesAfterRemoval=0;selected=0
 var result attempt;panicked:=false
 func(){defer func(){if recover()!=nil{panicked=true}}();result=probe(1,4)}()
 if panicked!=wantPanic{panic("Wrong panic result: "+name)}
 wantRemoved:=1;if name=="create-fails"{wantRemoved=0}
 if removed!=wantRemoved||queriesAfterRemoval!=0{panic("Wrong lifetime: "+name)}
 if name!="remove-fails"&&objects!=0{panic("Leaked object: "+name)}
 if !wantPanic&&(!result.Removed||result.Accepted!=(name=="success")){panic("Named return/defer incorrect: "+name)}
 if name=="bad-readback"&&(result.Access!=2||result.ReadSize!=4||result.Matched||result.Reason!="parameter_readback_mismatch_observed"){panic("Lost mismatch evidence")}
 fmt.Println("PASS",name)
}
func main(){
 run("success",false);run("parameter-rejected",false);run("bad-readback",false)
 for _,name:=range []string{"create-fails","unexpected-enabled","enabled-after-set","wrong-type","remove-fails"}{run(name,true)}
 scenario="size-canonicalization";objects=0;removed=0;queriesAfterRemoval=0;selected=0
 a,b:=probe(1,1),probe(1,4)
 if a.Size!=1||a.ReadSize!=4||a.Access!=4||a.Flags!=0||a.Accepted||a.Matched||!a.Removed||a.Reason!="parameter_readback_mismatch_observed"{panic("First mismatch observation lost")}
 if b.Size!=4||b.ReadSize!=4||!b.Accepted||!b.Matched||!b.Removed||objects!=0||removed!=2||queriesAfterRemoval!=0{panic("Independent size4 not completed")}
 fmt.Println("PASS size1 mismatch retained; independent size4 exact match (synthetic scenario only)")
}
'''
with tempfile.TemporaryDirectory(prefix='g1313-lifecycle-') as td:
 p=Path(td)/'main.go';p.write_text(fake+'\n'+core)
 subprocess.run(['go','run',str(p)],check=True)
print('Fake COM lifecycle only; native debugger execution remains untested.')
