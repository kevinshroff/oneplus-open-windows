"""Actual C runtime/fault layouts and portable production Go decoders."""
from pathlib import Path
import argparse,subprocess,json,struct,hashlib
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();O=a.output.resolve();assert not O.exists();O.mkdir();W=Path(__file__).resolve().parent
c=O/'fixture.c';c.write_text('''#include "driver-model-prefix.h"
int main(int argc,char**argv){assert(argc==3);G98_RUNTIME r={0};r.Size=sizeof(r);r.Version=1;r.Magic=G98HID_MAGIC;r.State=2;r.Starts=1;r.HardwareCalls=4;r.Cycles=0x100000003ULL;r.Epochs=0x100000001ULL;r.ReportsSubmitted=r.ReportsAccepted=0x200000002ULL;r.OwnerStarts=12;r.Recoveries=3;r.D0=r.Started=r.FaultReady=1;FILE*f=fopen(argv[1],"wb");assert(f&&fwrite(&r,1,sizeof(r),f)==sizeof(r)&&!fclose(f));G98_FAULT q={0};q.Size=sizeof(q);q.Version=1;q.Magic=G98HID_MAGIC;q.Present=1;q.PollCode=4;q.FrameError=4;q.ReadBytes=26;q.AtUs=0x123456789abcULL;memcpy(q.Bytes,G98TESTBadBody,26);f=fopen(argv[2],"wb");assert(f&&fwrite(&q,1,sizeof(q),f)==sizeof(q)&&!fclose(f));return 0;}
''');exe=O/'fixture';subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-const-variable','-I',str(W),'-I',str(W/'inputs'),str(c),'-o',str(exe)],check=True)
rb=O/'runtime.bin';fb=O/'fault.bin';subprocess.run([str(exe),str(rb),str(fb)],check=True)
(O/'g98_session.go').write_bytes((W/'g98_session.go').read_bytes());(O/'decode.go').write_text('''package main;import("os";"encoding/json");func main(){b,e:=os.ReadFile(os.Args[2]);if e!=nil{panic(e)};var v map[string]any;if os.Args[1]=="runtime"{v,e=decodeRuntime(b)}else{v,e=decodeFault(b)};json.NewEncoder(os.Stdout).Encode(map[string]any{"ok":e==nil,"result":v})}''');dec=O/'decoder';subprocess.run(['go','build','-o',str(dec),str(O/'g98_session.go'),str(O/'decode.go')],check=True)
cases=0
def run(mode,b,ok):
 global cases
 f=O/'input.bin';f.write_bytes(b);q=subprocess.run([str(dec),mode,str(f)],capture_output=True,text=True);assert q.returncode==0 and not q.stderr,q.stderr;v=json.loads(q.stdout);assert v['ok']==ok,v;cases+=1;return v['result']
r=run('runtime',rb.read_bytes(),True);assert r['cycles']==0x100000003 and r['reports_accepted']==0x200000002 and r['owner_starts']==12 and r['recoveries']==3 and r['fault_ready']==1
f=run('fault',fb.read_bytes(),True);assert f['read_bytes']==26 and len(f['raw_bytes'])==26 and f['at_us']==0x123456789abc
for mode,b,fields in [('runtime',rb.read_bytes(),[(0,159),(4,2),(8,0),(16,4),(20,7),(24,2),(28,5),(32,2),(36,5),(148,2),(152,2),(156,2)]),('fault',fb.read_bytes(),[(0,135),(4,2),(8,0),(16,2),(28,91)])]:
 run(mode,b[:-1],False);run(mode,b+b'\0',False)
 for at,val in fields:
  bad=bytearray(b);struct.pack_into('<I',bad,at,val);run(mode,bad,False)
r={'passed':True,'cases':cases,'actual_C_layout_and_Go_decoders':True,'counters_above_uint32_verified':True,'runtime_bytes':160,'first_fault_bytes':136,'source_sha256':{n:hashlib.sha256((W/n).read_bytes()).hexdigest()for n in ['g98hid_protocol.h','g98_session.go']},'native_operations':0};(O/'tests.json').write_text(json.dumps(r,indent=2));print(json.dumps(r))
