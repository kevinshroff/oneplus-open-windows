"""Exercise the actual C96/portable Go session ABI, including terminal states."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
c=a.output/'fixture.c';c.write_text(r'''#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef uint8_t UCHAR;typedef struct{uint32_t a;uint16_t b,c;uint8_t d[8];}GUID;
#define C_ASSERT(x) _Static_assert(x,#x)
#define FIELD_OFFSET(t,f) offsetof(t,f)
#include "g92hid_protocol.h"
int main(int argc,char**argv){if(argc!=2)return 2;G92_SESSION s;memset(&s,0,sizeof(s));s.Size=sizeof(s);s.Version=1;s.Magic=G92HID_MAGIC;s.State=3;s.StopReason=2;s.Starts=s.HardwareCalls=s.ResultReady=s.ThreadJoined=1;s.Outcome=2;s.StopChecks=123;s.StopSeen=3;s.Phase=90;s.PollCycles=0;s.BeginUs=0x123456789abcULL;s.StopUs=s.BeginUs+200000;s.EndUs=s.StopUs+100000;s.StopRequests=1;FILE*f=fopen(argv[1],"wb");if(!f||fwrite(&s,1,sizeof(s),f)!=sizeof(s)||fclose(f))return 3;return 0;}
''');exe=a.output/'fixture';q=subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-I',str(W),str(c),'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
raw=a.output/'session96.bin';subprocess.run([str(exe.resolve()),str(raw.resolve())],check=True)
g=a.output/'decoder.go';g.write_text('package main;import("encoding/json";"os");func main(){b,e:=os.ReadFile(os.Args[1]);if e!=nil{panic(e)};v,e:=decodeSession(b);if e!=nil{json.NewEncoder(os.Stdout).Encode(map[string]any{"ok":false});return};json.NewEncoder(os.Stdout).Encode(map[string]any{"ok":true,"result":v})}')
session_source=a.output/'g92_session.go';session_source.write_bytes((W/'g92_session.go').read_bytes());dec=a.output/'decoder';q=subprocess.run(['go','build','-o',str(dec.resolve()),str(session_source),str(g)],capture_output=True,text=True);assert not q.returncode,q.stderr
b=raw.read_bytes();cases=0
def run(name,data,ok):
 global cases
 path=a.output/(name+'.bin');path.write_bytes(data);q=subprocess.run([str(dec.resolve()),str(path.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);v=json.loads(q.stdout);assert v['ok']==ok,(name,v);cases+=1;return v.get('result')
v=run('normal',b,True);assert v['state']==3 and v['stop_reason']==2 and v['outcome']==2 and v['begin_us']==0x123456789abc and v['stop_us']==v['begin_us']+200000 and v['end_us']==v['stop_us']+100000 and v['stop_requests']==1
run('short',b[:-1],False);run('long',b+b'\0',False)
for name,off,val in [('size',0,95),('version',4,2),('magic',8,0),('state',16,4),('reason',20,7),('starts',24,2),('hardware',28,2),('ready',32,2),('outcome',36,5),('inhibit',48,2),('joined',52,2),('cycles',60,3001)]:
 x=bytearray(b);struct.pack_into('<I',x,off,val);run(name,x,False)
x=bytearray(96);struct.pack_into('<IIQ',x,0,96,1,0x314448323947504f);run('idle',x,True)
struct.pack_into('<I',x,24,1);run('idle_consumed',x,False)
x=bytearray(b);struct.pack_into('<I',x,16,2);run('running_joined',x,False)
x=bytearray(b);struct.pack_into('<I',x,28,0);struct.pack_into('<I',x,36,4);struct.pack_into('<I',x,40,0);struct.pack_into('<I',x,44,1);run('cancel_before_hardware',x,True)
r={'passed':True,'cases':cases,'actual_C96_and_actual_Go_decoder':True,'uint64_timestamps_and_terminal_states_verified':True,'source_sha256':{n:hashlib.sha256((W/n).read_bytes()).hexdigest()for n in ['g92_session.go','g92hid_protocol.h']},'native_operations':0};(a.output/'tests.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
