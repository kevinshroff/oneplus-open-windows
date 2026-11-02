"""Run the actual Go status decoder on an actual C protocol structure."""
from pathlib import Path
import argparse,hashlib,json,re,struct,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;s=(W/'g58_admin.go').read_text();m=re.search(r'^func parseStatus\(',s,re.M);assert m;i=s.index('{',m.end())+1;d=1
while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
body=s[m.start():i];g=a.output/'decoder.go';g.write_text('package main\nimport("encoding/binary";"encoding/json";"errors";"strings";"os")\n'+body+'\nfunc main(){b,e:=os.ReadFile(os.Args[1]);if e!=nil{panic(e)};v,e:=parseStatus(b);out:=map[string]any{"ok":e==nil,"result":v};if e!=nil{out["error"]=e.Error()};json.NewEncoder(os.Stdout).Encode(out)}\n');exe=a.output/'decoder';subprocess.run(['go','build','-trimpath','-buildvcs=false','-o',str(exe.resolve()),str(g.resolve())],check=True,capture_output=True,text=True)
c=a.output/'fixture.c';c.write_text('''#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef uint8_t UCHAR;
typedef struct{uint32_t a;uint16_t b,c;uint8_t d[8];}GUID;
#define FILE_DEVICE_UNKNOWN 0x22
#define METHOD_BUFFERED 0
#define FILE_READ_ACCESS 1
#define FILE_WRITE_ACCESS 2
#define CTL_CODE(d,f,m,a) (((d)<<16)|((a)<<14)|((f)<<2)|(m))
#define C_ASSERT(x) _Static_assert(x,#x)
#define FIELD_OFFSET(t,f) offsetof(t,f)
#include "g58hid_protocol.h"
int main(int argc,char**argv){G58HID_STATUS s;FILE*f;if(argc!=2)return 2;memset(&s,0,sizeof(s));s.Size=sizeof(s);s.Version=1;s.Magic=G58HID_MAGIC;s.KernelBuild=26100;s.Processors=8;s.FirmwareBytes=576;s.FirmwareMatch=s.D0=s.Started=1;s.Entries=2;s.Exits=1;s.Features=4;s.LiveAttempts=1;s.ReportsAccepted=4;s.LiveComplete=1;s.AcceptedGeneration=4;s.ReportsSubmitted=4;s.MaxContacts=10;s.MaxX=22680;s.MaxY=24400;s.ReportBytes=64;s.DescriptorBytes=811;s.Sequence=0x102030405060ULL;memcpy(s.BuildId,"G58-worker1",sizeof("G58-worker1"));f=fopen(argv[1],"wb");if(!f||fwrite(&s,1,sizeof(s),f)!=sizeof(s))return 3;fclose(f);return 0;}
''');cexe=a.output/'fixture';subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-const-variable','-I',str(W),str(c),'-o',str(cexe.resolve())],check=True,capture_output=True,text=True);fixture=a.output/'status-160.bin';subprocess.run([str(cexe.resolve()),str(fixture.resolve())],check=True);raw=fixture.read_bytes();assert len(raw)==160;cases=[]
def run(name,b):
 f=a.output/(name+'.bin');f.write_bytes(b);q=subprocess.run([str(exe.resolve()),str(f.resolve())],check=True,capture_output=True,text=True);v=json.loads(q.stdout);cases.append({'case':name,'ok':v['ok']});return v
v=run('normal',raw);assert v['ok'];r=v['result'];assert r['kernel_build']==26100 and r['processors']==8 and r['firmware_match']==r['D0']==r['started']==r['live_attempts']==1 and r['reports_accepted']==4 and r['live_complete']==1 and r['accepted_generation']==r['reports_submitted']==4 and r['accepted_mask']==r['live_error']==r['stop_attempts']==r['stop_accepted']==0 and r['D0_entries']==2 and r['D0_exits']==1 and r['feature_callbacks']==4 and r['max_contacts']==10 and r['raw_X_max']==22680 and r['raw_Y_max']==24400 and r['report_bytes']==64 and r['descriptor_bytes']==811 and r['mapping_qualified']==0 and r['sequence']==0x102030405060
for name,at,value in [('size',0,127),('version',4,2),('magic',8,0),('build',112,0)]:
 b=bytearray(raw);struct.pack_into('<I',b,at,value);assert not run(name,b)['ok']
assert not run('short',raw[:-1])['ok']and not run('long',raw+b'\0')['ok']
v={'passed':True,'cases':cases,'actual_Go_decoder_and_C_protocol_structure':True,'C_response_bytes':160,'source_sha256':hashlib.sha256(s.encode()).hexdigest(),'protocol_sha256':hashlib.sha256((W/'g58hid_protocol.h').read_bytes()).hexdigest(),'native_operations':0};(a.output/'tests.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps({'passed':True,'cases':len(cases),'C_response_bytes':160}))
