"""Execute actual bounded contact-wait helper with clock and quiet faults."""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
s=(W/'g52_touch.c').read_text();m=re.search(r'^static int ContactWindow\(',s,re.M);i=s.index('{',m.end())+1;d=1
while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
body=s[m.start():i]
f=a.output/'window.c';f.write_text(r'''
#include "g52_touch.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef struct {const G52_TOUCH_IO*Io;G52_TOUCH_RESULT*Result;} Owner;
typedef struct {uint64_t Time;unsigned Clocks,Waits,QuietCalls,Mode,FailClock;} Model;
static uint64_t Clock(void*c){Model*m=c;unsigned call=m->Clocks++;if(call==m->FailClock){if(m->Mode==1)return m->Time-100001;if(m->Mode==2)return 9000001;}return m->Time;}
static void Wait(Owner*o,uint32_t ms){Model*m=o->Io->Context;assert(ms==100);m->Waits++;if(m->Mode!=3)m->Time+=100000;}
static int Quiet(Owner*o){Model*m=o->Io->Context;m->QuietCalls++;return m->Mode!=4;}
'''+body+r'''
int main(void){unsigned mode,at,cases=0;for(mode=0;mode<5;mode++)for(at=0;at<=51;at++){
 Model m={1000000,0,0,0,mode,at};G52_TOUCH_RESULT r;G52_TOUCH_IO io={0};Owner o={&io,&r};memset(&r,0,sizeof(r));r.BusQuiescent=1;io.Context=&m;io.NowUs=Clock;
 int ok=ContactWindow(&o);assert(m.Waits<=50&&m.Clocks<=51&&m.QuietCalls<=1);cases++;
 if(mode==0||(at==51&&mode<3)||(mode==1&&at==0)){assert(ok&&m.Waits==50&&m.Clocks==51&&m.QuietCalls==1);}
 if(((mode==1&&at>0)||mode==2)&&at<=50)assert(!ok);
 if(mode==3)assert(!ok&&m.Waits==50&&m.QuietCalls==0);
 if(mode==4)assert(!ok&&!r.BusQuiescent&&m.QuietCalls==1);
 }
 printf("{\"passed\":true,\"cases\":%u,\"clock_deadline_and_regression_at_all50_post_start_boundaries\":true,\"minimum_five_seconds_required\":true,\"quiet_fault_denies_bus_ownership\":true}\n",cases);return 0;}
''')
exe=a.output/'window';q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(W),str(f),'-o',str(exe.resolve())],capture_output=True,text=True);assert q.returncode==0,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert q.returncode==0 and not q.stderr,(q.stdout,q.stderr)
v=json.loads(q.stdout);v.update(touch_sha256=hashlib.sha256((W/'g52_touch.c').read_bytes()).hexdigest(),actual_helper_sha256=hashlib.sha256(body.encode()).hexdigest(),ASan_UBSan=True,native_access=False)
(a.output/'tests.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
