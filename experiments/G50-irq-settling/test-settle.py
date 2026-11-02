"""Exercise the unchanged bounded settling helper at modeled clock/GPIO boundaries."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;src=W/'g50_touch.c';s=src.read_text();m=re.search(r'^static int SettleIrq\(',s,re.M);assert m;i=s.index('{',m.end())+1;d=1
while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
body=s[m.start():i]
code=r'''
#include "g50_touch.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
typedef struct{const G50_TOUCH_IO*Io;G50_TOUCH_RESULT*Result;} Owner;
typedef struct{uint64_t Time;unsigned Clocks,Waits,Reads,FailRead,Mode,QuietCalls;} Model;
static uint64_t Clock(void*c){Model*m=c;unsigned n=m->Clocks++;if(m->Mode==1&&n==1)return m->Time-1;if(m->Mode==2&&n==3)return m->Time+300000;if(m->Mode==3&&n==3)return m->Time-15000;return m->Time;}
static void Wait(Owner*o,uint32_t ms){Model*m=o->Io->Context;assert(ms==10);m->Waits++;if(m->Mode!=9)m->Time+=10000;}
static int Read(Owner*o,uint32_t at,uint32_t*v){Model*m=o->Io->Context;m->Reads++;if(m->Reads==m->FailRead)return 0;
 if(at==0xf119000)*v=(m->Mode==4&&m->Reads==9)?0xc1:0xc0;
 else if(at==0xf119004)*v=(m->Mode==5&&m->Reads==10)?2:(m->Mode==10?0:m->Time>=1040000);
 else if(at==0xf119008)*v=(m->Mode==6&&m->Reads==11)?0xe3:0xe2;
 else if(at==0xf11900c)*v=(m->Mode==7&&m->Reads==12)?2:0;else assert(0);return 1;}
static int Quiet(Owner*o){Model*m=o->Io->Context;m->QuietCalls++;return m->Mode!=8;}
'''+body+r'''
int main(void){Model m;G50_TOUCH_RESULT r;G50_TOUCH_IO io;Owner o;unsigned mode,fail,cases=0;int ok;
 for(mode=0;mode<=10;mode++)for(fail=0;fail<=24;fail++){
  memset(&m,0,sizeof(m));memset(&r,0,sizeof(r));memset(&io,0,sizeof(io));m.Time=1000000;m.Mode=mode;m.FailRead=fail;io.Context=&m;io.NowUs=Clock;o.Io=&io;o.Result=&r;r.BusQuiescent=1;ok=SettleIrq(&o);
  assert(m.Waits<=5&&m.Reads<=24&&m.Clocks<=7&&m.QuietCalls<=1&&r.SettleCount<=6);cases++;
  if(fail&&m.Reads==fail)assert(!ok);
  if(ok){assert(r.SettleCount==6&&m.Reads==24&&m.Waits==5&&m.Clocks==7&&m.QuietCalls==1);assert(mode==0||mode==9||mode==10);assert(r.Settle[5].ElapsedUs==(mode==9?0u:50000u));}
  else if(mode==8&&!fail)assert(!r.BusQuiescent&&r.SettleCount==6);
  if(!fail&&(mode==0||mode==9||mode==10))assert(ok);
  if(!fail&&mode>=1&&mode<=8)assert(!ok);
 }
 printf("{\"passed\":true,\"cases\":%u,\"unchanged_settling_helper\":true,\"backward_late_and_reversed_clocks_refused\":true,\"all24_GPIO_read_failures_and_foreign_pin_state_refused\":true,\"stuck_or_low_input_recorded_without_deassertion_claim\":true,\"elapsed_times_measured_not_assumed\":true}\n",cases);return 0;}
'''
f=a.output/'settle.c';f.write_text(code);exe=a.output/'settle';q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(W),str(f),'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);v=json.loads(q.stdout);v.update(ASan_UBSan=True,Touch_source_sha256=hashlib.sha256(src.read_bytes()).hexdigest(),unchanged_helper_sha256=hashlib.sha256(body.encode()).hexdigest(),native_commands_submitted=0,limits=['Clock, GPIO and quiet checks are modeled services.','Real elapsed times and GPIO levels require separate native observation.']);(a.output/'tests.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
