"""Execute the production re-admission gate with explicit PMIC service models."""
from pathlib import Path
import argparse,subprocess,re,json,hashlib
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();O=a.output.resolve();assert not O.exists();O.mkdir();W=Path(__file__).resolve().parent;s=(W/'g98_hardware.c').read_text()
def fn(name):
 m=re.search(r'^(?:static )?int '+name+r'\(',s,re.M);assert m;at=s.index('{',m.end())+1;d=1
 while d:d+=(s[at]=='{')-(s[at]=='}');at+=1
 return s[m.start():at]
body='''#include "driver-model-prefix.h"
static volatile LONG G98TrialUsed,G98ObserverFault,G98ObserverAttempts,G98OffPmicVerified,G98LastReleaseVerified;
static unsigned Present=1,Calls,Cases;static int Fault,Fixed=1,Off=1;
static int Available(void*x){return*(unsigned*)x;}
static G98_STREAM_IO Stream={&Present,0,0,0,Available,2048,1,0,0};
void G98HardwarePmic(G98_PMIC*out,const G98_STREAM_IO*io){assert(io==&Stream);Calls++;memset(out,0,sizeof(*out));G98ObserverAttempts++;out->Observer.Code=Fault;out->FixedRegistersUnchanged=Fixed;G98OffPmicVerified=Off;if(Fault||!Fixed)G98ObserverFault=1;}
'''+fn('G98Available')+fn('G98HardwareAdmit')+'''
static void Reset(void){G98TrialUsed=G98ObserverFault=G98ObserverAttempts=G98OffPmicVerified=G98LastReleaseVerified=0;Calls=Fault=0;Present=Fixed=Off=1;}
int main(void){Reset();assert(G98HardwareAdmit(&Stream)&&Calls==1&&G98ObserverAttempts==1);Cases++;
 for(unsigned i=0;i<100;i++){G98TrialUsed=G98LastReleaseVerified=1;unsigned before=Calls;assert(G98HardwareAdmit(&Stream)&&Calls==before+1&&!G98TrialUsed&&G98ObserverAttempts==1);assert(G98HardwareAdmit(&Stream)&&Calls==before+1);Cases+=2;}
 for(unsigned which=0;which<4;which++){Reset();if(which==0)Present=0;if(which==1)G98ObserverFault=1;if(which==2)G98TrialUsed=1;if(which==3){G98TrialUsed=1;G98LastReleaseVerified=0;G98ObserverAttempts=1;}assert(!G98HardwareAdmit(&Stream)&&!Calls);Cases++;}
 for(unsigned used=0;used<2;used++)for(unsigned bad=0;bad<3;bad++){Reset();G98TrialUsed=used;G98LastReleaseVerified=used;G98ObserverAttempts=used;if(bad==0)Fault=9;if(bad==1)Fixed=0;if(bad==2)Off=0;assert(!G98HardwareAdmit(&Stream)&&Calls==1&&G98TrialUsed==(LONG)used);unsigned before=Calls;assert(!G98HardwareAdmit(&Stream)&&Calls==before);Cases+=2;}
 printf("{\\"passed\\":true,\\"cases\\":%u,\\"actual_admission_gate\\":true,\\"PMIC_services_modeled\\":true,\\"native_operations\\":0}\\n",Cases);return 0;}
'''
f=O/'model.c';f.write_text(body);exe=O/'model';q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-const-variable','-fsanitize=address,undefined','-I',str(W),'-I',str(W/'inputs'),str(f),'-o',str(exe)],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe)],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);r=json.loads(q.stdout);r['source_sha256']=hashlib.sha256((W/'g98_hardware.c').read_bytes()).hexdigest();(O/'tests.json').write_text(json.dumps(r,indent=2));print(json.dumps(r))
