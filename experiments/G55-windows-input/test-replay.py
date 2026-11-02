"""Execute the actual bounded replay and accepted-state transitions with faults."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
c=r'''
#include "g55_replay.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef struct{unsigned Calls,Waits,Fail,Fail2,WaitFail;uint16_t Scan;uint8_t Accepted[5][64];unsigned Count;}M;
static int Submit(void*x,const uint8_t b[64]){M*m=x;assert(b[0]==1&&b[63]==1&&m->Calls<5);m->Calls++;if(m->Calls==m->Fail||m->Calls==m->Fail2)return 0;assert(m->Count<5);memcpy(m->Accepted[m->Count++],b,64);return 1;}
static int Wait(void*x){M*m=x;m->Waits++;m->Scan+=250;return m->Waits!=m->WaitFail;}
static uint16_t Scan(void*x){return((M*)x)->Scan;}
static unsigned Le(const uint8_t*p){return p[0]+256u*p[1];}
static void Verify(M*m,G55_STATE*s,G55_REPLAY_RESULT*r){
 assert(m->Calls==r->Submitted&&m->Count==r->Accepted&&r->Submitted<=5&&r->CleanupAttempted<=1&&r->CleanupAccepted<=1);
 if(!s->Mask&&m->Count){const uint8_t*up=m->Accepted[m->Count-1];assert(up[1]==2&&up[2]==0);if(m->Count>1){const uint8_t*last=m->Accepted[m->Count-2];assert(last[1]==3&&Le(up+3)==Le(last+3)&&Le(up+5)==Le(last+5));}}
 for(unsigned i=0;i<m->Count;i++){assert(m->Accepted[i][63]==1&&m->Accepted[i][2]==0);for(unsigned j=7;j<61;j+=6)assert(m->Accepted[i][j]==0);}
}
int main(void){unsigned cases=0;G55_STATE s;G55_REPLAY_RESULT r;M m;G55_REPLAY_IO io={&m,Submit,Wait,Scan};
 memset(&s,0,sizeof(s));memset(&m,0,sizeof(m));m.Scan=65500;assert(G55Replay(&s,&io,&r)&&r.Complete&&s.Generation==4&&!s.Mask&&m.Calls==4&&m.Waits==3);Verify(&m,&s,&r);cases++;
 /* Independent expected orientation from the three saved coordinates. */
 const unsigned xy[3][2]={{11459,12578},{2758,3844},{20039,3119}};
 for(unsigned i=0;i<3;i++){assert(m.Accepted[i][1]==3);assert(Le(m.Accepted[i]+3)==xy[i][0]&&Le(m.Accepted[i]+5)==xy[i][1]);cases++;}
 assert(Le(m.Accepted[0]+61)==65500&&Le(m.Accepted[1]+61)==214&&Le(m.Accepted[2]+61)==464&&Le(m.Accepted[3]+61)==714);cases++;
 for(unsigned fail=1;fail<=4;fail++)for(unsigned cleanupFail=0;cleanupFail<2;cleanupFail++){
  memset(&s,0,sizeof(s));memset(&m,0,sizeof(m));m.Fail=fail;if(cleanupFail)m.Fail2=fail+1;
  assert(!G55Replay(&s,&io,&r)&&r.Error==2&&!r.Complete);Verify(&m,&s,&r);
  assert(r.CleanupAttempted==(fail>1));if(fail>1)assert(r.CleanupAccepted==!cleanupFail&&!!s.Mask==!!cleanupFail);else assert(!s.Mask&&!r.Accepted);cases++;
 }
 for(unsigned fail=1;fail<=3;fail++)for(unsigned cleanupFail=0;cleanupFail<2;cleanupFail++){
  memset(&s,0,sizeof(s));memset(&m,0,sizeof(m));m.WaitFail=fail;if(cleanupFail)m.Fail=fail+1;
  assert(!G55Replay(&s,&io,&r)&&r.Error==3&&!r.Complete&&r.CleanupAttempted);Verify(&m,&s,&r);assert(r.CleanupAccepted==!cleanupFail&&!!s.Mask==!!cleanupFail);cases++;
 }
 for(unsigned n=0;n<7;n++){
  memset(&s,0,sizeof(s));memset(&m,0,sizeof(m));G55_REPLAY_IO bad=io;G55_STATE*sp=&s;
  if(n==0)sp=NULL;if(n==1)s.Mask=1;if(n==2)s.Generation=1;if(n==3)bad.Submit=NULL;if(n==4)bad.Wait25ms=NULL;if(n==5)bad.Scan100us=NULL;
  assert(!G55Replay(sp,n==6?NULL:&bad,&r)&&r.Error==4&&!r.Attempted&&!m.Calls);cases++;
 }
 assert(!G55Replay(&s,&io,NULL));cases++;
 printf("{\"passed\":true,\"cases\":%u,\"four_saved_reports_and_max_one_cleanup_UP\":true,\"all_submit_and_wait_failures_tested\":true,\"failed_submit_never_commits_coordinates\":true,\"release_keeps_last_accepted_ID_XY\":true,\"scan_wrap_and_rotated_positions_checked\":true}\n",cases);return 0;}
'''
f=a.output/'model.c';f.write_text(c);exe=a.output/'model';names=['g55_replay.c','g55_lifecycle.c','g55_raw.c'];q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(W),str(f),*[str(W/n)for n in names],'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);v=json.loads(q.stdout);v.update(ASan_UBSan=True,source_sha256={n:hashlib.sha256((W/n).read_bytes()).hexdigest()for n in names+['g55_replay.h','g55_lifecycle.h','g55_raw.h','g55_fixtures.h']},native_operations=0,limits=['Submission and waits are models; no Windows consumer delivery or native driver loading is exercised.']);(a.output/'tests.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
