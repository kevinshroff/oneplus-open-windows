/* Test only: captured fixtures are never linked into the native producer. */
#include "g58_input.h"
#include "g58_poll.h"
#include "test-fixtures.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef struct {
 G58_INPUT Input;uint64_t Now;unsigned Cycle,StageCalls,PublishCalls,ClearCalls,QuietCalls,SubmitCalls,Accepted;
 unsigned ReadCalls,IrqCalls,FailRead,FailIrq,JumpIrq,IrqBad,LastKind,BadAt;
 unsigned StopCalls,StopAt;
 unsigned Profile,FailStage,FailClear,FailSubmit,FailQuiet,JumpStage,JumpPublish;uint8_t Reports[102][64];int HaveStage,Ack,ClearQuiet;
}M;
static unsigned Cases;
static int Submit(void*x,const uint8_t b[64]){M*m=x;m->SubmitCalls++;assert(m->SubmitCalls<=101&&b[0]==1);if(m->SubmitCalls==m->FailSubmit)return 0;memcpy(m->Reports[m->Accepted++],b,64);return 1;}
static int Read(void*x,uint32_t kind,uint32_t address,uint8_t*b,uint32_t n){M*m=x;assert(address==G58_TOUCH_ADDRESS&&n==26&&(kind==G58_READ_PREFETCH||kind==G58_READ_RETRY));
 unsigned cycle=kind==G58_READ_RETRY?m->Cycle-1:m->Cycle;assert(cycle<100);if(kind==G58_READ_RETRY)assert(m->LastKind==G58_READ_PREFETCH&&!m->Ack&&!m->HaveStage);m->LastKind=kind;m->ReadCalls++;if(m->ReadCalls==m->FailRead)return 0;memset(b,0,n);
 if(m->Profile==0&&cycle<4)memcpy(b,G58TESTReplayRaw[cycle],26);
 if(m->Profile==1)memcpy(b,G58TESTReplayRaw[cycle%3],26);
 if(m->Profile==2&&cycle==0)memcpy(b,G58TESTReplayRaw[3],26);
 if(m->Profile==3){memcpy(b,G58TESTReplayRaw[0],26);b[8]^=1;}
 if(m->Profile>=4&&m->Profile<=6){
  memcpy(b,G58TESTReplayRaw[0],26);
  if(m->Profile==4)b[0]=0x81;
  if(m->Profile==5){b[10]=(uint8_t)22681;b[11]=(uint8_t)(22681>>8);}
  if(m->Profile==6)b[8]=4;
  unsigned sum=0;for(unsigned i=0;i<6;i++)sum+=b[i];b[6]=(uint8_t)sum;b[7]=(uint8_t)(sum>>8);
  sum=0;for(unsigned i=8;i<16;i++)sum+=b[i];b[16]=(uint8_t)sum;b[17]=(uint8_t)(sum>>8);
 }
 if(m->Profile>=7){
  memcpy(b,G58TESTReplayRaw[cycle%3],26);
  if(kind==G58_READ_PREFETCH&&(!m->BadAt||m->BadAt==cycle+1))memcpy(b,G58TESTBadHeader,26);
  if(kind==G58_READ_RETRY&&m->Profile==8)memcpy(b,G58TESTBadHeader,26);
  if(kind==G58_READ_RETRY&&m->Profile==9)memset(b,0,26);
 }
 if(kind==G58_READ_PREFETCH)m->Cycle++;m->HaveStage=m->Ack=m->ClearQuiet=0;m->Now+=100;return 1;
}
static int Irq(void*x,G58_POLL_IRQ*s){M*m=x;m->IrqCalls++;memset(s,0,sizeof(*s));s->Control=0xc0;s->Config=0xe2;s->Input=m->IrqCalls&1;s->Status=(m->IrqCalls>>1)&1;m->Now++;
 if(m->IrqCalls==m->JumpIrq)m->Now+=G58_POLL_DEADLINE_US+1;
 if(m->IrqCalls==m->FailIrq)return 0;
 if(m->IrqBad==1)s->Control^=1;if(m->IrqBad==2)s->Config^=1;if(m->IrqBad==3)s->Input=2;if(m->IrqBad==4)s->Status=2;return 1;}
static int Clear(void*x){M*m=x;m->ClearCalls++;assert(m->HaveStage&&!m->Ack);if(m->ClearCalls==m->FailClear)return 0;m->Ack=1;m->Now+=100;return 1;}
static int Quiet(void*x){M*m=x;m->QuietCalls++;if(m->QuietCalls==m->FailQuiet)return 0;if(m->Ack)m->ClearQuiet=1;m->Now++;return 1;}
static void Wait(void*x){((M*)x)->Now+=10000;}
static uint64_t Now(void*x){return((M*)x)->Now;}
static int Stage(void*x,const uint8_t*b,uint32_t n,uint64_t at){M*m=x;m->StageCalls++;assert(!m->Ack);if(m->StageCalls==m->FailStage)return 0;
 int ok=G58InputStage(&m->Input,b,n,(uint16_t)(at/100));if(ok)m->HaveStage=1;if(m->StageCalls==m->JumpStage)m->Now+=G58_POLL_DEADLINE_US+1;return ok;
}
static int Publish(void*x,const uint8_t*b,uint32_t n){M*m=x;G58_INPUT_IO io={m,Submit};m->PublishCalls++;assert(m->Ack&&m->ClearQuiet&&m->HaveStage);if(m->PublishCalls==m->JumpPublish)m->Now+=G58_POLL_DEADLINE_US+1;return G58InputPublish(&m->Input,&io,b,n);}
static int Stop(void*x){M*m=x;m->StopCalls++;return m->StopAt&&m->StopCalls>=m->StopAt;}
static int Run(M*m,G58_POLL_RESULT*r,unsigned limit){G58_POLL_IO io={m,limit,Read,Clear,Quiet,Wait,Now,Stage,Publish,Irq,Stop};int ok=G58Poll(&io,r);G58_INPUT_IO sink={m,Submit};unsigned old=m->SubmitCalls;int stopped=G58InputStop(&m->Input,&sink,(uint16_t)(m->Now/100));assert(m->SubmitCalls<=old+1);old=m->SubmitCalls;G58InputStop(&m->Input,&sink,0);assert(m->SubmitCalls==old);if(stopped)assert(!m->Input.Accepted.Mask);Cases++;return ok;}
static unsigned Le(const uint8_t*p){return p[0]+256u*p[1];}
int main(void){M m;G58_POLL_RESULT r;
 for(unsigned limit=8;limit<=100;limit+=92){
  memset(&m,0,sizeof(m));assert(Run(&m,&r,limit)&&r.Cycles==limit&&r.Limit==limit&&r.ClearCompleted==4&&m.Accepted==4&&m.Input.Accepted.Generation==4&&!m.Input.Accepted.Mask);
  assert(m.Reports[0][1]==3&&m.Reports[1][1]==3&&m.Reports[2][1]==3&&m.Reports[3][1]==2&&m.Reports[3][63]==1&&Le(m.Reports[2]+3)==Le(m.Reports[3]+3)&&Le(m.Reports[2]+5)==Le(m.Reports[3]+5));
 }
 memset(&m,0,sizeof(m));m.Profile=1;assert(Run(&m,&r,100)&&r.ClearCompleted==100&&m.Input.Published==100&&m.Accepted==101&&m.Input.StopAccepted==1&&!m.Input.Accepted.Mask);
 assert(m.Reports[100][1]==2&&Le(m.Reports[99]+3)==Le(m.Reports[100]+3)&&Le(m.Reports[99]+5)==Le(m.Reports[100]+5));
 memset(&m,0,sizeof(m));m.Profile=2;assert(Run(&m,&r,100)&&r.ClearCompleted==1&&m.Input.Staged==m.Input.Published==m.Input.NoReport&&m.Input.NoReport==1&&!m.SubmitCalls);
 memset(&m,0,sizeof(m));m.Profile=3;assert(!Run(&m,&r,100)&&r.Code==G58_POLL_DECODE&&!m.StageCalls&&!m.ClearCalls&&!m.SubmitCalls);
 /* Raw-valid optional flags, out-of-axis points and unsupported finger types
  * must fail HID mapping before clearing a physical pending event. */
 for(unsigned profile=4;profile<=6;profile++){memset(&m,0,sizeof(m));m.Profile=profile;assert(!Run(&m,&r,100)&&r.Code==G58_POLL_STAGE&&m.StageCalls==1&&!m.ClearCalls&&!m.PublishCalls&&!m.SubmitCalls);}
 for(unsigned at=1;at<=100;at++){
  memset(&m,0,sizeof(m));m.Profile=1;m.FailStage=at;assert(!Run(&m,&r,100)&&r.Code==G58_POLL_STAGE&&m.ClearCalls==at-1&&m.PublishCalls==at-1);
  memset(&m,0,sizeof(m));m.Profile=1;m.FailClear=at;assert(!Run(&m,&r,100)&&r.Code==G58_POLL_CLEAR&&m.ClearCalls==at&&m.PublishCalls==at-1);
  memset(&m,0,sizeof(m));m.Profile=1;m.FailSubmit=at;assert(!Run(&m,&r,100)&&r.Code==G58_POLL_PUBLISH&&m.PublishCalls==at&&m.ClearCalls==at&&!m.Input.Accepted.Mask);
  if(at>1){assert(m.Reports[m.Accepted-1][1]==2);if(m.Accepted>1)assert(Le(m.Reports[m.Accepted-2]+3)==Le(m.Reports[m.Accepted-1]+3)&&Le(m.Reports[m.Accepted-2]+5)==Le(m.Reports[m.Accepted-1]+5));}
  memset(&m,0,sizeof(m));m.Profile=1;m.JumpStage=at;assert(!Run(&m,&r,100)&&r.Code==G58_POLL_CLOCK&&m.ClearCalls==at-1&&m.PublishCalls==at-1);
  memset(&m,0,sizeof(m));m.Profile=1;m.JumpPublish=at;assert(!Run(&m,&r,100)&&r.Code==G58_POLL_CLOCK&&m.PublishCalls==at&&m.ClearCalls==at);
 }
 /* Every final/full-cycle quiet boundary can stop publishing without replay. */
 memset(&m,0,sizeof(m));m.Profile=1;assert(Run(&m,&r,100));unsigned quiets=m.QuietCalls;
 for(unsigned at=1;at<=quiets;at++){memset(&m,0,sizeof(m));m.Profile=1;m.FailQuiet=at;assert(!Run(&m,&r,100)&&r.Code==G58_POLL_QUIET);}
 memset(&m,0,sizeof(m));m.Profile=1;m.FailSubmit=101;assert(Run(&m,&r,100)&&m.Input.Accepted.Mask==1&&m.Input.Error==8&&m.SubmitCalls==101&&m.Input.StopAttempts==1&&!m.Input.StopAccepted);
 /* Stage/raw/plan mutations cannot authorize a different report or double use. */
 for(unsigned mutate=0;mutate<5;mutate++){
  memset(&m,0,sizeof(m));G58_INPUT_IO io={&m,Submit};uint8_t b[26];memcpy(b,G58TESTReplayRaw[0],26);assert(G58InputStage(&m.Input,b,26,17));
  if(mutate==0)b[10]^=1;if(mutate==1)m.Input.Pending.Report[3]^=1;if(mutate==2)m.Input.Accepted.Generation++;if(mutate==3)m.Input.Pending.HaveReport^=1;if(mutate==4)m.Input.Pending.FromGeneration++;
  assert(!G58InputPublish(&m.Input,&io,b,26)&&!m.SubmitCalls&&!m.Input.Accepted.Mask);Cases++;
 }
 memset(&m,0,sizeof(m));G58_INPUT_IO io={&m,Submit};assert(G58InputStage(&m.Input,G58TESTReplayRaw[0],26,1)&&G58InputPublish(&m.Input,&io,G58TESTReplayRaw[0],26));unsigned old=m.SubmitCalls;assert(!G58InputPublish(&m.Input,&io,G58TESTReplayRaw[0],26)&&m.SubmitCalls==old);assert(G58InputStop(&m.Input,&io,2)&&!m.Input.Accepted.Mask);Cases++;
 for(unsigned limit=0;limit<=101;limit+=101){memset(&m,0,sizeof(m));assert(!Run(&m,&r,limit)&&r.Code==G58_POLL_ARGUMENT&&!m.Cycle&&!m.ClearCalls&&!m.SubmitCalls);}
 /* A real G56 bad header precedes modeled fresh responses. Never treat the
  * later response as native evidence merely because the first bytes are native. */
 memset(&m,0,sizeof(m));m.Profile=7;assert(Run(&m,&r,100)&&r.HeaderRetries==100&&r.HeadersRecovered==100&&m.ReadCalls==200&&m.IrqCalls==400&&m.Accepted==101);
 for(unsigned i=0;i<100;i++)assert(r.Records[i].HeaderRetry==1&&r.Records[i].FirstReadBytes==26&&r.Records[i].IrqMask==15&&!memcmp(r.Records[i].First,G58TESTBadHeader,26));
 for(unsigned at=1;at<=100;at++){memset(&m,0,sizeof(m));m.Profile=7;m.BadAt=at;assert(Run(&m,&r,100)&&r.HeaderRetries==r.HeadersRecovered&&r.HeaderRetries==1&&m.ReadCalls==101&&m.ClearCalls==100);}
 memset(&m,0,sizeof(m));m.Profile=8;assert(!Run(&m,&r,100)&&r.Code==G58_POLL_DECODE&&m.ReadCalls==2&&r.HeaderRetries==1&&!r.HeadersRecovered&&!m.StageCalls&&!m.ClearCalls&&!m.SubmitCalls);
 memset(&m,0,sizeof(m));m.Profile=9;assert(Run(&m,&r,100)&&r.HeaderRetries==100&&!r.HeadersRecovered&&r.IdleRecords==100&&!m.StageCalls&&!m.ClearCalls&&!m.SubmitCalls);
 for(unsigned at=1;at<=200;at++){memset(&m,0,sizeof(m));m.Profile=7;m.FailRead=at;assert(!Run(&m,&r,100)&&r.Code==G58_POLL_READ&&m.ReadCalls==at);}
 for(unsigned at=1;at<=400;at++){memset(&m,0,sizeof(m));m.Profile=7;m.FailIrq=at;assert(!Run(&m,&r,100)&&r.Code==G58_POLL_IRQ_ERROR&&m.IrqCalls==at);}
 for(unsigned at=1;at<=400;at++){memset(&m,0,sizeof(m));m.Profile=7;m.JumpIrq=at;assert(!Run(&m,&r,100)&&r.Code==G58_POLL_CLOCK&&m.IrqCalls==at);}
 for(unsigned bad=1;bad<=4;bad++){memset(&m,0,sizeof(m));m.Profile=7;m.IrqBad=bad;assert(!Run(&m,&r,100)&&r.Code==G58_POLL_IRQ_ERROR&&!m.ReadCalls&&!m.ClearCalls&&!m.SubmitCalls);}
 const unsigned stop_profiles[]={0,1,7,9};
 for(unsigned index=0;index<4;index++){
  unsigned profile=stop_profiles[index];
  memset(&m,0,sizeof(m));m.Profile=profile;assert(Run(&m,&r,100));unsigned boundaries=m.StopCalls;
  for(unsigned stop=1;stop<=boundaries;stop++){
   memset(&m,0,sizeof(m));m.Profile=profile;m.StopAt=stop;
   assert(!Run(&m,&r,100)&&r.Code==G58_POLL_CANCELLED&&r.BusQuiescent&&m.StopCalls==stop);
   assert(m.Input.StopAttempts==1&&!m.Input.Accepted.Mask&&m.StageCalls==m.PublishCalls&&m.PublishCalls==r.ClearCompleted);
  }
 }
 printf("{\"one_fixed_read_retry_only_after_completed_bad_header\":true,\"all200_read_and400_IRQ_failure_clock_boundaries\":true,\"second_bad_header_never_cleared\":true,\"native_G56_bad_header_followed_by_modeled_successor_only\":true,\"passed\":true,\"cases\":%u,\"actual_poll_and_input_lifecycle_executed\":true,\"stage_before_clear_publish_after_quiet\":true,\"all100_stage_clear_submit_and_clock_failure_positions\":true,\"all_nominal_quiet_failure_positions\":true,\"failed_submit_never_commits_new_coordinates\":true,\"stop_once_releases_last_accepted_state\":true,\"no_spurious_windows_input_for_zero_count_with_empty_state\":true}\n",Cases);
 return 0;
}
