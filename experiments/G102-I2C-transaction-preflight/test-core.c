/* Explicit MMIO/time/clock models. No native operation is performed. */
#include "g102_core.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
typedef struct{unsigned Reads,Peripherals,SeenLoss,FailAt,CancelAt,ChangeAt,Off,WrongHwcg,Busy,TimeCalls,ClockAt,JumpAt;uint64_t Now;}Model;
static unsigned Cases;
static int Read(void*x,uint32_t at,uint32_t*v){Model*m=x;assert(G102ReadAllowed(at));m->Reads++;if(m->FailAt==m->Reads)return 0;
 for(unsigned i=0;i<2;i++){
  const G102_CONTROLLER*c=G102Controllers+i;
  if(at==c->Root){*v=m->Busy==i+1?1:0x80000000;return 1;}if(at==c->Root+4){*v=1;return 1;}
  for(unsigned j=0;j<3;j++){
   const G102_CLOCK*k=c->Clocks+j;
   if(at==k->Vote){*v=i?0x44302380:0x1001f;if(m->Off==i+1||(m->ChangeAt&&m->Reads>=m->ChangeAt))*v=0;if(!*v&&m->ChangeAt)m->SeenLoss=1;return 1;}
   if(at==k->Cbcr){*v=k->Hwcg?0x80000002:0;if(m->WrongHwcg==i+1&&k->Hwcg)*v=0x80000000;return 1;}
  }
  for(unsigned j=0;j<2;j++){uint32_t base=0xf100000+c->Pins[j]*0x1000;if(at==base){*v=(c->Mux[j]<<2)|3;return 1;}if(at==base+4){*v=1;return 1;}}
 }
 int i=G102Peripheral(at);assert(i>=0);m->Peripherals++;
 if(at==G102Controllers[i].Wrapper+4)*v=0x30090000;
 else if(at==G102Controllers[i].Base+0x68)*v=0x302;
 else if(at==G102Controllers[i].Base+0xe24||at==G102Controllers[i].Base+0xe28)*v=0x100010;
 else *v=0;
 return 1;
}
static int Available(void*x){Model*m=x;return !m->CancelAt||m->Reads<m->CancelAt;}
static uint64_t Now(void*x){Model*m=x;m->TimeCalls++;if(m->TimeCalls==m->ClockAt)return 0;if(m->TimeCalls==m->JumpAt)m->Now+=2000001;return ++m->Now;}
static void Run(Model*m,G102_RESULT*r){memset(r,0,sizeof(*r));G102_IO io={m,Read,Available,Now};G102Probe(&io,r);assert(r->Reads==m->Reads&&r->Reads<=G102_TRACE&&r->TraceCount<=r->Reads);Cases++;}
int main(void){Model baseline={0};G102_RESULT*r=calloc(1,sizeof(*r));assert(r);Run(&baseline,r);assert(!r->Code&&r->ReadyMask==3&&r->PostClockMask==3&&r->PinStableMask==15&&baseline.Peripherals==72&&r->Reads==696);unsigned reads=baseline.Reads;
 for(unsigned n=1;n<=reads;n++){Model m={0};m.FailAt=n;Run(&m,r);assert(r->Code==G102_IO_ERROR&&m.Reads==n);}
 for(unsigned n=1;n<=reads;n++){Model m={0};m.CancelAt=n;Run(&m,r);assert(r->Code==(n==reads?G102_OK:G102_CANCELLED)&&m.Reads==n);}
 for(unsigned i=1;i<=2;i++)for(unsigned field=0;field<3;field++){Model m={0};if(field==0)m.Off=i;if(field==1)m.WrongHwcg=i;if(field==2)m.Busy=i;Run(&m,r);assert(!r->Code&&r->ReadyMask==(3u^(1u<<(i-1)))&&m.Peripherals==(i==1?35u:37u));}
 for(unsigned n=25;n<=reads;n++){Model m={0};m.ChangeAt=n;Run(&m,r);assert(!r->Code||r->Code==G102_CLOCK_CHANGED);if(!r->Code&&m.SeenLoss)assert(r->PostClockMask!=3);}
 for(unsigned n=2;n<=reads+2;n++){Model m={0};m.ClockAt=n;Run(&m,r);assert(r->Code==G102_TIME_ERROR);m=(Model){0};m.JumpAt=n;Run(&m,r);assert(r->Code==G102_TIME_ERROR);}
 const uint32_t forbidden[]={0xc7b7000,0xc7b7008,0xb000000,0x880700,0x880780,0x880618,0x98c700,0x98c780,0x98c618};
 for(unsigned i=0;i<sizeof(forbidden)/sizeof(forbidden[0]);i++){assert(!G102ReadAllowed(forbidden[i]));Cases++;}
 for(unsigned i=0;i<2;i++)for(unsigned off=0;off<0x1000;off++){
  int expected=0;for(unsigned j=0;j<G102_OFFSETS;j++)if(G102Offset(i,j)!=G102_SKIPPED&&off==G102Offset(i,j))expected=1;
  assert(G102ReadAllowed(G102Controllers[i].Base+off)==expected);Cases++;
 }
 free(r);printf("{\"passed\":true,\"cases\":%u,\"every_read_failure_and_cancellation\":true,\"clock_gating_and_post_snapshot_changes_checked\":true,\"HWCG_and_required_votes_modeled\":true,\"no_write_callback_exists\":true,\"native_operations\":0}\n",Cases);return 0;}
