/* Explicit MMIO/time models; executes the real portable sampler. */
#include "g99_core.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct {unsigned Reads,Writes,Waits,Poll,Active,Target,Offset,Rts,Configs,FailRead,FailWrite,FailAfter,WrongRoute,WrongOwner,WrongId,Pending,Timeout,Denied,ConfigChanged,CancelAt,ClockAt,JumpAt,TimeCalls,InvalidArb,CompletionDelay;uint32_t LastCommand,Data[2];uint64_t Now;}Model;
static unsigned Cases;
static uint8_t Ids[4][8]={{33,0,1,2,81,74,1,0},{0,1,0,1,1,8,0,0},{0,1,0,1,1,9,0,0},{0,4,1,1,16,16,0,0}};
static uint8_t Config[8]={0,0,1,1,0,0,0,128};
static int Index(uint32_t at){for(unsigned i=0;i<4;i++)if(at>=G99Base(i)&&at<G99Base(i)+0x20)return(int)i;return -1;}
static int R(void*x,uint32_t at,uint32_t*out){Model*m=x;assert(G99ReadAllowed(at));m->Reads++;if(m->FailRead==m->Reads&&!m->FailAfter)return 0;
 if(at==0xc400000)*out=m->InvalidArb?0:0x70000001;else if(at==0xc400004)*out=0x80040300;else{
  unsigned handled=0;for(unsigned i=0;i<4;i++){
   if(at==0xc402000+G99Targets[i].Apid*4){*out=G99Targets[i].Map^(m->WrongRoute==i+1?0x100:0);handled=1;break;}
   if(at==0xc42d000+G99Targets[i].Apid*4){*out=G99Targets[i].Owner^(m->WrongOwner==i+1?1:0);handled=1;break;}
  }
  if(!handled){int i=Index(at);assert(i>=0);uint32_t off=at-G99Base((unsigned)i);
   if(off==0)*out=m->Pending?0x08000007:m->LastCommand;else if(off==8){if(m->Pending&&!m->Active)*out=0;else if(m->Active){assert((unsigned)i==m->Target);m->Poll++;if(m->Timeout||m->Poll<=m->CompletionDelay)*out=0;else{*out=1|(m->Denied?2:0);m->Active=0;}}else*out=1;}
   else if(off==0x18||off==0x1c){assert(!m->Active);*out=m->Data[(off-0x18)/4];}else assert(0);
  }
 }
 return m->FailRead==m->Reads&&m->FailAfter?0:1;
}
static int W(void*x,uint32_t at,uint32_t v){Model*m=x;assert(G99WriteAllowed(at,v)&&!m->Active);m->Writes++;if(m->FailWrite==m->Writes&&!m->FailAfter)return 0;int i=Index(at);assert(i>=0);m->Target=(unsigned)i;m->Offset=(v>>4)&255;m->LastCommand=v;m->Active=1;m->Poll=0;uint8_t bytes[8]={0};
 if(m->Offset==0){memcpy(bytes,Ids[i],8);if(m->WrongId==(unsigned)i+1)bytes[i==0?0:i==3?4:5]^=1;}
 else if(m->Offset==0x40){memcpy(bytes,Config,8);if(m->ConfigChanged&&m->Configs)bytes[3]^=1;m->Configs++;}
 else{assert(m->Offset==0x10&&i>0);unsigned frame=m->Rts/3;if(i==1)bytes[0]=(frame%4)==1?3:0;if(i==2)bytes[0]=(frame%4)==1?0x80:(frame%4)==2?0x40:0;if(i==3)bytes[0]=(frame%4)==3?0:1;m->Rts++;}
 memcpy(m->Data,bytes,8);return m->FailWrite==m->Writes&&m->FailAfter?0:1;
}
static void U(void*x){Model*m=x;m->Waits++;m->Now++;}
static void M(void*x){Model*m=x;m->Now+=20000;}
static int A(void*x){Model*m=x;return !m->CancelAt||m->Reads<m->CancelAt;}
static uint64_t T(void*x){Model*m=x;m->TimeCalls++;if(m->ClockAt==m->TimeCalls)return 1;if(m->JumpAt==m->TimeCalls)m->Now+=G99_DEADLINE_US+1;return m->Now;}
static void Run(Model*m,unsigned n,G99_RESULT*r){m->Now=100;m->CompletionDelay=2;memset(r,0,sizeof(*r));G99_IO io={m,R,W,U,M,A,T};G99Sample(&io,n,r);assert(r->Reads==m->Reads&&r->Writes==m->Writes&&r->Commands<=r->Writes&&r->Reads<=G99_MAX_READS&&r->TraceCount<=G99_MAX_COMMANDS&&r->SampleCount<=n);Cases++;}
int main(void){G99_RESULT*r=calloc(1,sizeof(*r));assert(r);Model baseline={0};Run(&baseline,4,r);assert(!r->Code);unsigned reads=baseline.Reads,writes=baseline.Writes;
 for(unsigned n=1;n<=G99_MAX_SAMPLES;n++){Model m={0};Run(&m,n,r);assert(!r->Code&&r->SampleCount==n&&r->Commands==6+3*n&&r->PostRoutesVerified&&m.Configs==2&&!memcmp(r->GpioBefore,r->GpioAfter,8));for(unsigned k=0;k<r->TraceCount;k++)assert(r->Trace[k].Flags==63);for(unsigned k=0;k<n;k++){assert(r->Samples[k].Raw[0]==(k%4==1?3:0));assert(r->Samples[k].Raw[1]==(k%4==1?0x80:k%4==2?0x40:0));assert(r->Samples[k].Raw[2]==(k%4==3?0:1));if(k)assert(r->Samples[k].AtUs-r->Samples[k-1].AtUs>=20000);}}
 for(unsigned after=0;after<2;after++)for(unsigned i=1;i<=reads;i++){Model m={0};m.FailRead=i;m.FailAfter=after;Run(&m,4,r);assert(r->Code&&m.Reads==i);}
 for(unsigned after=0;after<2;after++)for(unsigned i=1;i<=writes;i++){Model m={0};m.FailWrite=i;m.FailAfter=after;Run(&m,4,r);assert(r->Code&&m.Writes==i);}
 for(unsigned i=1;i<=4;i++){
  Model m={0};m.WrongRoute=i;Run(&m,1,r);assert(r->Code==G99_ROUTE&&m.Writes==i-1);
  memset(&m,0,sizeof(m));m.WrongOwner=i;Run(&m,1,r);assert(r->Code==G99_ROUTE&&m.Writes==i-1);
  memset(&m,0,sizeof(m));m.WrongId=i;Run(&m,1,r);assert(r->Code==G99_IDENTITY&&m.Writes==i);
 }
 for(unsigned n=0;n<2;n++){Model m={0};Run(&m,n?1025:0,r);assert(r->Code==G99_ARGUMENT&&!m.Reads&&!m.Writes);}
 for(unsigned n=1;n<=reads;n++){Model m={0};m.CancelAt=n;Run(&m,4,r);assert(r->Code==G99_CANCELLED&&r->Cancelled);}
 {Model m={0};m.InvalidArb=1;Run(&m,1,r);assert(r->Code==G99_ARBITER&&!m.Writes);}
 {Model m={0};m.Pending=1;Run(&m,1,r);assert(r->Code==G99_PENDING&&!m.Writes);}
 {Model m={0};m.Timeout=1;Run(&m,1,r);assert(r->Code==G99_TIMEOUT&&m.Writes==1&&r->Polls==12);}
 {Model m={0};m.Denied=1;Run(&m,1,r);assert(r->Code==G99_COMPLETION&&m.Writes==1&&!(r->Trace[0].Flags&G99_DATA));}
 {Model m={0};m.ConfigChanged=1;Run(&m,1,r);assert(r->Code==G99_CONFIG_CHANGED&&!r->PostRoutesVerified);}
 for(unsigned i=2;i<30;i++){Model m={0};m.ClockAt=i;Run(&m,1,r);if(i<=m.TimeCalls)assert(r->Code==G99_CLOCK);m=(Model){0};m.JumpAt=i;Run(&m,1,r);if(i<=m.TimeCalls)assert(r->Code==G99_DEADLINE);}
 unsigned allowed=0;for(uint32_t at=0xc400000;at<0xc448000;at++)for(unsigned j=0;j<4;j++){uint32_t v=(uint32_t[]){0x08000007,0x08000100,0x08000407,0x07000100}[j];int yes=G99WriteAllowed(at,v);if(yes)allowed++;if(at==0xc440ea0||at==0xc441220||at==0xc4456e0)assert(!yes);}assert(allowed==8);Cases++;
 for(unsigned i=0;i<4;i++)for(unsigned bit=0;bit<32;bit++)assert(G99WriteAllowed(G99Base(i),0x08000007u^(1u<<bit))==(i==3&&bit==10));Cases++;
 printf("{\"passed\":true,\"cases\":%u,\"max_samples\":1024,\"every_read_write_fault_position\":true,\"modeled_MMIO\":true,\"shared_observer_state_model\":true,\"native_operations\":0,\"touch_APIDs_excluded\":true}\n",Cases);free(r);return 0;}
