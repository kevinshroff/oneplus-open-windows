/* Actual core/policy execute with explicit register, time and bus models. */
#include "g103_policy.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static const uint32_t Pages[]={0x152000,0x11e000,0x117000,0x123000,0xf100000,0xf101000,0xf116000,0xf117000,0x880000,0x8c0000,0x98c000,0x9c0000};
typedef struct{
 uint32_t Memory[12][1024];G103_POLICY Policy;
 unsigned Reads,Writes,FailRead,FailWrite,CancelAt,ErrorCmd,TimeoutCmd,NoCancel,NoAbort,BadRX,Selectors[2],Fed[2],Waiting[2],Kind[2],CMDCount;
 uint64_t Now;
}Model;
static unsigned Cases;
static uint32_t*At(Model*m,uint32_t at){for(unsigned i=0;i<12;i++)if(at>=Pages[i]&&at-Pages[i]<4096)return&m->Memory[i][(at-Pages[i])/4];assert(0);return NULL;}
static void Put(Model*m,unsigned i,unsigned o,uint32_t v){*At(m,G102Controllers[i].Base+o)=v;}
static int Read(void*x,uint32_t at,uint32_t*v){
 Model*m=x;assert(G103ReadAllowed(at));m->Reads++;if(m->Reads==m->FailRead)return 0;
 int i=G103Controller(at);unsigned o=i>=0?at-G102Controllers[i].Base:0;
 if(i>=0&&o==0x610&&m->Waiting[i]){
  if(m->CMDCount==m->ErrorCmd){Put(m,i,0x610,0x480);Put(m,i,0x40,0);Put(m,i,0x908,7);m->Waiting[i]=0;}
  else if(m->CMDCount!=m->TimeoutCmd){
   if(m->Kind[i]!=2&&!m->Fed[i])Put(m,i,0x610,0x40000080);
   else{
    Put(m,i,0x610,0x81|(m->Kind[i]==2?0x08000000:0));Put(m,i,0x40,0);Put(m,i,0x908,m->Kind[i]==1?1:7);
    if(m->Kind[i]==2)Put(m,i,0x804,m->BadRX?0xb0000001:0xa0000001);m->Waiting[i]=0;
   }
  }
 }
 if(i>=0&&o==0x780){
  assert(G103ReceiveAllowed(&m->Policy,(unsigned)i));
  *v=0xa55a0000u|(m->Selectors[i]==0?0x4010u:m->Selectors[i]==1?(i?0x0603u:0x0602u):0x1234u+i);Put(m,i,0x804,0);
 }else *v=*At(m,at);
 if(i>=0)G103Observed(&m->Policy,(unsigned)i,o,*v);return 1;
}
static int Write(void*x,uint32_t at,uint32_t v){
 Model*m=x;int i=G103Controller(at);assert(i>=0);unsigned o=at-G102Controllers[i].Base;m->Writes++;if(m->Writes==m->FailWrite)return 0;
 assert(G103WriteAllowed(&m->Policy,(unsigned)i,o,v));
 if(o==0x600){m->Kind[i]=m->CMDCount%3;m->CMDCount++;m->Waiting[i]=1;m->Fed[i]=0;Put(m,i,0x40,1);Put(m,i,0x610,0x80);}
 if(o==0x700){m->Fed[i]=1;if(m->Kind[i]==0)m->Selectors[i]=v>>8;}
 if(o==0x604&&((v==4&&!m->NoCancel)||(v==2&&!m->NoAbort))){m->Waiting[i]=0;Put(m,i,0x40,0);Put(m,i,0x800,0);Put(m,i,0x804,0);Put(m,i,0x908,7);Put(m,i,0x610,0x80|(v==4?0x10:0x20));}
 if(o==0x618)*At(m,G102Controllers[i].Base+0x610)&=~v;
 else *At(m,at)=v;
 return 1;
}
static int Available(void*x){Model*m=x;return !m->CancelAt||m->Reads<m->CancelAt;}
static uint64_t Now(void*x){Model*m=x;return++m->Now;}
static void Delay(void*x,uint32_t us){assert(us==20);((Model*)x)->Now+=us;}
static void Reset(Model*m){
 memset(m,0,sizeof(*m));
 for(unsigned i=0;i<2;i++){
  const G102_CONTROLLER*c=G102Controllers+i;
  for(unsigned j=0;j<3;j++){*At(m,c->Clocks[j].Vote)|=c->Clocks[j].Mask;*At(m,c->Clocks[j].Cbcr)=c->Clocks[j].Hwcg?0x80000002:0;}
  *At(m,c->Root+4)=i?1:0x100001;
  for(unsigned j=0;j<2;j++){*At(m,0xf100000+c->Pins[j]*0x1000)=(c->Mux[j]<<2)|3;*At(m,0xf100004+c->Pins[j]*0x1000)=1;}
  const unsigned off[]={0,4,0x24,0x28,0x48,0x68,0x6c,0x26c,0x270,0x278,0x610,0x640,0xe24,0xe28,0x260,0x264,0x284,0x288,0x600,0x614,0x644,0x810,0x814,0x908};
  const uint32_t val[]={9,9,0x7f,0x7f,0x71,0x303,0x303,1,2,0xa02c1a,0x80,0x08000000,0x201029e4,0x20104800,0x7f8fe,0xffefe,0x7f8fe,0xffefe,0x1000aa00,0x33c0007e,0x03001e36,13,14,7};
  for(unsigned j=0;j<sizeof(off)/sizeof(off[0]);j++)Put(m,i,off[j],val[j]);Put(m,i,0x50,1);
 }*At(m,0x8c0004)=0x30090000;
}
static void Run(Model*m,G103_RESULT*r){
 memset(r,0,sizeof(*r));G103_IO io={m,Read,Write,Available,Now,Delay};G103Identify(&io,r);Cases++;
 assert(r->TraceCount<=G103_TRACE&&!r->TraceDropped);
 if(!r->Uncertain){
  for(unsigned i=0;i<2;i++)if(r->RestoredMask&(1u<<i)){
   assert(!*At(m,G102Controllers[i].Base+0x40)&&!*At(m,G102Controllers[i].Base+0x800)&&!*At(m,G102Controllers[i].Base+0x804));
   assert((*At(m,G102Controllers[i].Base+0x908)&3)==3&&*At(m,G102Controllers[i].Base+0x26c)==1&&*At(m,G102Controllers[i].Base+0x270)==2&&!*At(m,G102Controllers[i].Base+0x80c));
  }
 }
}
int main(void){
 Model*m=calloc(1,sizeof(*m));G103_RESULT*r=calloc(1,sizeof(*r));assert(m&&r);Reset(m);Run(m,r);
 assert(!r->Code&&!r->Uncertain&&r->Commands==18&&r->Completed==18&&r->QueryMask==63&&r->CleanMask==3&&r->RestoredMask==3&&m->Policy.Commands==18&&m->Policy.Completed==18&&!m->Policy.Active&&!m->Policy.Held);
 assert(r->Values[0][0]==0x4010&&r->Values[0][1]==0x0602&&r->Values[0][2]==0x1234&&r->Values[1][1]==0x0603);
 unsigned reads=m->Reads,writes=m->Writes;printf("baseline reads%u writes%u trace%u\n",reads,writes,r->TraceCount);
 for(unsigned n=1;n<=reads;n++){Reset(m);m->FailRead=n;Run(m,r);assert(r->Code&&m->Reads>=n);}
 for(unsigned n=1;n<=writes;n++){Reset(m);m->FailWrite=n;Run(m,r);assert(r->Code);}
 for(unsigned n=1;n<=reads;n+=3){Reset(m);m->CancelAt=n;Run(m,r);assert(r->Code||m->Reads<=n);assert(!r->Uncertain);}
 for(unsigned n=1;n<=18;n++){
  Reset(m);m->ErrorCmd=n;Run(m,r);assert(r->Code==G103_BUS_ERROR&&!r->Uncertain&&!m->Policy.Active&&!m->Policy.Held);
  Reset(m);m->TimeoutCmd=n;Run(m,r);assert(r->Code==G103_TIMEOUT&&!r->Uncertain&&r->Cancels==1&&!r->Aborts);
  Reset(m);m->TimeoutCmd=n;m->NoCancel=1;Run(m,r);assert(r->Code==G103_TIMEOUT&&!r->Uncertain&&r->Cancels==1&&r->Aborts==1);
  Reset(m);m->TimeoutCmd=n;m->NoCancel=m->NoAbort=1;Run(m,r);assert(r->Code==G103_TIMEOUT&&r->Uncertain);
 }
 Reset(m);m->BadRX=1;Run(m,r);assert(r->Code==G103_FIFO_ERROR&&!r->Uncertain&&r->Cancels==1);
 for(unsigned i=0;i<2;i++){Reset(m);Put(m,i,0x260,0);Run(m,r);assert(r->Code==G103_PREFLIGHT&&!r->Uncertain&&!m->Writes);}
 free(m);free(r);printf("{\"passed\":true,\"cases\":%u,\"every_read_and_write_failure\":true,\"hardware_time_clock_explicitly_modeled\":true,\"native_operations\":0}\n",Cases);return 0;
}
