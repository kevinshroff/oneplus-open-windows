/* SPDX-License-Identifier: MIT. Fixed read-only gauge query selectors only. */
#include "g103_core.h"
#include "g103_policy.h"
#include <stddef.h>
typedef struct{const G103_IO*IO;G103_RESULT*R;unsigned I,Issued,Touched,InCleanup;}Run;
static int Fail(Run*c,uint32_t code){if(!c->R->Code)c->R->Code=code;return 0;}
static void Event(Run*c,uint32_t k,uint32_t at,uint32_t v){G103_RESULT*r=c->R;if(r->TraceCount<G103_TRACE)r->Trace[r->TraceCount++]=(G103_EVENT){k,at,v,r->Commands};else r->TraceDropped++;}
static int Limit(Run*c){
 uint64_t t=c->IO->NowUs(c->IO->Context);if(!c->InCleanup&&(t<c->R->BeginUs||t<c->R->EndUs||t-c->R->BeginUs>2000000))return Fail(c,G103_TIME_ERROR);c->R->EndUs=t;
 if(c->R->TraceCount>=G103_TRACE-(c->InCleanup?0u:4096u))return Fail(c,G103_LIMIT);return 1;
}
static int Read(Run*c,uint32_t o,uint32_t*v){
 uint32_t at=G102Controllers[c->I].Base+o;if(!Limit(c)||!G103ReadAllowed(at))return Fail(c,G103_LIMIT);
 c->R->Reads++;if(!c->IO->Read(c->IO->Context,at,v))return Fail(c,G103_IO_ERROR);Event(c,1,at,*v);return 1;
}
static int Write(Run*c,uint32_t o,uint32_t v){
 uint32_t at=G102Controllers[c->I].Base+o;if(!Limit(c)||c->R->Writes>=256)return Fail(c,G103_LIMIT);
 c->R->Writes++;if(!c->IO->Write(c->IO->Context,at,v))return Fail(c,G103_IO_ERROR);Event(c,2,at,v);return 1;
}
static int Idle(Run*c,int bus){uint32_t s,t,r,ios;return Read(c,0x40,&s)&&Read(c,0x800,&t)&&Read(c,0x804,&r)&&Read(c,0x908,&ios)&&!s&&!t&&!r&&(!bus||(ios&3)==3);}
static int Ack(Run*c,uint32_t stat){uint32_t v=stat&G103_OWNED_IRQ;return !v||Write(c,0x618,v);}
static int Fixed(Run*c){
 static const uint32_t off[]={0x68,0x6c,0x64,0x258,0x254,0x260,0x264,0x284,0x288,0x48,0x7c,0x278,0x614,0x644,0x810,0x814};
 static const uint32_t val[]={0x303,0x303,0,0,0,0x7f8fe,0xffefe,0x7f8fe,0xffefe,0x71,0,0xa02c1a,0x33c0007e,0x03001e36,13,14};
 uint32_t v;for(unsigned j=0;j<sizeof(off)/sizeof(off[0]);j++)if(!Read(c,off[j],&v)||v!=val[j])return Fail(c,G103_PREFLIGHT);return 1;
}
static int Clean(Run*c){
 uint32_t main;if(!Idle(c,1))return 0;if(!Read(c,0x610,&main)||!Ack(c,main))return 0;
 if(!Read(c,0x610,&main)||(main&G103_OWNED_IRQ)||!Idle(c,1))return 0;c->Issued=0;c->R->CleanMask|=1u<<c->I;return 1;
}
static int Quiesce(Run*c){
 c->InCleanup=1;if(Clean(c))return 1;
 if(!c->Issued)return 0;
 if(!Write(c,0x80c,0)||!Write(c,0x604,4))return 0;c->R->Cancels++;
 for(unsigned attempt=0;attempt<2;attempt++){
  if(attempt){if(!Write(c,0x604,2))return 0;c->R->Aborts++;}
  for(unsigned j=0;j<256;j++){
   uint32_t main;if(!Read(c,0x610,&main))return 0;
   if((main&(attempt?0x20u:0x10u))&&Idle(c,1)&&Ack(c,main)&&Clean(c))return 1;
   c->IO->DelayUs(c->IO->Context,20);
  }
 }
 return 0;
}
static int Transfer(Run*c,unsigned kind,unsigned selector,uint32_t*out){
 uint32_t main,tx,rx,s,data=0;int fed=kind==2,received=0;
 if(!Fixed(c)||!Idle(c,kind!=2)||!Read(c,0x610,&main)||(main&G103_OWNED_IRQ))return Fail(c,G103_DIRTY);
 c->R->CleanMask&=~(1u<<c->I);c->Touched=1;
 if(!Write(c,kind==2?0x270:0x26c,kind==0?3u:kind==1?1u:2u))return 0;
 c->Issued=1;c->R->Commands++;
 if(!Write(c,0x600,kind==0?0x0800aa00u:kind==1?0x0800aa04u:0x1000aa00u))return 0;
 if(kind!=2&&!Write(c,0x80c,1))return 0;
 for(unsigned j=0;j<256;j++){
  if(!Read(c,0x610,&main)||!Read(c,0x800,&tx)||!Read(c,0x804,&rx))return 0;
  if(main&G103_ERROR_IRQ)return Fail(c,G103_BUS_ERROR);
  if(!fed&&(main&0x40000000u)){
   if(tx||!Write(c,0x700,kind==0?selector<<8:0)||!Write(c,0x80c,0))return Fail(c,G103_FIFO_ERROR);fed=1;
  }
  if(kind==2&&rx){
   if(received||rx!=0xa0000001u||!Read(c,0x780,&data))return Fail(c,G103_FIFO_ERROR);received=1;
  }else if(kind!=2&&rx)return Fail(c,G103_FIFO_ERROR);
  if(!Read(c,0x40,&s))return 0;
  if(main&1){
   if(!fed||(kind==2&&!received)||s||!Read(c,0x800,&tx)||!Read(c,0x804,&rx)||tx||rx)return Fail(c,G103_FIFO_ERROR);
   if(!Ack(c,main))return 0;c->R->Completed++;c->Issued=kind==1;
   if(kind!=1&&!Idle(c,1))return Fail(c,G103_DIRTY);
   if(out)*out=data&0xffff;return 1;
  }
  if(!Ack(c,main))return 0;c->IO->DelayUs(c->IO->Context,20);
 }
 return Fail(c,G103_TIMEOUT);
}
static int Restore(Run*c){
 uint32_t v;c->InCleanup=1;
 if(!Clean(c))return 0;
 if(c->Touched&&(!Write(c,0x26c,1)||!Write(c,0x270,2)||!Write(c,0x80c,0)))return 0;
 if(!Fixed(c)||!Read(c,0x26c,&v)||v!=1||!Read(c,0x270,&v)||v!=2||!Read(c,0x80c,&v)||v||!Clean(c))return 0;
 c->R->RestoredMask|=1u<<c->I;return 1;
}
static int SnapshotQualified(const G102_RESULT*r){
 static const unsigned index[]={0,1,2,3,4,5,6,7,8,9,10,11,12,15,16,19,20,21,22,23,24,25,27,28,30,31,32,33,34};
 static const uint32_t value[]={9,9,0x7f,0x7f,0,0x71,0,0,0x303,0x303,1,2,0xa02c1a,0,0,0,0,0,0x7f8fe,0xffefe,0x7f8fe,0xffefe,0,0x33c0007e,0,0x03001e36,0,13,14};
 for(unsigned i=0;i<2;i++){
  for(unsigned j=0;j<sizeof(index)/sizeof(index[0]);j++)if(r->Controller[i][index[j]]!=value[j])return 0;
  if((r->Controller[i][13]&G103_OWNED_IRQ)||(r->Controller[i][35]&3)!=3)return 0;
  for(unsigned j=0;j<2;j++)if(r->PinsBefore[2*i+j][0]!=((G102Controllers[i].Mux[j]<<2)|3))return 0;
 }return 1;
}
void G103Identify(const G103_IO*io,G103_RESULT*r){
 Run c={io,r,0,0,0,0};if(!r)return;r->Size=sizeof(*r);
 if(!io||!io->Read||!io->Write||!io->Available||!io->NowUs||!io->DelayUs){r->Code=G103_ARGUMENT;return;}
 r->BeginUs=r->EndUs=io->NowUs(io->Context);r->Stage=1;
 G102_IO probe={io->Context,io->Read,io->Available,io->NowUs};G102Probe(&probe,&r->Before);
 if(r->Before.Code||r->Before.ReadyMask!=3||r->Before.PostClockMask!=3||r->Before.PinStableMask!=15||!SnapshotQualified(&r->Before)){Fail(&c,G103_PREFLIGHT);goto done;}
 for(c.I=0;c.I<2;c.I++){
  c.Touched=0;c.InCleanup=0;c.Issued=0;r->Stage=10+c.I;
  if(!Fixed(&c)||!Idle(&c,1)){Fail(&c,G103_PREFLIGHT);goto bad;}
  for(unsigned selector=0;selector<3;selector++){
   r->Stage=100+10*c.I+selector;
   if(!io->Available(io->Context)){r->Cancelled=1;Fail(&c,G103_CANCELLED);goto bad;}
   if(!Transfer(&c,0,selector,NULL))goto bad;
   for(unsigned d=0;d<5;d++)io->DelayUs(io->Context,20);
   if(!io->Available(io->Context)){r->Cancelled=1;Fail(&c,G103_CANCELLED);goto bad;}
   /* Once the pointer is issued, finish its repeated-start READ even if the
    * client cancels; leaving a stretched bus is not a cancellation strategy. */
   if(!Transfer(&c,1,selector,NULL)||!Transfer(&c,2,selector,&r->Values[c.I][selector]))goto bad;
   r->QueryMask|=1u<<(3*c.I+selector);
  }
  if(!Restore(&c)){Fail(&c,G103_RESTORE);goto bad;}continue;
  bad:if((c.Touched||c.Issued)&&(!Quiesce(&c)||!Restore(&c)))r->Uncertain|=1u<<c.I;goto done;
 }
 done:r->Stage=r->Code?r->Stage:0;
 if(!r->Uncertain){G102Probe(&probe,&r->After);if(r->After.Code||r->After.ReadyMask!=3||r->After.PostClockMask!=3||r->After.PinStableMask!=15)Fail(&c,G103_RESTORE);}
 r->EndUs=io->NowUs(io->Context);if(r->EndUs<r->BeginUs)Fail(&c,G103_TIME_ERROR);
}
