/* SPDX-License-Identifier: MIT
 * Only SPMI READ opcodes, on fixed channels disjoint from G100's observer set.
 * No PMIC writes, RW channel, reset, charging/profile or interrupt-clear write.
 */
#include "g186_core.h"
static int Fail(G186_RESULT*r,unsigned code){if(!r->Code)r->Code=code;return 0;}
static int Read(const G186_IO*io,G186_RESULT*r,uint32_t at,uint32_t*v){if(r->Code||r->Reads>=G186_READ_LIMIT||!G186ReadAllowed(at))return Fail(r,G186_BUDGET);r->Reads++;return io->Read(io->Context,at,v)?1:Fail(r,G186_IO_ERROR);}
static int Guard(const G186_IO*io,G186_RESULT*r){
 uint64_t now;if(!io->Available(io->Context)){r->Cancelled=1;return Fail(r,G186_CANCELLED);}now=io->NowUs(io->Context);
 if(now<r->BeginUs||now<r->EndUs)return Fail(r,G186_CLOCK);r->EndUs=now;return now-r->BeginUs<=1000000?1:Fail(r,G186_DEADLINE);
}
static int Route(const G186_IO*io,G186_RESULT*r,unsigned i){uint32_t map,owner;return Read(io,r,0xc402000+G186Targets[i].Apid*4,&map)&&Read(io,r,0xc42d000+G186Targets[i].Apid*4,&owner)&&(map==G186Targets[i].Map&&owner==G186Targets[i].Owner?1:Fail(r,G186_ROUTE));}
static int Version(const G186_IO*io,G186_RESULT*r){uint32_t a,b,c;return Read(io,r,0xc400000,&a)&&Read(io,r,0xc400004,&b)&&Read(io,r,0xc400008,&c)&&(a==0x70000001&&b==0x80040300&&c==0x100?1:Fail(r,G186_ARBITER));}
static int Transaction(const G186_IO*io,G186_RESULT*r,unsigned index){
 const G186_QUERY*q=G186Queries+index;G186_TRACE*t;uint32_t base=G186Base(q->Target),command;unsigned j;
 if(!Guard(io,r))return 0;r->Stage=100+index;t=r->Trace+r->TraceCount++;t->Target=q->Target;t->Offset=q->Offset;t->Bytes=q->Bytes;
 if(!Route(io,r,q->Target))return 0;t->Flags|=G186_ROUTE_OK;
 if(!Read(io,r,base+8,&t->BeforeStatus)||!Read(io,r,base,&t->BeforeCommand))return 0;
 if(!(t->BeforeStatus&1)&&t->BeforeCommand)return Fail(r,G186_PENDING);t->Flags|=G186_PREVIOUS_IDLE;
 if(!Guard(io,r))return 0;command=0x08000000u|(q->Offset<<4)|(q->Bytes-1);
 if(!G186WriteAllowed(base,command)||r->Writes>=G186_STEPS)return Fail(r,G186_BUDGET);
 t->Flags|=G186_ATTEMPTED;r->Writes++;if(!io->Write(io->Context,base,command))return Fail(r,G186_IO_ERROR);t->Flags|=G186_WRITTEN;r->Commands++;
 /* Finish an issued READ despite cancellation; never issue another afterward. */
 for(j=0;j<64;j++){r->Polls++;if(!Read(io,r,base+8,&t->Completion))return 0;if(t->Completion&1)break;if(j<63)io->WaitUs(io->Context);}
 if(!(t->Completion&1))return Fail(r,G186_TIMEOUT);t->Flags|=G186_DONE;
 if(t->Completion&0xe)return Fail(r,G186_COMPLETION);
 if(!Read(io,r,base+0x18,&t->Data0)||(q->Bytes>4&&!Read(io,r,base+0x1c,&t->Data1)))return 0;
 for(j=0;j<q->Bytes;j++)r->Values[index][j]=(uint8_t)((j<4?t->Data0:t->Data1)>>((j%4)*8));t->Flags|=G186_DATA;return 1;
}
void G186Observe(const G186_IO*io,G186_RESULT*r){
 unsigned i;r->Size=sizeof(*r);if(!io||!io->Read||!io->Write||!io->WaitUs||!io->WaitInterval||!io->Available||!io->NowUs){Fail(r,G186_ARGUMENT);return;}
 r->BeginUs=r->EndUs=io->NowUs(io->Context);if(!Guard(io,r)||!Version(io,r))goto done;
 for(i=0;i<G186_STEPS;i++){
  if(i==G186_STEPS-1)io->WaitInterval(io->Context);
  if(!Transaction(io,r,i))goto done;
  if(i<3&&(r->Values[i][4]!=0x10||r->Values[i][5]<0x10||r->Values[i][5]>0x13)){Fail(r,G186_IDENTITY);goto done;}
 }
 for(i=0;i<G186_TARGETS;i++)if(!Route(io,r,i))goto done;
 if(!Version(io,r)||!Guard(io,r))goto done;r->PostRoutesVerified=1;r->Stage=0;
 done:{uint64_t now=io->NowUs(io->Context);if(now<r->BeginUs||now<r->EndUs)Fail(r,G186_CLOCK);else r->EndUs=now;if(now>=r->BeginUs&&now-r->BeginUs>1000000)Fail(r,G186_DEADLINE);}
}
