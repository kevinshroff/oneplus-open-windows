/* SPDX-License-Identifier: MIT. This interface has no write callback. */
#include "g101_core.h"
static int Fail(G101_RESULT*r,uint32_t code){if(!r->Code)r->Code=code;return 0;}
static int Read(const G101_IO*io,G101_RESULT*r,uint32_t at,uint32_t*v){
 uint64_t now;if(r->Code)return 0;
 if(!G101ReadAllowed(at)||r->Reads>=G101_TRACE||r->TraceCount>=G101_TRACE)return Fail(r,G101_BUDGET);
 if(!io->Available(io->Context))return Fail(r,G101_CANCELLED);
 now=io->NowUs(io->Context);if(now<r->BeginUs||now<r->EndUs||now-r->BeginUs>2000000)return Fail(r,G101_TIME_ERROR);r->EndUs=now;
 r->Reads++;if(!io->Read(io->Context,at,v))return Fail(r,G101_IO_ERROR);
 r->Trace[r->TraceCount++]=(G101_EVENT){at,*v};return 1;
}
static int Clocks(const G101_IO*io,G101_RESULT*r,unsigned i,uint32_t*v){
 const G101_CONTROLLER*c=G101Controllers+i;
 for(unsigned j=0;j<3;j++)if(!Read(io,r,c->Clocks[j].Vote,v+2*j)||!Read(io,r,c->Clocks[j].Cbcr,v+2*j+1))return 0;
 return Read(io,r,c->Root,v+6)&&Read(io,r,c->Root+4,v+7);
}
static int Pins(const G101_IO*io,G101_RESULT*r,uint32_t v[4][2]){
 for(unsigned i=0;i<2;i++)for(unsigned j=0;j<2;j++){
  uint32_t base=0xf100000+G101Controllers[i].Pins[j]*0x1000;
  if(!Read(io,r,base,&v[2*i+j][0])||!Read(io,r,base+4,&v[2*i+j][1]))return 0;
 }
 return 1;
}
static int Guard(const G101_IO*io,G101_RESULT*r,unsigned i){
 uint32_t current[8];if(!Clocks(io,r,i,current))return 0;
 if(!G101ClockUsable(i,current)||current[7]!=r->Before[i][7])return Fail(r,G101_CLOCK_CHANGED);return 1;
}
void G101Probe(const G101_IO*io,G101_RESULT*r){
 unsigned i,j;if(!r)return;r->Size=sizeof(*r);
 if(!io||!io->Read||!io->Available||!io->NowUs){Fail(r,G101_ARGUMENT);return;}
 r->BeginUs=io->NowUs(io->Context);r->EndUs=r->BeginUs;r->Stage=1;
 for(i=0;i<2;i++)if(!Clocks(io,r,i,r->Before[i]))goto done;
 if(!Pins(io,r,r->PinsBefore))goto done;
 for(i=0;i<2;i++){
  r->Stage=10+i;if(!G101ClockUsable(i,r->Before[i]))continue;r->ReadyMask|=1u<<i;
  if(i==0&&(!Guard(io,r,i)||!Read(io,r,G101Controllers[i].Wrapper+4,r->Wrapper+i)))goto done;
  for(j=0;j<G101_OFFSETS;j++){uint32_t offset=G101Offset(i,j);if(offset==G101_SKIPPED)continue;if(!Guard(io,r,i)||!Read(io,r,G101Controllers[i].Base+offset,&r->Controller[i][j]))goto done;}
 }
 r->Stage=20;
 for(i=0;i<2;i++){
  if(!Clocks(io,r,i,r->After[i]))goto done;
  for(j=0;j<8;j++)if(r->After[i][j]!=r->Before[i][j])break;
  if(j==8)r->PostClockMask|=1u<<i;
 }
 if(!Pins(io,r,r->PinsAfter))goto done;
 for(i=0;i<4;i++)if(r->PinsBefore[i][0]==r->PinsAfter[i][0]&&r->PinsBefore[i][1]==r->PinsAfter[i][1])r->PinStableMask|=1u<<i;
 r->Stage=0;
 done:{uint64_t now=io->NowUs(io->Context);if(now<r->BeginUs||now<r->EndUs||now-r->BeginUs>2000000)Fail(r,G101_TIME_ERROR);r->EndUs=now;}
}
