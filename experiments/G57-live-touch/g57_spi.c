/* SPDX-License-Identifier: MIT
 * Primary SPI clock/pad preparation and undo. All writes are fixed.
 * Pads follow source mux1/6mA/pulldown; clocks follow G24's qualified votes.
 */
#include "g57_spi.h"
static const uint32_t Clock[6]={0x152008,0x1184e4,0x1184f0,0x1184f4,0x12327c,0x123280};
static const uint32_t ClockBaseline[6]={0x40002380,0x80004000,0x80000000,0x100000,0,0x80000002};
static const uint32_t Stages[3]={0x100000,0x200000,0x4000000};
static const uint32_t Ident[7]={0xac0004,0xa90040,0xa90064,0xa90068,0xa9006c,0xa90e24,0xa90e28};
static int Event(G57_SPI_RESULT*r,uint32_t kind,uint32_t at,uint32_t value)
{
 G57_SPI_EVENT*e;if(r->TraceCount>=128)return 0;e=&r->Trace[r->TraceCount++];e->Kind=kind;e->Address=at;e->Value=value;return 1;
}
static int Read(const G57_SPI_IO*io,G57_SPI_RESULT*r,uint32_t at,uint32_t*v)
{
 if(r->Reads>=112||r->TraceCount>=128)return 0;r->Reads++;
 if(!io->Read(io->Context,at,v)){Event(r,3,at,0);return 0;}return Event(r,1,at,*v);
}
static int Write(const G57_SPI_IO*io,G57_SPI_RESULT*r,uint32_t at,uint32_t v)
{
 int pad=at>=0xf12c000&&at<=0xf12f000&&(at&0xfff)==0;
 int vote=at==0x152008&&(v==0x40002380||v==0x40102380||v==0x40302380||v==0x44302380);
 if(r->Writes>=14||!((pad&&(v==1||v==0x85))||vote))return 0;
 r->Writes++;if(!Event(r,2,at,v))return 0;return io->Write(io->Context,at,v);
}
static int ReadPins(const G57_SPI_IO*io,G57_SPI_RESULT*r,uint32_t*out,int baseline)
{
 unsigned p,i;
 for(p=0;p<4;p++)for(i=0;i<4;i++){
  if(!Read(io,r,0xf12c000+p*0x1000+i*4,&out[p*4+i]))return 0;
  if(baseline&&out[p*4+i]!=(i==0?1u:i==2?0xe2u:0u))return 0;
 }
 return 1;
}
static int ReadClock(const G57_SPI_IO*io,G57_SPI_RESULT*r,uint32_t*out,int baseline)
{
 unsigned i;for(i=0;i<6;i++){if(!Read(io,r,Clock[i],&out[i]))return 0;if(baseline&&out[i]!=ClockBaseline[i])return 0;}return 1;
}
static int Restore(const G57_SPI_IO*io,G57_SPI_RESULT*r)
{
 int p,i;uint32_t now,v;int pins_ok=1;
 r->Stage=90;
 for(p=3;p>=0;p--)if(r->DirtyPins&(1u<<p)){
  uint32_t at=0xf12c000+(uint32_t)p*0x1000;
  if(!Read(io,r,at,&now)){pins_ok=0;continue;}
  if(now!=1&&now!=0x85){pins_ok=0;continue;}
  if(now!=1){
   int written=Write(io,r,at,1);
   /* An ambiguous callback is never replayed; a separate read proves outcome. */
   if(!Read(io,r,at,&now)||now!=1){pins_ok=0;continue;}
   if(!written&&r->Code==0)r->Code=11;
  }
 }
 io->WaitMicrosecond(io->Context);
 if(!ReadPins(io,r,r->AfterPins,1))pins_ok=0;
 if(!pins_ok){r->RestoreError=1;return 0;}
 r->Stage=91;
 if(r->VoteDirty){
  if(!Read(io,r,0x152008,&now)){r->RestoreError=2;return 0;}
  if((now&~0x4300000u)!=ClockBaseline[0]){r->RestoreError=3;return 0;}
  for(i=2;i>=0;i--){
   v=now&~Stages[i];
   if(v!=now){
    int written=Write(io,r,0x152008,v);
    if(!Read(io,r,0x152008,&now)||now!=v){r->RestoreError=4;return 0;}
    if(!written&&r->Code==0)r->Code=11;
   }
  }
 }
 if(!ReadClock(io,r,r->AfterClock,1)){r->RestoreError=5;return 0;}
 r->Restored=1;return 1;
}
void G57PrepareSpi(const G57_SPI_IO*io,G57_SPI_RESULT*r)
{
 unsigned i,p;uint32_t now,clock;int dirty=0;
 r->Stage=1;
 if(!ReadClock(io,r,r->BeforeClock,1)||!ReadPins(io,r,r->BeforePins,1)){r->Code=1;return;}
 now=r->BeforeClock[0];r->Stage=2;
 for(i=0;i<3;i++){
  dirty=1;r->VoteDirty=1;now|=Stages[i];
  if(!Write(io,r,0x152008,now)||!Read(io,r,0x152008,&clock)||clock!=now){r->Code=2;goto done;}
 }
 r->VoteEnabled=now;r->Stage=3;
 for(i=0;i<8;i++){if(!Read(io,r,0x1184e4,&clock)){r->Code=3;goto done;}if(!(clock&0x80000000))break;if(i+1<8)io->WaitMicrosecond(io->Context);}
 if(clock&0x80000000){r->Code=4;goto done;}
 for(i=0;i<7;i++)if(!Read(io,r,Ident[i],&r->Identity[i])){r->Code=5;goto done;}
 r->Identity[7]=clock;
 if(r->Identity[0]!=0x30090000||r->Identity[1]!=0||r->Identity[2]!=0||r->Identity[3]!=0x102||r->Identity[4]!=0x102||r->Identity[5]!=0x20102864||r->Identity[6]!=0x20104800){r->Code=6;goto done;}
 r->Stage=4;
 for(p=0;p<4;p++){
  uint32_t at=0xf12c000+p*0x1000;
  /* Baseline excludes EGPIO/remote ownership, OE and interrupt use. */
  if(!Read(io,r,at,&clock)||clock!=1){r->Code=7;goto done;}
  r->DirtyPins|=1u<<p;
  if(!Write(io,r,at,0x85)||!Read(io,r,at,&clock)||clock!=0x85){r->Code=8;goto done;}
 }
 io->WaitMicrosecond(io->Context);r->Stage=5;
 if(!ReadPins(io,r,r->DuringPins,0)){r->Code=9;goto done;}
 for(p=0;p<4;p++)if(r->DuringPins[p*4]!=0x85||r->DuringPins[p*4+2]!=0xe2||r->DuringPins[p*4+3]!=0||(r->DuringPins[p*4+1]&~1u)){r->Code=10;goto done;}
 {
  G57_ENGINE_IO engine={io->Context,io->Read,io->Write,io->WaitMicrosecond,io->Transfer};
  G57ConfigureEngine(&engine,&r->Engine);
  if(r->Engine.Code||!r->Engine.Restored){
   r->Code=12;
   /* No clock/pad undo while a changed engine state is unproven. */
   if(r->Engine.RestoreError||(r->Engine.Dirty&&!r->Engine.Restored)){r->RestoreError=6;return;}
  }
 }
 done:
 if(dirty)Restore(io,r);
 if(r->Restored&&r->Code==0)r->Stage=0;
}
