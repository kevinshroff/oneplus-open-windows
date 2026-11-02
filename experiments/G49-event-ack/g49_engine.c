/* SPDX-License-Identifier: MIT
 * Fixed primary GENI SPI configuration/readback/undo, while touch is off.
 * Values follow the pinned OnePlus spi-msm-geni and qcom-geni-se sources.
 * A source-0, non-MND 19.2 MHz root is required, never assumed from CFG alone.
 */
#include "g49_engine.h"
typedef struct {uint32_t Offset,Mask,Value;} Field;
static const Field Fields[G49_ENGINE_FIELDS]={
 {0xe1c,0xffffffff,0},{0xe18,0xffffffff,0},
 {0x28,0x7f,0x7f},{0x24,0xffffffff,0x7f},
 {0x224,1,0},{0x230,4,0},{0x22c,3,0},{0x250,15,0},
 {0x24c,1,0},{0x254,3,0},{0x258,1,0},{0x25c,1,0},
 {0x260,0xffffffff,0x7f8fe},{0x264,0xffffffff,0xffefe},
 {0x268,0x3ff,4},{0x278,0xffffffff,0},
 {0x284,0xffffffff,0x7f8fe},{0x288,0xffffffff,0xffefe},
 {0x7c,0xffffffff,0},{0x48,0xffffffff,0x141},
 {0x80c,0x3f,0},{0x810,0x3f,0},{0x814,0x3f,14},
 {0x614,0x4c000001,0x4c000001}
};
static const uint32_t Guards[10]={0xa90040,0xa90610,0xa90640,0xa90800,0xa90804,
 0x17100130,0x17100230,0x17100330,0x17100c60,0xa90064};
static const uint32_t Masks[10]={0x1001,0xffffff7f,0xffffffff,0x0fffffff,0x81ffffff,
 0x20,0x20,0x20,0xc00,1};
int G49EngineWriteAddress(uint32_t at)
{
 unsigned i;for(i=0;i<G49_ENGINE_FIELDS;i++)if(at==0xa90000+Fields[i].Offset)return 1;return 0;
}
static int Event(G49_ENGINE_RESULT*r,uint32_t kind,uint32_t at,uint32_t v)
{
 G49_ENGINE_EVENT*e;if(r->TraceCount>=G49_ENGINE_TRACE)return 0;
 e=&r->Trace[r->TraceCount++];e->Kind=kind;e->Address=at;e->Value=v;return 1;
}
static int Read(const G49_ENGINE_IO*io,G49_ENGINE_RESULT*r,uint32_t at,uint32_t*v)
{
 if(r->Reads>=320||r->TraceCount>=G49_ENGINE_TRACE)return 0;r->Reads++;
 if(!io->Read(io->Context,at,v)){Event(r,3,at,0);return 0;}return Event(r,1,at,*v);
}
static int Write(const G49_ENGINE_IO*io,G49_ENGINE_RESULT*r,uint32_t at,uint32_t v)
{
 if(r->Writes>=48||!G49EngineWriteAddress(at)||r->TraceCount>=G49_ENGINE_TRACE)return 0;
 r->Writes++;if(!Event(r,2,at,v))return 0;return io->Write(io->Context,at,v);
}
static int Guard(const G49_ENGINE_IO*io,G49_ENGINE_RESULT*r,uint32_t*out)
{
 unsigned i;uint32_t enabled;for(i=0;i<10;i++)if(!Read(io,r,Guards[i],&out[i])||(out[i]&Masks[i]))return 0;
 if(!Read(io,r,0xa90614,&enabled)||(enabled&0x80u))return 0;return 1;
}
static int Snapshot(const G49_ENGINE_IO*io,G49_ENGINE_RESULT*r,uint32_t*out)
{
 unsigned i;for(i=0;i<G49_ENGINE_FIELDS;i++)if(!Read(io,r,0xa90000+Fields[i].Offset,&out[i]))return 0;return 1;
}
static int Dfs(const G49_ENGINE_IO*io,G49_ENGINE_RESULT*r,uint32_t*out)
{
 unsigned i;if(!Read(io,r,0x118504,out))return 0;
 for(i=0;i<8;i++){
  if(!Read(io,r,0x11850c+i*4,&out[1+i])||
   !Read(io,r,0x11854c+i*4,&out[9+i])||!Read(io,r,0x11858c+i*4,&out[17+i]))return 0;
 }
 return 1;
}
static int XoRate(uint32_t cfg)
{
 /* Source selector0, mode0, HID0/1 only. HW_CLK_CTRL may be set. */
 return (cfg&~0x10001fu)==0&&(cfg&0x1f)<=1;
}
static int Select(const G49_ENGINE_IO*io,G49_ENGINE_RESULT*r)
{
 unsigned i;uint32_t cfg;
 if(r->Before[18]&~7u)return 0;
 if(r->DfsBefore[0]&1){
  uint32_t level=(r->DfsBefore[0]>>1)&15;
  if(level>=8||level!=r->Before[18])return 0;
  for(i=0;i<8;i++)if(XoRate(r->DfsBefore[1+i])){r->Index=i;break;}
  if(i==8)return 0;
 }else{
  if(!Read(io,r,0x1184f4,&cfg)||!XoRate(cfg))return 0;r->Index=0;
 }
 r->SourceHz=19200000;r->BusHz=r->SourceHz/20;return 1;
}
static uint32_t Desired(G49_ENGINE_RESULT*r,unsigned i)
{
 return i==18?r->Index:(r->Before[i]&~Fields[i].Mask)|Fields[i].Value;
}
static int Restore(const G49_ENGINE_IO*io,G49_ENGINE_RESULT*r)
{
 int i;uint32_t now;unsigned n;
 r->Stage=90;
 if(!Guard(io,r,r->GuardAfter)){r->RestoreError=1;return 0;}
 for(i=(int)G49_ENGINE_FIELDS-1;i>=0;i--)if(r->Dirty&(1u<<i)){
  uint32_t at=0xa90000+Fields[i].Offset;
  if(!Read(io,r,at,&now)){r->RestoreError=2;return 0;}
  if(now!=r->Before[i]&&now!=Desired(r,(unsigned)i)){r->RestoreError=3;return 0;}
  if(now!=r->Before[i]){
   int written=Write(io,r,at,r->Before[i]);
   if(!Read(io,r,at,&now)||now!=r->Before[i]){r->RestoreError=4;return 0;}
   if(!written&&r->Code==0)r->Code=9;
  }
 }
 io->WaitMicrosecond(io->Context);
 if(r->DfsBefore[0]&1){
  for(n=0;n<8;n++){
   if(!Read(io,r,0x118504,&now)){r->RestoreError=9;return 0;}
   if(((now>>1)&15)==((r->DfsBefore[0]>>1)&15))break;
   if(n<7)io->WaitMicrosecond(io->Context);
  }
  if(n==8){r->RestoreError=10;return 0;}
 }
 if(!Snapshot(io,r,r->After)||!Dfs(io,r,r->DfsAfter)){r->RestoreError=5;return 0;}
 for(n=0;n<G49_ENGINE_FIELDS;n++)if(r->Before[n]!=r->After[n]){r->RestoreError=6;return 0;}
 for(n=0;n<25;n++)if(r->DfsBefore[n]!=r->DfsAfter[n]){r->RestoreError=7;return 0;}
 if(!Guard(io,r,r->GuardAfter)){r->RestoreError=8;return 0;}
 r->Restored=1;return 1;
}
void G49ConfigureEngine(const G49_ENGINE_IO*io,G49_ENGINE_RESULT*r)
{
 unsigned i;uint32_t now;
 r->Stage=1;
 if(!Guard(io,r,r->GuardBefore)||!Snapshot(io,r,r->Before)||!Dfs(io,r,r->DfsBefore)){r->Code=1;return;}
 if(!Select(io,r)){r->Code=2;return;}
 r->Stage=2;
 for(i=0;i<G49_ENGINE_FIELDS;i++){
  uint32_t at=0xa90000+Fields[i].Offset,v=Desired(r,i);
  if(!Read(io,r,at,&now)||now!=r->Before[i]){r->Code=3;goto done;}
  if(v==now)continue;
  r->Dirty|=1u<<i;
  if(!Write(io,r,at,v)||!Read(io,r,at,&now)||now!=v){r->Code=4;goto done;}
 }
 r->Stage=3;
 if(r->DfsBefore[0]&1){
  for(i=0;i<8;i++){
   if(!Read(io,r,0x118504,&now)){r->Code=5;goto done;}
   if(((now>>1)&15)==r->Index)break;
   if(i<7)io->WaitMicrosecond(io->Context);
  }
  if(i==8){r->Code=6;goto done;}
 }
 if(!Snapshot(io,r,r->During)){r->Code=7;goto done;}
 for(i=0;i<G49_ENGINE_FIELDS;i++)if(r->During[i]!=Desired(r,i)){r->Code=8;goto done;}
 if(io->Transfer){
  int result=io->Transfer(io->Context);
  if(result<=0)r->Code=10;
  if(result<0){r->RestoreError=11;return;}
 }
 done:
 Restore(io,r);if(r->Code==0&&r->Restored)r->Stage=0;
}
