/* SPDX-License-Identifier: MIT
 * Primary QUP1 clock votes only. Each attempted write has an independent
 * readback; an ambiguous write is never retried. Cleanup has its own reserved
 * budget and will not overwrite foreign vote bits or access removed hardware.
 */
#include "g70_clock.h"
const uint32_t G70PageBase[3]={0x118000,0x123000,0x152000};
const uint32_t G70RegisterPage[6]={2,0,0,0,1,1};
const uint32_t G70RegisterOffset[6]={8,0x4e4,0x4f0,0x4f4,0x27c,0x280};
static const uint32_t Baseline[6]={0x40002380,0x80004000,0x80000000,0x100000,0,0x80000002};
static const uint32_t Stage[3]={0x100000,0x200000,0x4000000};
static uint32_t U32(const uint8_t*p){return(uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
int G70ValidateResources(const uint8_t raw[3][20],const uint8_t tr[3][20],uint32_t index[3])
{
 uint32_t mask=0,i,j;
 if(!raw||!tr||!index)return 0;
 for(i=0;i<3;i++){
  const uint8_t *a=raw[i],*b=tr[i];
  if(a[0]!=3||a[1]!=1||a[2]||a[3]||b[0]!=3||b[1]!=1||b[2]||b[3])return 0;
  if(U32(a+8)||U32(b+8)||U32(a+12)!=0x1000||U32(b+12)!=0x1000||U32(a+16)||U32(b+16))return 0;
  if(U32(a+4)!=U32(b+4))return 0; /* This platform trial pins identity translation. */
  for(j=0;j<3&&U32(a+4)!=G70PageBase[j];j++){}
  if(j==3||(mask&(1u<<j)))return 0;
  index[j]=i;mask|=1u<<j;
 }
 return mask==7;
}
static int Event(G70_CLOCK_RESULT*r,uint32_t kind,uint32_t reg,uint32_t value)
{
 G70_EVENT*e;if(r->TraceCount==G70_EVENTS)return 0;e=&r->Trace[r->TraceCount++];e->Kind=kind;e->Register=reg;e->Value=value;e->Phase=r->Phase;return 1;
}
static int Available(const G70_CLOCK_IO*io,G70_CLOCK_RESULT*r)
{
 if(io->Available(io->Context))return 1;
 if(!r->Code)r->Code=6;Event(r,6,0,0);return 0;
}
static int Read(const G70_CLOCK_IO*io,G70_CLOCK_RESULT*r,uint32_t reg,uint32_t*v)
{
 if(reg>=6||r->Reads==64||r->TraceCount==G70_EVENTS||!Available(io,r))return 0;
 r->Reads++;if(!io->Read(io->Context,reg,v)){Event(r,4,reg,0);return 0;}return Event(r,1,reg,*v);
}
static int Write(const G70_CLOCK_IO*io,G70_CLOCK_RESULT*r,uint32_t value)
{
 int ok;
 if(r->Writes==6||r->TraceCount==G70_EVENTS||!Available(io,r))return 0;
 if((value&~G70_VOTE_MASK)!=Baseline[0]||(value&G70_VOTE_MASK)&~r->DirtyMask)return 0;
 r->Writes++;ok=io->Write(io->Context,0,value);Event(r,ok?2u:5u,0,value);return ok;
}
static int Poll(const G70_CLOCK_IO*io,G70_CLOCK_RESULT*r,int stopped)
{
 uint32_t i,value,root;
 for(i=0;i<8;i++){
  if(!Read(io,r,1,&value)||!Read(io,r,2,&root))return 0;
  /* G68 native evidence: ROOT_OFF follows gate activity in HW_CLK_CTRL_MODE.
   * Only status bit31 may differ; do not accept changed SE/root controls.
   * Each poll reads both statuses so their independent delays remain bounded.
   */
  if((value&~0x80000000u)!=0x4000u||(root&~0x80000000u)){
   if(!r->Code)r->Code=5;return 0;
  }
  if(!!(value&0x80000000u)==stopped&&!!(root&0x80000000u)==stopped)return 1;
  if(i!=7){if(!Available(io,r))return 0;r->Waits++;io->WaitOneUs(io->Context);if(!Event(r,3,1,1))return 0;}
 }
 return 0;
}
static int Snapshot(const G70_CLOCK_IO*io,G70_CLOCK_RESULT*r,uint32_t out[6])
{uint32_t i;for(i=0;i<6;i++)if(!Read(io,r,i,&out[i]))return 0;return 1;}
int G70ClockRelease(const G70_CLOCK_IO*io,G70_CLOCK_RESULT*r,uint64_t nonce)
{
 int i,ok;uint32_t now,next,got;
 if(!io||!r||!io->Available||!io->Read||!io->Write||!io->WaitOneUs||!nonce||nonce!=r->Nonce||(!r->DirtyMask&&!r->Active))return 0;
 r->Phase=90;
 if(!Read(io,r,0,&now)){r->RestoreError=1;return 0;}
 if((now&~G70_VOTE_MASK)!=Baseline[0]||(now&G70_VOTE_MASK)&~r->DirtyMask){r->RestoreError=2;return 0;}
 for(i=2;i>=0;i--){
  if(!(r->DirtyMask&Stage[i]))continue;
  if(!Read(io,r,0,&got)||got!=now){r->RestoreError=3;return 0;}
  next=now&~Stage[i];
  if(next!=now){
   ok=Write(io,r,next);
   if(!Read(io,r,0,&got)||got!=next){r->RestoreError=4;return 0;}
   if(!ok&&!r->Code)r->Code=3;
  }
  now=next;r->DirtyMask&=~Stage[i];
 }
 r->Active=0;r->Phase=91;
 if(!Poll(io,r,1)||!Snapshot(io,r,r->After)){r->RestoreError=5;return 0;}
 for(i=0;i<6;i++)if(r->After[i]!=Baseline[i]){r->RestoreError=6;return 0;}
 r->Restored=1;r->Phase=0;return 1;
}
int G70ClockAcquire(const G70_CLOCK_IO*io,G70_CLOCK_RESULT*r,uint64_t nonce)
{
 uint32_t i,now,next,got;int ok;
 if(!io||!r||!io->Available||!io->Read||!io->Write||!io->WaitOneUs||!nonce||r->Nonce||r->DirtyMask||r->Active||r->TraceCount)return 0;
 r->Nonce=nonce;r->Phase=1;
 if(!Snapshot(io,r,r->Before)){r->Code=r->Code?r->Code:2;return 0;}
 for(i=0;i<6;i++)if(r->Before[i]!=Baseline[i]){r->Code=1;return 0;}
 now=r->Before[0];r->Phase=2;
 for(i=0;i<3;i++){
  if(!Read(io,r,0,&got)){r->Code=r->Code?r->Code:2;goto undo;}
  if(got!=now){r->Code=5;goto undo;}
  next=now|Stage[i];r->DirtyMask|=Stage[i]; /* Intent before attempted write. */
  ok=Write(io,r,next);
  if(!Read(io,r,0,&got)||got!=next||!ok){r->Code=r->Code?r->Code:3;goto undo;}
  now=next;
 }
 r->Phase=3;
 if(!Poll(io,r,0)){r->Code=r->Code?r->Code:4;goto undo;}
 if(!Snapshot(io,r,r->Enabled)){r->Code=r->Code?r->Code:2;goto undo;}
 if(r->Enabled[0]!=(Baseline[0]|G70_VOTE_MASK)||r->Enabled[1]!=0x4000u||r->Enabled[2]!=0||r->Enabled[3]!=Baseline[3]){r->Code=5;goto undo;}
 r->Active=1;r->Phase=4;return 1;
 undo:
 if(r->DirtyMask)G70ClockRelease(io,r,nonce);
 return 0;
}
