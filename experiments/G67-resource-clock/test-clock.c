/* SPDX-License-Identifier: MIT -- original policy with modeled MMIO only. */
#include "g67_clock.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef struct {
 uint32_t Reg[6],Reads,Writes,Calls,AvailableCalls,Waits;
 uint32_t FailRead,FailWrite,AmbiguousWrite,RemoveAt,ForeignAtVoteRead,VoteReads;
 uint32_t OnDelay,OffDelay,OnReads,OffReads;
 int Removed;
} MODEL;
static unsigned Cases;
static const uint32_t Original[6]={0x40002380,0x80004000,0x80000000,0x100000,0,0x80000002};
static void Reset(MODEL*m,G67_CLOCK_RESULT*r){memset(m,0,sizeof(*m));memcpy(m->Reg,Original,sizeof(Original));memset(r,0,sizeof(*r));}
static int Available(void*x){MODEL*m=x;m->AvailableCalls++;if(m->RemoveAt&&m->AvailableCalls>=m->RemoveAt)m->Removed=1;return !m->Removed;}
static int Read(void*x,uint32_t reg,uint32_t*v)
{
 MODEL*m=x;assert(reg<6&&!m->Removed);m->Calls++;m->Reads++;
 if(m->FailRead==m->Reads)return 0;
 if(reg==0&&++m->VoteReads==m->ForeignAtVoteRead)m->Reg[0]|=0x10;
 *v=m->Reg[reg];
 if(reg==1){
  if(m->Reg[0]&0x4000000){m->OnReads++;if(m->OnReads>m->OnDelay)*v&=~0x80000000u;}
  else if(m->OnReads){m->OffReads++;if(m->OffReads<=m->OffDelay)*v&=~0x80000000u;}
 }
 return 1;
}
static int Write(void*x,uint32_t reg,uint32_t v)
{
 MODEL*m=x;assert(!m->Removed&&reg==0);assert(!((v^m->Reg[0])&~G67_VOTE_MASK));
 m->Calls++;m->Writes++;if(m->Writes==m->FailWrite)return 0;
 m->Reg[0]=v;return m->Writes!=m->AmbiguousWrite;
}
static void Wait(void*x){MODEL*m=x;assert(!m->Removed);m->Calls++;m->Waits++;}
static G67_CLOCK_IO Io(MODEL*m){G67_CLOCK_IO io={m,Available,Read,Write,Wait};return io;}
static void Check(const MODEL*m,const G67_CLOCK_RESULT*r)
{
 assert(r->Reads<=64&&r->Writes<=6&&r->Waits<=14&&r->TraceCount<=G67_EVENTS);
 assert(m->Reads==r->Reads&&m->Writes==r->Writes&&m->Waits==r->Waits);
 if(r->Restored){assert(!r->DirtyMask&&!r->Active&&!r->RestoreError);assert(!memcmp(m->Reg,Original,sizeof(Original)));assert(!memcmp(r->After,Original,sizeof(Original)));}
 if(r->Phase==4)assert(r->Active&&r->DirtyMask==G67_VOTE_MASK&&!r->Code);
 for(unsigned i=0;i<r->TraceCount;i++)if(r->Trace[i].Kind==2||r->Trace[i].Kind==5)assert(r->Trace[i].Register==0);
}
static int Cycle(MODEL*m,G67_CLOCK_RESULT*r){G67_CLOCK_IO io=Io(m);int ok=G67ClockAcquire(&io,r,0x123456789abcdef0ull);if(ok)ok=G67ClockRelease(&io,r,r->Nonce);Check(m,r);return ok;}
static void Put32(uint8_t*p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i));}
static void Resources(uint8_t rows[3][20]){memset(rows,0,60);for(unsigned i=0;i<3;i++){rows[i][0]=3;rows[i][1]=1;Put32(rows[i]+4,G67PageBase[i]);Put32(rows[i]+12,0x1000);}}
int main(void)
{
 MODEL m;G67_CLOCK_RESULT r;G67_CLOCK_IO io;uint32_t calls,reads;uint8_t raw[3][20],tr[3][20];uint32_t index[3];
 for(unsigned on=0;on<8;on++)for(unsigned off=0;off<8;off++){Reset(&m,&r);m.OnDelay=on;m.OffDelay=off;assert(Cycle(&m,&r)&&r.Restored&&r.Writes==6);Cases++;}
 Reset(&m,&r);io=Io(&m);assert(G67ClockAcquire(&io,&r,3));calls=m.Calls;assert(!G67ClockRelease(&io,&r,0)&&!G67ClockRelease(&io,&r,4)&&!G67ClockAcquire(&io,&r,4)&&m.Calls==calls);assert(G67ClockRelease(&io,&r,3));calls=m.Calls;assert(!G67ClockRelease(&io,&r,3)&&m.Calls==calls);Check(&m,&r);Cases++;
 Reset(&m,&r);assert(Cycle(&m,&r));reads=m.Reads;
 for(unsigned fail=1;fail<=reads;fail++){Reset(&m,&r);m.FailRead=fail;assert(!Cycle(&m,&r));assert(r.Code||r.RestoreError);Cases++;}
 for(unsigned fail=1;fail<=6;fail++){Reset(&m,&r);m.FailWrite=fail;assert(!Cycle(&m,&r));assert(r.Code||r.RestoreError);Cases++;Reset(&m,&r);m.AmbiguousWrite=fail;Cycle(&m,&r);assert(r.Code==3&&r.Restored&&m.Writes<=6);Cases++;}
 Reset(&m,&r);m.OnDelay=8;assert(!Cycle(&m,&r)&&r.Code==4&&r.Restored);Cases++;
 Reset(&m,&r);m.OffDelay=8;assert(!Cycle(&m,&r)&&r.RestoreError==5&&!r.Restored);Cases++;
 for(unsigned reg=0;reg<6;reg++){Reset(&m,&r);m.Reg[reg]^=1;assert(!Cycle(&m,&r)&&r.Code==1&&!m.Writes);Cases++;}
 Reset(&m,&r);io=Io(&m);assert(!G67ClockAcquire(&io,&r,0)&&!m.Calls);Cases++;
 Reset(&m,&r);assert(Cycle(&m,&r));calls=m.AvailableCalls;
 for(unsigned cut=1;cut<=calls;cut++){Reset(&m,&r);m.RemoveAt=cut;assert(!Cycle(&m,&r));assert(m.Removed&&!r.Restored);unsigned before=m.Calls;assert(!G67ClockRelease(&((G67_CLOCK_IO){&m,Available,Read,Write,Wait}),&r,r.Nonce));assert(m.Calls==before);Cases++;}
 for(unsigned at=1;at<=13;at++){Reset(&m,&r);m.ForeignAtVoteRead=at;assert(!Cycle(&m,&r));assert(m.Reg[0]&0x10);assert(!r.Restored);Cases++;}
 Resources(raw);Resources(tr);assert(G67ValidateResources(raw,tr,index));Cases++;
 for(unsigned perm=0;perm<6;perm++){
  static const unsigned order[6][3]={{0,1,2},{0,2,1},{1,0,2},{1,2,0},{2,0,1},{2,1,0}};
  uint8_t a[3][20],b[3][20];for(unsigned i=0;i<3;i++){memcpy(a[i],raw[order[perm][i]],20);memcpy(b[i],tr[order[perm][i]],20);}assert(G67ValidateResources(a,b,index));for(unsigned i=0;i<3;i++)assert(order[perm][index[i]]==i);Cases++;
 }
 for(unsigned side=0;side<2;side++)for(unsigned row=0;row<3;row++)for(unsigned byte=0;byte<20;byte++){
  Resources(raw);Resources(tr);(side?tr:raw)[row][byte]^=1;assert(!G67ValidateResources(raw,tr,index));Cases++;
 }
 Resources(raw);Resources(tr);memcpy(raw[1],raw[0],20);memcpy(tr[1],tr[0],20);assert(!G67ValidateResources(raw,tr,index));Cases++;
 assert(!G67ValidateResources(NULL,tr,index)&&!G67ValidateResources(raw,NULL,index)&&!G67ValidateResources(raw,tr,NULL));Cases++;
 printf("{\"passed\":true,\"cases\":%u,\"normal_read_calls\":%u,\"actual_clock_core\":true,\"native_operations\":0}\n",Cases,reads);return 0;
}
