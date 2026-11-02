/* SPDX-License-Identifier: MIT -- original policy with modeled MMIO only. */
#include "g69_clock.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef struct {
 uint32_t Reg[6],Reads,Writes,Calls,AvailableCalls,Waits;
 uint32_t FailRead,FailWrite,AmbiguousWrite,RemoveAt,ForeignAtVoteRead,VoteReads;
 uint32_t OnDelay,OffDelay,OnReads,OffReads;
 uint32_t RootOnDelay,RootOffDelay,RootOnReads,RootOffReads;
 uint32_t BadOnReg,BadOffReg,BadMask,SeenOn;
 int Removed;
} MODEL;
static unsigned Cases;
static const uint32_t Original[6]={0x40002380,0x80004000,0x80000000,0x100000,0,0x80000002};
static void Reset(MODEL*m,G69_CLOCK_RESULT*r){memset(m,0,sizeof(*m));memcpy(m->Reg,Original,sizeof(Original));memset(r,0,sizeof(*r));}
static int Available(void*x){MODEL*m=x;m->AvailableCalls++;if(m->RemoveAt&&m->AvailableCalls>=m->RemoveAt)m->Removed=1;return !m->Removed;}
static int Read(void*x,uint32_t reg,uint32_t*v)
{
 MODEL*m=x;assert(reg<6&&!m->Removed);m->Calls++;m->Reads++;
 if(m->FailRead==m->Reads)return 0;
 if(reg==0&&++m->VoteReads==m->ForeignAtVoteRead)m->Reg[0]|=0x10;
 *v=m->Reg[reg];
 if(reg==1||reg==2){
  uint32_t *on=reg==1?&m->OnReads:&m->RootOnReads;
  uint32_t *off=reg==1?&m->OffReads:&m->RootOffReads;
  uint32_t onDelay=reg==1?m->OnDelay:m->RootOnDelay;
  uint32_t offDelay=reg==1?m->OffDelay:m->RootOffDelay;
  if(m->Reg[0]&0x4000000){(*on)++;if(*on>onDelay)*v&=~0x80000000u;}
  else if(*on){(*off)++;if(*off<=offDelay)*v&=~0x80000000u;}
 }
 if(((m->Reg[0]&0x4000000)&&m->BadOnReg==reg+1)||(!(m->Reg[0]&0x4000000)&&m->SeenOn&&m->BadOffReg==reg+1))*v^=m->BadMask;
 return 1;
}
static int Write(void*x,uint32_t reg,uint32_t v)
{
 MODEL*m=x;assert(!m->Removed&&reg==0);assert(!((v^m->Reg[0])&~G69_VOTE_MASK));
 m->Calls++;m->Writes++;if(m->Writes==m->FailWrite)return 0;
 m->Reg[0]=v;if(v&0x4000000)m->SeenOn=1;return m->Writes!=m->AmbiguousWrite;
}
static void Wait(void*x){MODEL*m=x;assert(!m->Removed);m->Calls++;m->Waits++;}
static G69_CLOCK_IO Io(MODEL*m){G69_CLOCK_IO io={m,Available,Read,Write,Wait};return io;}
static void Check(const MODEL*m,const G69_CLOCK_RESULT*r)
{
 assert(r->Reads<=64&&r->Writes<=6&&r->Waits<=14&&r->TraceCount<=G69_EVENTS);
 assert(m->Reads==r->Reads&&m->Writes==r->Writes&&m->Waits==r->Waits);
 if(r->Restored){assert(!r->DirtyMask&&!r->Active&&!r->RestoreError);assert(!memcmp(m->Reg,Original,sizeof(Original)));assert(!memcmp(r->After,Original,sizeof(Original)));}
 if(r->Phase==4)assert(r->Active&&r->DirtyMask==G69_VOTE_MASK&&!r->Code);
 for(unsigned i=0;i<r->TraceCount;i++)if(r->Trace[i].Kind==2||r->Trace[i].Kind==5)assert(r->Trace[i].Register==0);
}
static int Cycle(MODEL*m,G69_CLOCK_RESULT*r){G69_CLOCK_IO io=Io(m);int ok=G69ClockAcquire(&io,r,0x123456789abcdef0ull);if(ok)ok=G69ClockRelease(&io,r,r->Nonce);Check(m,r);return ok;}
static void Put32(uint8_t*p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i));}
static void Resources(uint8_t rows[3][20]){memset(rows,0,60);for(unsigned i=0;i<3;i++){rows[i][0]=3;rows[i][1]=1;Put32(rows[i]+4,G69PageBase[i]);Put32(rows[i]+12,0x1000);}}
int main(int argc,char**argv)
{
 MODEL m;G69_CLOCK_RESULT r;G69_CLOCK_IO io;uint32_t calls,reads;uint8_t raw[3][20],tr[3][20];uint32_t index[3];
 for(unsigned on=0;on<8;on++)for(unsigned off=0;off<8;off++)for(unsigned rootOn=0;rootOn<8;rootOn++)for(unsigned rootOff=0;rootOff<8;rootOff++){
  Reset(&m,&r);m.OnDelay=on;m.OffDelay=off;m.RootOnDelay=rootOn;m.RootOffDelay=rootOff;
  assert(Cycle(&m,&r)&&r.Restored&&r.Writes==6&&r.Enabled[1]==0x4000&&r.Enabled[2]==0);Cases++;
 }
 Reset(&m,&r);m.OnDelay=m.OffDelay=m.RootOnDelay=m.RootOffDelay=7;
 assert(Cycle(&m,&r)&&r.Reads==63&&r.Writes==6&&r.Waits==14&&r.TraceCount==83);Cases++;
 Reset(&m,&r);io=Io(&m);assert(G69ClockAcquire(&io,&r,3));calls=m.Calls;assert(!G69ClockRelease(&io,&r,0)&&!G69ClockRelease(&io,&r,4)&&!G69ClockAcquire(&io,&r,4)&&m.Calls==calls);assert(G69ClockRelease(&io,&r,3));calls=m.Calls;assert(!G69ClockRelease(&io,&r,3)&&m.Calls==calls);Check(&m,&r);Cases++;
 Reset(&m,&r);assert(Cycle(&m,&r));reads=m.Reads;
 for(unsigned slow=0;slow<2;slow++)for(unsigned fail=1;fail<=(slow?63:reads);fail++){
  Reset(&m,&r);if(slow)m.OnDelay=m.OffDelay=m.RootOnDelay=m.RootOffDelay=7;
  m.FailRead=fail;assert(!Cycle(&m,&r));assert(r.Code||r.RestoreError);Cases++;
 }
 for(unsigned fail=1;fail<=6;fail++){Reset(&m,&r);m.FailWrite=fail;assert(!Cycle(&m,&r));assert(r.Code||r.RestoreError);Cases++;Reset(&m,&r);m.AmbiguousWrite=fail;Cycle(&m,&r);assert(r.Code==3&&r.Restored&&m.Writes<=6);Cases++;}
 Reset(&m,&r);m.OnDelay=8;assert(!Cycle(&m,&r)&&r.Code==4&&r.Restored);Cases++;
 Reset(&m,&r);m.OffDelay=8;assert(!Cycle(&m,&r)&&r.RestoreError==5&&!r.Restored);Cases++;
 Reset(&m,&r);m.RootOnDelay=8;assert(!Cycle(&m,&r)&&r.Code==4&&r.Restored);Cases++;
 Reset(&m,&r);m.RootOffDelay=8;assert(!Cycle(&m,&r)&&r.RestoreError==5&&!r.Restored);Cases++;
 for(unsigned reg=1;reg<=3;reg++)for(unsigned bit=0;bit<32;bit++){
  Reset(&m,&r);m.BadOnReg=reg+1;m.BadMask=1u<<bit;
  assert(!Cycle(&m,&r)&&r.Restored&&r.Code==(bit==31&&reg<3?4u:5u));Cases++;
 }
 for(unsigned reg=1;reg<6;reg++)for(unsigned bit=0;bit<32;bit++){
  Reset(&m,&r);m.BadOffReg=reg+1;m.BadMask=1u<<bit;
  assert(!Cycle(&m,&r)&&!r.Restored&&r.RestoreError);Cases++;
 }
 for(unsigned reg=0;reg<6;reg++){Reset(&m,&r);m.Reg[reg]^=1;assert(!Cycle(&m,&r)&&r.Code==1&&!m.Writes);Cases++;}
 Reset(&m,&r);io=Io(&m);assert(!G69ClockAcquire(&io,&r,0)&&!m.Calls);Cases++;
 Reset(&m,&r);m.OnDelay=m.OffDelay=m.RootOnDelay=m.RootOffDelay=7;assert(Cycle(&m,&r));calls=m.AvailableCalls;
 for(unsigned cut=1;cut<=calls;cut++){Reset(&m,&r);m.OnDelay=m.OffDelay=m.RootOnDelay=m.RootOffDelay=7;m.RemoveAt=cut;assert(!Cycle(&m,&r));assert(m.Removed&&!r.Restored);unsigned before=m.Calls;assert(!G69ClockRelease(&((G69_CLOCK_IO){&m,Available,Read,Write,Wait}),&r,r.Nonce));assert(m.Calls==before);Cases++;}
 for(unsigned at=1;at<=16;at++){Reset(&m,&r);m.ForeignAtVoteRead=at;assert(!Cycle(&m,&r));assert(m.Reg[0]&0x10);assert(!r.Restored);Cases++;}
 assert(argc==2);G69_REPORT native;FILE*f=fopen(argv[1],"rb");assert(f&&fread(&native,1,sizeof(native),f)==sizeof(native)&&fgetc(f)==EOF&&!fclose(f));
 assert(native.Magic==UINT64_C(0x314b4c433736504f)&&native.Clock.Code==5&&native.Clock.Restored==1&&native.Clock.Reads==34&&native.Clock.Writes==6&&native.Clock.TraceCount==41);
 Reset(&m,&r);m.OnDelay=1;assert(Cycle(&m,&r)&&r.Restored&&!r.Code);
 assert(!memcmp(r.Before,native.Clock.Before,sizeof(r.Before))&&!memcmp(r.Enabled,native.Clock.Enabled,sizeof(r.Enabled))&&!memcmp(r.After,native.Clock.After,sizeof(r.After)));Cases++;
 Resources(raw);Resources(tr);assert(G69ValidateResources(raw,tr,index));Cases++;
 for(unsigned perm=0;perm<6;perm++){
  static const unsigned order[6][3]={{0,1,2},{0,2,1},{1,0,2},{1,2,0},{2,0,1},{2,1,0}};
  uint8_t a[3][20],b[3][20];for(unsigned i=0;i<3;i++){memcpy(a[i],raw[order[perm][i]],20);memcpy(b[i],tr[order[perm][i]],20);}assert(G69ValidateResources(a,b,index));for(unsigned i=0;i<3;i++)assert(order[perm][index[i]]==i);Cases++;
 }
 for(unsigned side=0;side<2;side++)for(unsigned row=0;row<3;row++)for(unsigned byte=0;byte<20;byte++){
  Resources(raw);Resources(tr);(side?tr:raw)[row][byte]^=1;assert(!G69ValidateResources(raw,tr,index));Cases++;
 }
 Resources(raw);Resources(tr);memcpy(raw[1],raw[0],20);memcpy(tr[1],tr[0],20);assert(!G69ValidateResources(raw,tr,index));Cases++;
 assert(!G69ValidateResources(NULL,tr,index)&&!G69ValidateResources(raw,NULL,index)&&!G69ValidateResources(raw,tr,NULL));Cases++;
 printf("{\"passed\":true,\"cases\":%u,\"normal_read_calls\":%u,\"worst_case_read_calls\":63,\"worst_case_trace_rows\":83,\"actual_clock_core\":true,\"G68_native_snapshots_regression_modeled\":true,\"new_core_native_execution_claimed\":false,\"native_operations\":0}\n",Cases,reads);return 0;
}
