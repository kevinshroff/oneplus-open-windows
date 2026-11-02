/* SPDX-License-Identifier: MIT
 * Native port of G29..G33's qualified fixed DRV2/TCS0 sequence and reclaim.
 * RSC resource addresses are payloads, never physical CPU MMIO addresses.
 */
#include "g91_power.h"
static const uint32_t Address[17]={0x17a20000,0x17a20004,0x17a2000c,0x17a20d00,0x17a20d04,0x17a20d28,0x17a20d24,0x17a20d2c,0x17a20d34,0x17a20d38,0x17a20d3c,0x17a20d40,0x17a20d44,0x17100104,0x17100204,0x17100304,0x17100c08};
static const uint32_t Baseline[11]={0x30000,0x4010100,0x800c8104,1,0,1,0,0,0x10108,0x50008,0x60000001};
int G91RscWriteAllowed(uint32_t at,uint32_t v)
{
 if(at==0x17a20d34)return v==0x108||v==0x10108||v==0x10008;
 if(at==0x17a20d38)return v==0x40800||v==0x40804||v==0x40808||v==0x50008;
 if(at==0x17a20d3c)return v==0||v==1||v==0x60000001;
 if(at==0x17a20d24)return v==0||v==0x10000||v==0x1010000;
 if(at==0x17a20d2c)return v==0||v==1;
 return at==0x17a20d08&&v==1;
}
static int Event(G91_RSC_RESULT*r,uint32_t k,uint32_t at,uint32_t v)
{
 G91_RSC_EVENT*e;if(r->TraceCount>=256)return 0;e=&r->Trace[r->TraceCount++];e->Kind=k;e->Address=at;e->Value=v;return 1;
}
static int Read(const G91_RSC_IO*io,G91_RSC_RESULT*r,unsigned key,uint32_t*v)
{
 if(key>=17||r->Reads>=192||r->TraceCount>=256)return 0;r->Reads++;
 if(!io->Read(io->Context,Address[key],v)){Event(r,3,Address[key],0);return 0;}return Event(r,1,Address[key],*v);
}
static int Put(const G91_RSC_IO*io,G91_RSC_RESULT*r,uint32_t at,uint32_t v)
{
 if(r->Writes>=14||!G91RscWriteAllowed(at,v)||r->TraceCount>=256)return 0;
 r->Writes++;if(!Event(r,2,at,v))return 0;return io->Write(io->Context,at,v);
}
static int Set(const G91_RSC_IO*io,G91_RSC_RESULT*r,unsigned key,uint32_t v,int cleanup)
{
 uint32_t now;int written=Put(io,r,Address[key],v);
 if(!written&&!cleanup)return 0;
 if(!Read(io,r,key,&now)||now!=v)return 0;
 if(!written&&r->Code==0)r->Code=9;return 1;
}
static int Snapshot(const G91_RSC_IO*io,G91_RSC_RESULT*r,uint32_t*out)
{
 unsigned i;for(i=0;i<17;i++)if(!Read(io,r,i,&out[i]))return 0;return 1;
}
static int Check(const uint32_t*v)
{
 unsigned i;for(i=0;i<11;i++)if(v[i]!=Baseline[i])return 0;
 return !((v[13]|v[14]|v[15])&32)&&!(v[16]&0xc00);
}
static int Reclaim(const G91_RSC_IO*io,G91_RSC_RESULT*r)
{
 unsigned i;uint32_t v;
 r->Stage=90;
 if(!Read(io,r,0,&v)||v!=Baseline[0]||!Read(io,r,5,&v)||v!=1){r->RestoreError=1;return 0;}
 /* Reject foreign payloads/direction before touching controller state. */
 for(i=6;i<=10;i++){
  if(!Read(io,r,i,&v)){r->RestoreError=2;return 0;}
  if((i==6&&(v&~0x1010000u))||(i==7&&v>1)||
   (i==8&&v!=Baseline[i]&&v!=r->MsgId)||
   (i==9&&v!=Baseline[i]&&v!=r->RequestAddress)||
   (i==10&&v!=Baseline[i]&&v!=r->RequestData)){r->RestoreError=3;return 0;}
 }
 if(!Set(io,r,6,0x10000,1)||!Set(io,r,6,0,1)||!Set(io,r,7,0,1)){r->RestoreError=4;return 0;}
 if(!Read(io,r,5,&v)||v!=1||!Read(io,r,6,&v)||v||!Read(io,r,7,&v)||v){r->RestoreError=5;return 0;}
 if(!Read(io,r,4,&v)||v>1){r->RestoreError=6;return 0;}
 if(v&1){
  int written=Put(io,r,0x17a20d08,1);
  if(!Read(io,r,4,&v)||v){r->RestoreError=7;return 0;}
  if(!written&&r->Code==0)r->Code=9;
 }
 if(!Read(io,r,4,&v)||v){r->RestoreError=8;return 0;}
 for(i=8;i<=10;i++)if(!Set(io,r,i,Baseline[i],1)){r->RestoreError=9;return 0;}
 if(!Snapshot(io,r,r->After)||!Check(r->After)){r->RestoreError=10;return 0;}
 r->Restored=1;return 1;
}
void G91Transfer(const G91_RSC_IO*io,G91_RSC_RESULT*r,uint32_t at,uint32_t data,int writing)
{
 unsigned i;uint32_t irq,idle,status,v;
 r->RequestAddress=at;r->RequestData=data;r->Stage=1;
 if(writing!=G91_READ&&writing!=G91_OFF_ACK&&writing!=G91_OFF_NO_ACK&&writing!=G91_ON_ACK){r->Code=1;return;}
 r->MsgId=writing==G91_READ?0x108:writing==G91_OFF_NO_ACK?0x10008:0x10108;
 if(data!=(writing==G91_ON_ACK?1u:0u)||(writing!=G91_READ?at!=0x40804:!(at==0x40800||at==0x40804||at==0x40808))){r->Code=1;return;}
 if(!Snapshot(io,r,r->Before)||!Check(r->Before)){r->Code=2;return;}
 r->Mutated=1;r->Stage=2;
 if(!Set(io,r,8,r->MsgId,0)||!Set(io,r,9,at,0)||!Set(io,r,10,data,0)){r->Code=3;goto done;}
 if(!Read(io,r,8,&v)||v!=r->MsgId||!Read(io,r,9,&v)||v!=at||!Read(io,r,10,&v)||v!=data){r->Code=4;goto done;}
 if(!Set(io,r,7,1,0)||!Set(io,r,6,0x10000,0)||!Set(io,r,6,0x10000,0)){r->Code=5;goto done;}
 r->Triggered=1;r->Stage=3;
 if(!Put(io,r,Address[6],0x1010000)){r->Code=6;goto done;}
 for(i=0;i<24;i++){
  if(!Read(io,r,4,&irq)||!Read(io,r,5,&idle)||!Read(io,r,11,&status)){r->Code=7;goto done;}
  /* G73 native: no-response OFF completes with issued status101, finished
   * TCS IRQ and idle1, without response bit16. Keep the stronger response
   * requirement for READ/ACK. The core then independently queries exact
   * original raw0 and PMIC-off; this predicate alone never claims undo. */
  if((irq&1)&&idle==1&&(writing==G91_OFF_NO_ACK?status==0x101u:(status&0x10100)==0x10100)){r->Completion=status;break;}
  if(i<23)io->WaitMillisecond(io->Context);
 }
 if(i==24){r->Code=8;goto done;}
 if(!writing&&!Read(io,r,12,&r->Response)){r->Code=7;goto done;}
 done:
 Reclaim(io,r);if(r->Code==0&&r->Restored)r->Stage=0;
}
