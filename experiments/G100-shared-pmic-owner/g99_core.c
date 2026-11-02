/* SPDX-License-Identifier: MIT
 * Fixed v7 observer READs. No PMIC writes, reset/IRQ/GPIO configuration or
 * control channels. PON/GPIO semantics are independently pinned in receipts.
 */
#include "g99_core.h"
static int Fail(G99_RESULT*r,uint32_t code){if(!r->Code)r->Code=code;return 0;}
static int Read(const G99_IO*io,G99_RESULT*r,uint32_t at,uint32_t*v){
 if(r->Code||r->Reads>=G99_MAX_READS||!G99ReadAllowed(at))return Fail(r,G99_BUDGET);
 r->Reads++;return io->Read(io->Context,at,v)?1:Fail(r,G99_IO_ERROR);
}
static int Guard(const G99_IO*io,G99_RESULT*r){
 uint64_t now;if(!io->Available(io->Context)){r->Cancelled=1;return Fail(r,G99_CANCELLED);}
 now=io->NowUs(io->Context);if(now<r->BeginUs||now<r->EndUs)return Fail(r,G99_CLOCK);r->EndUs=now;
 if(now-r->BeginUs>G99_DEADLINE_US)return Fail(r,G99_DEADLINE);return 1;
}
static int Route(const G99_IO*io,G99_RESULT*r,unsigned i){
 uint32_t map,owner;return Read(io,r,0xc402000+G99Targets[i].Apid*4,&map)&&Read(io,r,0xc42d000+G99Targets[i].Apid*4,&owner)&&(map==G99Targets[i].Map&&owner==G99Targets[i].Owner?1:Fail(r,G99_ROUTE));
}
static int TransactionLocked(const G99_IO*io,G99_RESULT*r,unsigned i,unsigned offset,unsigned length,uint8_t*out){
 uint32_t command,base;G99_TRACE*t;unsigned p;
 if(r->Code)return 0;
 if(i>=4||!out||!((offset==0&&length==8)||(i>0&&offset==0x10&&length==1)||(i==3&&offset==0x40&&length==8)))return Fail(r,G99_ARGUMENT);
 if(!Guard(io,r))return 0;
 if(r->TraceCount>=G99_MAX_COMMANDS)return Fail(r,G99_BUDGET);t=&r->Trace[r->TraceCount++];t->Target=i;t->Offset=offset;t->Length=length;base=G99Base(i);
 r->Stage=10+i;if(!Route(io,r,i))return 0;t->Flags|=G99_ROUTE_OK;
 if(!Read(io,r,base+8,&t->BeforeStatus)||!Read(io,r,base,&t->BeforeCommand))return 0;
 if(!(t->BeforeStatus&1)&&t->BeforeCommand)return Fail(r,G99_PENDING);t->Flags|=G99_PREVIOUS_IDLE;
 if(!Guard(io,r))return 0;
 command=0x08000000u|(offset<<4)|(length-1);
 if(!G99WriteAllowed(base,command)||r->Writes>=G99_MAX_COMMANDS)return Fail(r,G99_BUDGET);
 r->Stage=20+i;r->Writes++;t->Flags|=G99_COMMAND_ATTEMPTED;
 if(!io->Write(io->Context,base,command))return Fail(r,G99_IO_ERROR);t->Flags|=G99_COMMAND_WRITTEN;r->Commands++;
 /* Finish this bounded in-flight READ even if cancellation arrives. Never
  * abandon it solely due to a user-mode handle closing during completion. */
 r->Stage=30+i;for(p=0;p<12;p++){r->Polls++;if(!Read(io,r,base+8,&t->Completion))return 0;if(t->Completion&1)break;if(p<11)io->WaitUs(io->Context);}
 if(!(t->Completion&1))return Fail(r,G99_TIMEOUT);t->Flags|=G99_DONE;
 if(t->Completion&0xe)return Fail(r,G99_COMPLETION);
 if(!Read(io,r,base+0x18,&t->Data0)||(length>4&&!Read(io,r,base+0x1c,&t->Data1)))return 0;
 for(p=0;p<length;p++)out[p]=(uint8_t)((p<4?t->Data0:t->Data1)>>((p%4)*8));t->Flags|=G99_DATA;return 1;
}
static int Transaction(const G99_IO*io,G99_RESULT*r,unsigned i,unsigned offset,unsigned length,uint8_t*out){
 uint32_t before=r->TraceCount;int ok,uncertain=0;
 if(r->Code)return 0;
 if(!io->Acquire(io->Context))return Fail(r,G99_GATE);
 ok=TransactionLocked(io,r,i,offset,length,out);
 if(r->TraceCount>before){const G99_TRACE*t=&r->Trace[r->TraceCount-1];uncertain=(t->Flags&G99_COMMAND_ATTEMPTED)&&!(t->Flags&G99_DATA);}
 io->Release(io->Context,uncertain);return ok;
}
void G99Sample(const G99_IO*io,uint32_t count,G99_RESULT*r){
 unsigned i,j;uint32_t version,features;static const uint8_t revision[8]={33,0,1,2,81,74,1,0};
 r->Size=sizeof(*r);r->IntervalMs=G99_INTERVAL_MS;
 if(!io||!io->Read||!io->Write||!io->WaitUs||!io->WaitInterval||!io->Available||!io->NowUs||!io->Acquire||!io->Release||!count||count>G99_MAX_SAMPLES){Fail(r,G99_ARGUMENT);return;}
 r->BeginUs=io->NowUs(io->Context);
 if(!Guard(io,r))goto done;
 r->Stage=1;if(!Read(io,r,0xc400000,&version)||!Read(io,r,0xc400004,&features))goto done;
 if(version!=0x70000001||features!=0x80040300){Fail(r,G99_ARBITER);goto done;}
 for(i=0;i<4;i++){
  if(!Transaction(io,r,i,0,8,r->Identity[i]))goto done;r->Stage=40+i;
  if(i==0){for(j=0;j<8;j++)if(r->Identity[i][j]!=revision[j]){Fail(r,G99_IDENTITY);goto done;}}
  if((i==1&&r->Identity[i][5]!=8)||(i==2&&r->Identity[i][5]!=9)||(i==3&&r->Identity[i][4]!=0x10)){Fail(r,G99_IDENTITY);goto done;}
 }
 if(!Transaction(io,r,3,0x40,8,r->GpioBefore))goto done;
 for(i=0;i<count;i++){
  if(i)io->WaitInterval(io->Context);if(!Guard(io,r))goto done;
  for(j=0;j<3;j++)if(!Transaction(io,r,j+1,0x10,1,&r->Samples[i].Raw[j]))goto done;
  r->Samples[i].AtUs=io->NowUs(io->Context);if(r->Samples[i].AtUs<r->BeginUs||r->Samples[i].AtUs<r->EndUs){Fail(r,G99_CLOCK);goto done;}r->EndUs=r->Samples[i].AtUs;r->SampleCount++;
 }
 if(!Transaction(io,r,3,0x40,8,r->GpioAfter))goto done;
 for(i=0;i<8;i++)if(r->GpioBefore[i]!=r->GpioAfter[i]){Fail(r,G99_CONFIG_CHANGED);goto done;}
 if(!Guard(io,r))goto done;
 for(i=0;i<4;i++)if(!Route(io,r,i))goto done;
 if(!Read(io,r,0xc400000,&version)||!Read(io,r,0xc400004,&features))goto done;
 if(version!=0x70000001||features!=0x80040300){Fail(r,G99_POST_ROUTE);goto done;}
 if(!Guard(io,r))goto done;r->PostRoutesVerified=1;r->Stage=0;
 done:{uint64_t now=io->NowUs(io->Context);if(now<r->BeginUs||now<r->EndUs)Fail(r,G99_CLOCK);r->EndUs=now;if(now>=r->BeginUs&&now-r->BeginUs>G99_DEADLINE_US)Fail(r,G99_DEADLINE);}
}
