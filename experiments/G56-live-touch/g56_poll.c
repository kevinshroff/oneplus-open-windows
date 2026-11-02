/* SPDX-License-Identifier: MIT */
#include "g56_poll.h"
static int Clock(const G56_POLL_IO*io,G56_POLL_RESULT*r,uint64_t begin,uint64_t*previous)
{
 uint64_t now=io->NowUs(io->Context);if(now<begin||now<*previous||now-begin>G56_POLL_DEADLINE_US){r->Code=G56_POLL_CLOCK;return 0;}*previous=now;r->ElapsedUs=(uint32_t)(now-begin);return 1;
}
int G56Poll(const G56_POLL_IO*io,G56_POLL_RESULT*r)
{
 uint64_t begin,previous;uint32_t i,j;uint8_t*p;
 if(!r)return 0;p=(uint8_t*)r;for(j=0;j<sizeof(*r);j++)p[j]=0;
 if(!io||!io->Read||!io->Clear||!io->Quiet||!io->WaitTenMs||!io->NowUs||!io->Stage||!io->Publish||io->Limit==0||io->Limit>G56_POLL_CYCLES){r->Code=G56_POLL_ARGUMENT;return 0;}
 r->Limit=io->Limit;begin=previous=io->NowUs(io->Context);r->BusQuiescent=io->Quiet(io->Context)!=0;
 if(!r->BusQuiescent){r->Code=G56_POLL_QUIET;return 0;}
 for(i=0;i<io->Limit;i++){
  G56_POLL_RECORD*f=&r->Records[i];if(i)io->WaitTenMs(io->Context);
  if(!Clock(io,r,begin,&previous))break;
  r->ReadAttempts++;if(!io->Read(io->Context,G56_TOUCH_ADDRESS,f->Bytes,G56_PREFETCH)){r->Code=G56_POLL_READ;break;}
  f->ReadBytes=G56_PREFETCH;r->Cycles=i+1;
  r->BusQuiescent=io->Quiet(io->Context)!=0;if(!r->BusQuiescent){r->Code=G56_POLL_QUIET;break;}
  if(!Clock(io,r,begin,&previous))break;
  G56DecodeReport(f->Bytes,f->ReadBytes,&f->Frame);
  if(f->Frame.Kind==G56_FRAME_MORE){
   uint32_t tail=f->Frame.TailBytes;if(tail<8||tail>64||f->Frame.MeaningfulBytes!=G56_PREFETCH+tail){r->Code=G56_POLL_DECODE;break;}
   r->ReadAttempts++;r->TailReads++;f->TailRead=1;
   if(!io->Read(io->Context,G56_TAIL_ADDRESS,f->Bytes+G56_PREFETCH,tail)){r->Code=G56_POLL_READ;break;}
   f->ReadBytes+=tail;r->BusQuiescent=io->Quiet(io->Context)!=0;if(!r->BusQuiescent){r->Code=G56_POLL_QUIET;break;}
   if(!Clock(io,r,begin,&previous))break;
   G56DecodeReport(f->Bytes,f->ReadBytes,&f->Frame);
  }
  if(f->Frame.Kind==G56_FRAME_IDLE){r->IdleRecords++;f->ElapsedUs=r->ElapsedUs;continue;}
  if(!G56ReportClearable(f->Bytes,f->ReadBytes)){r->Code=G56_POLL_DECODE;break;}
  if(f->Frame.Kind==G56_FRAME_CONTACTS){
   if(!io->Stage(io->Context,f->Bytes,f->ReadBytes,begin+r->ElapsedUs)){r->Code=G56_POLL_STAGE;break;}
   if(!Clock(io,r,begin,&previous))break;
  }
  f->ClearAttempted=1;r->ClearAttempts++;
  if(!io->Clear(io->Context)){r->Code=G56_POLL_CLEAR;break;}
  f->ClearCompleted=1;r->ClearCompleted++;
  r->BusQuiescent=io->Quiet(io->Context)!=0;if(!r->BusQuiescent){r->Code=G56_POLL_QUIET;break;}
  if(!Clock(io,r,begin,&previous))break;f->ElapsedUs=r->ElapsedUs;
  if(f->Frame.Kind==G56_FRAME_CONTACTS){
   r->ContactRecords++;
   if(!io->Publish(io->Context,f->Bytes,f->ReadBytes)){r->Code=G56_POLL_PUBLISH;break;}
   if(!Clock(io,r,begin,&previous))break;
  }else r->RequestRecords++;
 }
 /* Even failed reads/writes require an explicit quiescence observation before
  * the caller may restore pins/clocks/power. Never retry a failed clear. */
 if(r->Code!=G56_POLL_QUIET){r->BusQuiescent=io->Quiet(io->Context)!=0;if(!r->BusQuiescent)r->Code=G56_POLL_QUIET;}
 if(r->Code==0&&r->BusQuiescent)Clock(io,r,begin,&previous);
 return r->Code==0&&r->Cycles==io->Limit&&r->BusQuiescent;
}
