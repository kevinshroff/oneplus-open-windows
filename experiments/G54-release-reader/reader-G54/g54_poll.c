/* SPDX-License-Identifier: MIT */
#include "g54_poll.h"
static int Clock(const G54_POLL_IO*io,G54_POLL_RESULT*r,uint64_t begin,uint64_t*previous)
{
 uint64_t now=io->NowUs(io->Context);if(now<begin||now<*previous||now-begin>G54_POLL_DEADLINE_US){r->Code=G54_POLL_CLOCK;return 0;}*previous=now;r->ElapsedUs=(uint32_t)(now-begin);return 1;
}
int G54Poll(const G54_POLL_IO*io,G54_POLL_RESULT*r)
{
 uint64_t begin,previous;uint32_t i,j;uint8_t*p;
 if(!r)return 0;p=(uint8_t*)r;for(j=0;j<sizeof(*r);j++)p[j]=0;
 if(!io||!io->Read||!io->Clear||!io->Quiet||!io->WaitTenMs||!io->NowUs){r->Code=G54_POLL_ARGUMENT;return 0;}
 begin=previous=io->NowUs(io->Context);r->BusQuiescent=io->Quiet(io->Context)!=0;
 if(!r->BusQuiescent){r->Code=G54_POLL_QUIET;return 0;}
 for(i=0;i<G54_POLL_CYCLES;i++){
  G54_POLL_RECORD*f=&r->Records[i];if(i)io->WaitTenMs(io->Context);
  if(!Clock(io,r,begin,&previous))break;
  r->ReadAttempts++;if(!io->Read(io->Context,G54_TOUCH_ADDRESS,f->Bytes,G54_PREFETCH)){r->Code=G54_POLL_READ;break;}
  f->ReadBytes=G54_PREFETCH;r->Cycles=i+1;
  r->BusQuiescent=io->Quiet(io->Context)!=0;if(!r->BusQuiescent){r->Code=G54_POLL_QUIET;break;}
  if(!Clock(io,r,begin,&previous))break;
  G54DecodeReport(f->Bytes,f->ReadBytes,&f->Frame);
  if(f->Frame.Kind==G54_FRAME_MORE){
   uint32_t tail=f->Frame.TailBytes;if(tail<8||tail>64||f->Frame.MeaningfulBytes!=G54_PREFETCH+tail){r->Code=G54_POLL_DECODE;break;}
   r->ReadAttempts++;r->TailReads++;f->TailRead=1;
   if(!io->Read(io->Context,G54_TAIL_ADDRESS,f->Bytes+G54_PREFETCH,tail)){r->Code=G54_POLL_READ;break;}
   f->ReadBytes+=tail;r->BusQuiescent=io->Quiet(io->Context)!=0;if(!r->BusQuiescent){r->Code=G54_POLL_QUIET;break;}
   if(!Clock(io,r,begin,&previous))break;
   G54DecodeReport(f->Bytes,f->ReadBytes,&f->Frame);
  }
  if(f->Frame.Kind==G54_FRAME_IDLE){r->IdleRecords++;f->ElapsedUs=r->ElapsedUs;continue;}
  if(!G54ReportClearable(f->Bytes,f->ReadBytes)){r->Code=G54_POLL_DECODE;break;}
  f->ClearAttempted=1;r->ClearAttempts++;
  if(!io->Clear(io->Context)){r->Code=G54_POLL_CLEAR;break;}
  f->ClearCompleted=1;r->ClearCompleted++;
  r->BusQuiescent=io->Quiet(io->Context)!=0;if(!r->BusQuiescent){r->Code=G54_POLL_QUIET;break;}
  if(!Clock(io,r,begin,&previous))break;f->ElapsedUs=r->ElapsedUs;
  if(f->Frame.Kind==G54_FRAME_CONTACTS)r->ContactRecords++;else r->RequestRecords++;
 }
 /* Even failed reads/writes require an explicit quiescence observation before
  * the caller may restore pins/clocks/power. Never retry a failed clear. */
 if(r->Code!=G54_POLL_QUIET){r->BusQuiescent=io->Quiet(io->Context)!=0;if(!r->BusQuiescent)r->Code=G54_POLL_QUIET;}
 if(r->Code==0&&r->BusQuiescent)Clock(io,r,begin,&previous);
 return r->Code==0&&r->Cycles==G54_POLL_CYCLES&&r->BusQuiescent;
}
