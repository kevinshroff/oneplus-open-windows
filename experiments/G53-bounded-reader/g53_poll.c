/* SPDX-License-Identifier: MIT */
#include "g53_poll.h"
static int Clock(const G53_POLL_IO*io,G53_POLL_RESULT*r,uint64_t begin,uint64_t*previous)
{
 uint64_t now=io->NowUs(io->Context);if(now<begin||now<*previous||now-begin>G53_POLL_DEADLINE_US){r->Code=G53_POLL_CLOCK;return 0;}*previous=now;r->ElapsedUs=(uint32_t)(now-begin);return 1;
}
int G53Poll(const G53_POLL_IO*io,G53_POLL_RESULT*r)
{
 uint64_t begin,previous;uint32_t i,j;uint8_t*p;
 if(!r)return 0;p=(uint8_t*)r;for(j=0;j<sizeof(*r);j++)p[j]=0;
 if(!io||!io->Read||!io->Clear||!io->Quiet||!io->WaitTenMs||!io->NowUs){r->Code=G53_POLL_ARGUMENT;return 0;}
 begin=previous=io->NowUs(io->Context);r->BusQuiescent=io->Quiet(io->Context)!=0;
 if(!r->BusQuiescent){r->Code=G53_POLL_QUIET;return 0;}
 for(i=0;i<G53_POLL_CYCLES;i++){
  G53_POLL_RECORD*f=&r->Records[i];if(i)io->WaitTenMs(io->Context);
  if(!Clock(io,r,begin,&previous))break;
  r->ReadAttempts++;if(!io->Read(io->Context,G53_TOUCH_ADDRESS,f->Bytes,G53_PREFETCH)){r->Code=G53_POLL_READ;break;}
  f->ReadBytes=G53_PREFETCH;r->Cycles=i+1;
  r->BusQuiescent=io->Quiet(io->Context)!=0;if(!r->BusQuiescent){r->Code=G53_POLL_QUIET;break;}
  if(!Clock(io,r,begin,&previous))break;
  G53DecodeReport(f->Bytes,f->ReadBytes,&f->Frame);
  if(f->Frame.Kind==G53_FRAME_MORE){
   uint32_t tail=f->Frame.TailBytes;if(tail<8||tail>64||f->Frame.MeaningfulBytes!=G53_PREFETCH+tail){r->Code=G53_POLL_DECODE;break;}
   r->ReadAttempts++;r->TailReads++;f->TailRead=1;
   if(!io->Read(io->Context,G53_TAIL_ADDRESS,f->Bytes+G53_PREFETCH,tail)){r->Code=G53_POLL_READ;break;}
   f->ReadBytes+=tail;r->BusQuiescent=io->Quiet(io->Context)!=0;if(!r->BusQuiescent){r->Code=G53_POLL_QUIET;break;}
   if(!Clock(io,r,begin,&previous))break;
   G53DecodeReport(f->Bytes,f->ReadBytes,&f->Frame);
  }
  if(f->Frame.Kind==G53_FRAME_IDLE){r->IdleRecords++;f->ElapsedUs=r->ElapsedUs;continue;}
  if(!G53ReportClearable(f->Bytes,f->ReadBytes)){r->Code=G53_POLL_DECODE;break;}
  f->ClearAttempted=1;r->ClearAttempts++;
  if(!io->Clear(io->Context)){r->Code=G53_POLL_CLEAR;break;}
  f->ClearCompleted=1;r->ClearCompleted++;
  r->BusQuiescent=io->Quiet(io->Context)!=0;if(!r->BusQuiescent){r->Code=G53_POLL_QUIET;break;}
  if(!Clock(io,r,begin,&previous))break;f->ElapsedUs=r->ElapsedUs;
  if(f->Frame.Kind==G53_FRAME_CONTACTS)r->ContactRecords++;else r->RequestRecords++;
 }
 /* Even failed reads/writes require an explicit quiescence observation before
  * the caller may restore pins/clocks/power. Never retry a failed clear. */
 if(r->Code!=G53_POLL_QUIET){r->BusQuiescent=io->Quiet(io->Context)!=0;if(!r->BusQuiescent)r->Code=G53_POLL_QUIET;}
 if(r->Code==0&&r->BusQuiescent)Clock(io,r,begin,&previous);
 return r->Code==0&&r->Cycles==G53_POLL_CYCLES&&r->BusQuiescent;
}
