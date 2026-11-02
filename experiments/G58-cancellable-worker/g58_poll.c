/* SPDX-License-Identifier: MIT */
#include "g58_poll.h"
static int Stopped(const G58_POLL_IO*io,G58_POLL_RESULT*r)
{
 if(!io->StopRequested(io->Context))return 0;r->Code=G58_POLL_CANCELLED;return 1;
}
static int Clock(const G58_POLL_IO*io,G58_POLL_RESULT*r,uint64_t begin,uint64_t*previous)
{
 uint64_t now=io->NowUs(io->Context);if(now<begin||now<*previous||now-begin>G58_POLL_DEADLINE_US){r->Code=G58_POLL_CLOCK;return 0;}*previous=now;r->ElapsedUs=(uint32_t)(now-begin);return 1;
}
static int Irq(const G58_POLL_IO*io,G58_POLL_RESULT*r,G58_POLL_RECORD*f,uint32_t index)
{
 G58_POLL_IRQ*s=&f->Irq[index];r->IrqReadAttempts++;
 if(!io->SampleIrq(io->Context,s)||s->Control!=0xc0||s->Config!=0xe2||s->Input>1||s->Status>1){r->Code=G58_POLL_IRQ_ERROR;return 0;}
 f->IrqMask|=1u<<index;return 1;
}
static int ReadPrefix(const G58_POLL_IO*io,G58_POLL_RESULT*r,G58_POLL_RECORD*f,uint32_t retry,uint64_t begin,uint64_t*previous)
{
 if(Stopped(io,r))return 0;
 if(!Irq(io,r,f,retry?2:0)||!Clock(io,r,begin,previous))return 0;
 r->ReadAttempts++;if(!io->Read(io->Context,retry?G58_READ_RETRY:G58_READ_PREFETCH,G58_TOUCH_ADDRESS,f->Bytes,G58_PREFETCH)){r->Code=G58_POLL_READ;return 0;}
 f->ReadBytes=G58_PREFETCH;r->BusQuiescent=io->Quiet(io->Context)!=0;
 if(!r->BusQuiescent){r->Code=G58_POLL_QUIET;return 0;}
 if(!Irq(io,r,f,retry?3:1)||!Clock(io,r,begin,previous))return 0;
 G58DecodeReport(f->Bytes,f->ReadBytes,&f->Frame);return 1;
}
int G58Poll(const G58_POLL_IO*io,G58_POLL_RESULT*r)
{
 uint64_t begin,previous;uint32_t i,j;uint8_t*p;
 if(!r)return 0;p=(uint8_t*)r;for(j=0;j<sizeof(*r);j++)p[j]=0;
 if(!io||!io->Read||!io->Clear||!io->Quiet||!io->WaitTenMs||!io->NowUs||!io->Stage||!io->Publish||!io->SampleIrq||!io->StopRequested||io->Limit==0||io->Limit>G58_POLL_CYCLES){r->Code=G58_POLL_ARGUMENT;return 0;}
 r->Limit=io->Limit;begin=previous=io->NowUs(io->Context);r->BusQuiescent=io->Quiet(io->Context)!=0;
 if(!r->BusQuiescent){r->Code=G58_POLL_QUIET;return 0;}
 for(i=0;i<io->Limit;i++){
  G58_POLL_RECORD*f=&r->Records[i];if(Stopped(io,r))break;if(i)io->WaitTenMs(io->Context);
  if(!Clock(io,r,begin,&previous))break;
  if(Stopped(io,r))break;
  r->Cycles=i+1;
  if(!ReadPrefix(io,r,f,0,begin,&previous))break;
  if(Stopped(io,r))break;
  if(f->Frame.Error==G58_BAD_HEADER&&f->Frame.HeaderChecked&&!f->Frame.HeaderValid){
   for(j=0;j<G58_PREFETCH;j++)f->First[j]=f->Bytes[j];f->FirstReadBytes=G58_PREFETCH;f->HeaderRetry=1;r->HeaderRetries++;
   if(!ReadPrefix(io,r,f,1,begin,&previous))break;
   if(Stopped(io,r))break;
   if(f->Frame.HeaderChecked&&f->Frame.HeaderValid)r->HeadersRecovered++;
  }
  if(f->Frame.Kind==G58_FRAME_MORE){
   uint32_t tail=f->Frame.TailBytes;if(tail<8||tail>64||f->Frame.MeaningfulBytes!=G58_PREFETCH+tail){r->Code=G58_POLL_DECODE;break;}
   r->ReadAttempts++;r->TailReads++;f->TailRead=1;
   if(!io->Read(io->Context,G58_READ_TAIL,G58_TAIL_ADDRESS,f->Bytes+G58_PREFETCH,tail)){r->Code=G58_POLL_READ;break;}
   f->ReadBytes+=tail;r->BusQuiescent=io->Quiet(io->Context)!=0;if(!r->BusQuiescent){r->Code=G58_POLL_QUIET;break;}
   if(!Clock(io,r,begin,&previous))break;
   G58DecodeReport(f->Bytes,f->ReadBytes,&f->Frame);
  }
  if(Stopped(io,r))break;
  if(f->Frame.Kind==G58_FRAME_IDLE){r->IdleRecords++;f->ElapsedUs=r->ElapsedUs;continue;}
  if(!G58ReportClearable(f->Bytes,f->ReadBytes)){r->Code=G58_POLL_DECODE;break;}
  if(f->Frame.Kind==G58_FRAME_CONTACTS){
   if(!io->Stage(io->Context,f->Bytes,f->ReadBytes,begin+r->ElapsedUs)){r->Code=G58_POLL_STAGE;break;}
   if(!Clock(io,r,begin,&previous))break;
  }
  f->ClearAttempted=1;r->ClearAttempts++;
  if(!io->Clear(io->Context)){r->Code=G58_POLL_CLEAR;break;}
  f->ClearCompleted=1;r->ClearCompleted++;
  r->BusQuiescent=io->Quiet(io->Context)!=0;if(!r->BusQuiescent){r->Code=G58_POLL_QUIET;break;}
  if(!Clock(io,r,begin,&previous))break;f->ElapsedUs=r->ElapsedUs;
  if(f->Frame.Kind==G58_FRAME_CONTACTS){
   r->ContactRecords++;
   if(!io->Publish(io->Context,f->Bytes,f->ReadBytes)){r->Code=G58_POLL_PUBLISH;break;}
   if(!Clock(io,r,begin,&previous))break;
  }else r->RequestRecords++;
 }
 if(r->Code!=G58_POLL_QUIET){r->BusQuiescent=io->Quiet(io->Context)!=0;if(!r->BusQuiescent)r->Code=G58_POLL_QUIET;}
 if(r->Code==0&&r->BusQuiescent)Clock(io,r,begin,&previous);
 return r->Code==0&&r->Cycles==io->Limit&&r->BusQuiescent;
}
