/* SPDX-License-Identifier: MIT
 * Four bounded frames: fresh IC-info, report prefetch, one event clear and post-contact read.
 * The GPL G27 FIFO core is linked with the G96 source-verified IRQ correction.
 */
#include "g96_touch.h"
typedef struct {const G96_TOUCH_IO*Io;G96_TOUCH_RESULT*Result;uint32_t LastM,LastS,HaveM,HaveS,SAcks,Frame,CycleBase;} Owner;
static int Stopped(Owner*o)
{
 if(!o->Io->StopRequested(o->Io->Context))return 0;
 if(!o->Result->Code)o->Result->Code=G96_TOUCH_CANCELLED;return 1;
}
static const uint32_t Pins[3]={0xf10a000,0xf118000,0xf119000};
static int Event(G96_TOUCH_RESULT*r,uint32_t k,uint32_t at,uint32_t v)
{
 G96_TOUCH_EVENT*e;if(r->TraceCount>=G96_TOUCH_EVENT_BUDGET)return 0;e=&r->Trace[(r->TraceCount++)%G96_TOUCH_TRACE_SLOTS];e->Kind=k;e->Address=at;e->Value=v;return 1;
}
static int Read(Owner*o,uint32_t at,uint32_t*v)
{
 G96_TOUCH_RESULT*r=o->Result;if(r->Reads>=G96_TOUCH_READ_BUDGET||r->TraceCount>=G96_TOUCH_EVENT_BUDGET)return 0;r->Reads++;
 if(!o->Io->Read(o->Io->Context,at,v)){Event(r,3,at,0);return 0;}
 if(at==0xa90610){o->LastM=*v;o->HaveM=1;}if(at==0xa90640){o->LastS=*v;o->HaveS=1;}
 return Event(r,1,at,*v);
}
static int Put(Owner*o,uint32_t at,uint32_t v)
{
 G96_TOUCH_RESULT*r=o->Result;
 int gpio=(at==0xf10a000&&(v==1||v==0x81||v==0x281))||((at==0xf10a004||at==0xf118004)&&v<=3)||(at==0xf118000&&(v==0x201||v==0x2c0))||(at==0xf119000&&(v==1||v==0xc0))||(at==0xf11900c&&v==0);
 int m_ack=at==0xa90618&&r->CommandAttempted&&o->HaveM&&v==o->LastM;
 int s_ack=at==0xa90648&&r->CommandAttempted&&o->HaveS&&v==o->LastS&&!o->SAcks;
 int spi=at==0xa9025c||at==0xa9026c||at==0xa90270||at==0xa9080c||at==0xa90700||(at==0xa90600&&(v==0x18000000||v==0x08000000))||(at==0xa90604&&(v==4||v==2))||m_ack||s_ack;
 if(!gpio&&!spi)return 0;if(r->Writes>=G96_TOUCH_WRITE_BUDGET||r->TraceCount>=G96_TOUCH_EVENT_BUDGET)return 0;
 if(m_ack)o->HaveM=0;if(s_ack){o->HaveS=0;o->SAcks++;}
 if(at==0xa90600){
  if(o->Frame>=4+4*r->Poll.Limit||r->CommandAttempted!=o->Frame)return 0;
  if(o->Frame<4){if(v!=(o->Frame==2?0x08000000u:0x18000000u))return 0;}
  else if(!G96PollPlan(r,o->CycleBase,o->Frame-4)||v!=(r->PollFrames[(o->Frame-4)%G96_POLL_WIRES].Kind==G96_WIRE_CLEAR?0x08000000u:0x18000000u))return 0;
  if(o->Frame==2&&!G96AckEligible(&r->Report))return 0;
  if(o->Frame==3&&!r->Ack.TransportOk)return 0;
  r->CommandAttempted++;if(o->Frame==1)r->Report.Attempted=1;else if(o->Frame==2)r->Ack.Attempted=1;else if(o->Frame==3)r->Post.Attempted=1;else if(o->Frame>=4)r->PollFrames[(o->Frame-4)%G96_POLL_WIRES].Attempted=1;
  o->HaveM=o->HaveS=o->SAcks=0;
 }
 if(at==0xa90604){if(v==4){if(r->CancelSent||r->AbortSent)return 0;r->CancelSent=1;}else{if(!r->CancelSent||r->AbortSent)return 0;r->AbortSent=1;}}
 if(at==0xa9026c)r->LengthsDirty|=1;if(at==0xa90270)r->LengthsDirty|=2;
 r->Writes++;if(!Event(r,2,at,v))return 0;return o->Io->Write(o->Io->Context,at,v);
}
static void Wait(Owner*o,uint32_t ms)
{
 unsigned k=ms==10?0:ms==15?1:ms==50?2:3;o->Result->WaitCounts[k]++;o->Io->WaitMs(o->Io->Context,ms);
}
static int Snapshot(Owner*o,uint32_t*out,int baseline)
{
 unsigned p,i;for(p=0;p<3;p++)for(i=0;i<4;i++){
  if(!Read(o,Pins[p]+i*4,&out[p*4+i]))return 0;
  if(i==2&&out[p*4+i]!=0xe2)return 0;
  if(i==3&&(out[p*4+i]&~(p==2?1u:0u)))return 0;
 }
 if(baseline){static const uint32_t b[12]={1,0,0xe2,0,0x201,0,0xe2,0,1,0,0xe2,0};
  for(i=0;i<12;i++)if(out[i]!=b[i])return 0;
 }
 return 1;
}
static int Quiet(Owner*o)
{
 static const uint32_t a[9]={0xa90040,0xa90800,0xa90804,0xa90e18,0xa90e1c,0x17100130,0x17100230,0x17100330,0x17100c60};
 static const uint32_t mask[9]={0x1001,0x0fffffff,0x81ffffff,0xffffffff,0xffffffff,0x20,0x20,0x20,0xc00};
 uint32_t v;unsigned i;for(i=0;i<9;i++)if(!Read(o,a[i],&v)||(v&mask[i]))return 0;
 if(!Read(o,0xa90610,&v)||(v&~0x80u))return 0;
 if(!Read(o,0xa90614,&v)||v!=0x7fc0007fu||(v&0x80u))return 0;
 if(!Read(o,0xa90640,&v))return 0;
 if(v){if(v!=0x0c000000u||!o->Result->CommandAttempted||!Put(o,0xa90648,v)||!Read(o,0xa90640,&v)||v)return 0;}
 return 1;
}

static int FifoRead(void*c,uint32_t off,uint32_t*v){return Read(c,0xa90000+off,v)?0:1;}
static int FifoWrite(void*c,uint32_t off,uint32_t v){return Put(c,0xa90000+off,v)?0:1;}
static int Barrier(void*c){Owner*o=c;return o->Io->Barrier(o->Io->Context);}
static void PollWait(Owner*o){o->Result->WaitCounts[4]++;o->Io->WaitPoll(o->Io->Context);}
static void Transfer(Owner*o,uint32_t frame)
{
 G96_TOUCH_RESULT*r=o->Result;struct g27_fifo s;struct g27_io io={o,FifoRead,FifoWrite,Barrier};
 G96_REPORT_RESULT*f=frame==1?&r->Report:frame==2?&r->Ack:frame==3?&r->Post:0;
 const uint32_t sizes[4]={250,34,6,34};uint64_t until;unsigned i;int code=G27_EINVAL;uint32_t bytes;
 uint8_t*tx=f?f->Tx:r->Tx,*rx=frame==2?0:f?f->Rx:r->Rx;o->Frame=frame;
 if(frame>3){r->Code=6;return;}bytes=sizes[frame];
 if((frame==2?!G96EventClearFrame(tx,36):g27_goodix_read_frame(frame?0x10274:0x10070,bytes-8,tx,frame?36:252))||g27_init(&s,io,256)){r->Code=6;return;}
 code=g27_start(&s,tx,rx,bytes);if(f)f->StartCode=code;else r->StartCode=code;
 if(code==0){
  until=o->Io->NowUs(o->Io->Context)+50000;
  for(i=0;i<256;i++){
   code=g27_step(&s);if(code!=G27_WAIT)break;
   if(o->Io->NowUs(o->Io->Context)>=until){code=G27_ETIME;break;}PollWait(o);
  }
  if(code==G27_WAIT)code=G27_ETIME;
 }
 if(f)f->StepCode=code;else r->StepCode=code;
 if(code==0&&s.state==G27_DONE){
  if(f){f->TransportOk=1;if(frame==1)G96AnalyzeReport(f);else if(frame==3)G96AnalyzeReport(f);}
  else{r->TransportOk=1;r->InfoLength=(uint32_t)r->Rx[8]|((uint32_t)r->Rx[9]<<8);r->HeaderLengthValid=r->InfoLength==242;{uint32_t sum=0,j;for(j=8;j<248;j++)sum+=r->Rx[j];r->FullBlockChecksumValid=r->HeaderLengthValid&&((sum&0xffffu)==((uint32_t)r->Rx[248]|((uint32_t)r->Rx[249]<<8)));}if(!r->FullBlockChecksumValid)r->Code=7;}
 }
 else{
  r->Code=8;
  if(r->CommandAttempted==frame+1&&s.state!=G27_UNCERTAIN&&g27_cancel(&s)==0){
   until=o->Io->NowUs(o->Io->Context)+5000;
   for(i=0;i<64;i++){
    int e=g27_step(&s);if(s.recovered_idle||s.state==G27_UNCERTAIN)break;
    if(e!=G27_WAIT||o->Io->NowUs(o->Io->Context)>=until)break;PollWait(o);
   }
   if(!s.recovered_idle&&s.state!=G27_UNCERTAIN&&g27_abort(&s)==0){
    until=o->Io->NowUs(o->Io->Context)+5000;
    for(i=0;i<64;i++){
     int e=g27_step(&s);if(s.recovered_idle||s.state==G27_UNCERTAIN)break;
     if(e!=G27_WAIT||o->Io->NowUs(o->Io->Context)>=until)break;PollWait(o);
    }
   }
  }
 }
 if(f){f->State=(uint32_t)s.state;f->Steps=s.steps;f->TxDone=s.tx_done;f->RxDone=s.rx_done;f->CancelSent=s.cancel_sent;f->AbortSent=s.abort_sent;}
 else{r->State=(uint32_t)s.state;r->Steps=s.steps;r->TxDone=s.tx_done;r->RxDone=s.rx_done;}
 r->CancelSent|=s.cancel_sent;r->AbortSent|=s.abort_sent;
 if(r->CommandAttempted&&s.state==G27_UNCERTAIN){r->BusQuiescent=0;return;}
 r->BusQuiescent=Quiet(o);
}
/* A separate record for each attempted poll command. No clear is retried. */
static int PollTransfer(Owner*o,uint32_t kind,uint32_t address,uint32_t payload,uint8_t*out)
{
 G96_TOUCH_RESULT*r=o->Result;struct g27_fifo s;struct g27_io io={o,FifoRead,FifoWrite,Barrier};G96_WIRE_RESULT*f;uint64_t until;unsigned i;int code;uint32_t index,wire;
 if(r->PollFrameCount>=4*r->Poll.Limit){r->Code=19;return 0;}
 index=r->PollFrameCount++;f=&r->PollFrames[index%G96_POLL_WIRES];{uint32_t j;for(j=0;j<sizeof(*f);j++)((uint8_t*)f)[j]=0;}f->Kind=kind;f->Address=address;f->Payload=payload;
 if(!G96PollPlan(r,o->CycleBase,index)){r->Code=19;return 0;}
 wire=kind==G96_WIRE_CLEAR?6:payload+8;o->Frame=4+index;
 if((kind==G96_WIRE_CLEAR?!G96EventClearFrame(f->Tx,72):g27_goodix_read_frame(address,payload,f->Tx,72))||g27_init(&s,io,256)){r->Code=6;return 0;}
 code=g27_start(&s,f->Tx,kind==G96_WIRE_CLEAR?0:f->Rx,wire);f->StartCode=code;
 if(code==0){
  until=o->Io->NowUs(o->Io->Context)+50000;
  for(i=0;i<256;i++){code=g27_step(&s);if(code!=G27_WAIT)break;if(o->Io->NowUs(o->Io->Context)>=until){code=G27_ETIME;break;}PollWait(o);}
  if(code==G27_WAIT)code=G27_ETIME;
 }
 f->StepCode=code;
 if(code==0&&s.state==G27_DONE)f->TransportOk=1;
 else{
  r->Code=8;
  if(r->CommandAttempted==o->Frame+1&&s.state!=G27_UNCERTAIN&&g27_cancel(&s)==0){
   until=o->Io->NowUs(o->Io->Context)+5000;
   for(i=0;i<64;i++){int e=g27_step(&s);if(s.recovered_idle||s.state==G27_UNCERTAIN)break;if(e!=G27_WAIT||o->Io->NowUs(o->Io->Context)>=until)break;PollWait(o);}
   if(!s.recovered_idle&&s.state!=G27_UNCERTAIN&&g27_abort(&s)==0){
    until=o->Io->NowUs(o->Io->Context)+5000;
    for(i=0;i<64;i++){int e=g27_step(&s);if(s.recovered_idle||s.state==G27_UNCERTAIN)break;if(e!=G27_WAIT||o->Io->NowUs(o->Io->Context)>=until)break;PollWait(o);}
   }
  }
 }
 f->State=(uint32_t)s.state;f->Steps=s.steps;f->TxDone=s.tx_done;f->RxDone=s.rx_done;f->CancelSent=s.cancel_sent;f->AbortSent=s.abort_sent;
 r->CancelSent|=s.cancel_sent;r->AbortSent|=s.abort_sent;
 if(r->CommandAttempted&&s.state==G27_UNCERTAIN){r->BusQuiescent=0;return 0;}
 r->BusQuiescent=Quiet(o);
 if(f->TransportOk&&r->BusQuiescent&&kind!=G96_WIRE_CLEAR)for(i=0;i<payload;i++)out[i]=f->Rx[8+i];
 return f->TransportOk&&r->BusQuiescent;
}
static int PollRead(void*c,uint32_t kind,uint32_t address,uint8_t*out,uint32_t n)
{
 if(!out)return 0;
 return PollTransfer(c,kind,address,n,out);
}
static int PollIrq(void*c,G96_POLL_IRQ*s){Owner*o=c;
 return Read(o,0xf119000,&s->Control)&&s->Control==0xc0&&Read(o,0xf119004,&s->Input)&&!(s->Input&~1u)&&Read(o,0xf119008,&s->Config)&&s->Config==0xe2&&Read(o,0xf11900c,&s->Status)&&!(s->Status&~1u);
}
static int PollClear(void*c){return PollTransfer(c,G96_WIRE_CLEAR,G96_TOUCH_ADDRESS,1,0);}
static int PollQuiet(void*c){Owner*o=c;if(!o->Result->BusQuiescent)return 0;o->Result->BusQuiescent=Quiet(o);return o->Result->BusQuiescent;}
static void PollTenMs(void*c){Wait(c,10);}
static int PollStage(void*c,const uint8_t*raw,uint32_t n,uint64_t at){Owner*o=c;return o->Io->StageInput(o->Io->Context,raw,n,at);}
static int PollPublish(void*c,const uint8_t*raw,uint32_t n){Owner*o=c;return o->Io->PublishInput(o->Io->Context,raw,n);}
static uint64_t PollClock(void*c){Owner*o=c;return o->Io->NowUs(o->Io->Context);}
static int PollAdvance(void*c)
{
 Owner*o=c;G96_TOUCH_RESULT*r=o->Result;
 if(!G96CycleComplete(r,o->CycleBase,r->PollFrameCount)||!r->BusQuiescent||!Quiet(o)||!o->Io->Advance(o->Io->Context)){r->Code=22;r->BusQuiescent=0;return 0;}
 o->CycleBase=r->PollFrameCount;return 1;
}
static int PollStopped(void*c){Owner*o=c;return o->Io->StopRequested(o->Io->Context);}

static int SampleIrq(Owner*o,uint32_t*values,uint32_t flag)
{
 if(!Read(o,0xf119004,&values[0])||(values[0]&~1u)||!Read(o,0xf11900c,&values[1])||(values[1]&~1u))return 0;
 o->Result->IrqSamples|=flag;return 1;
}
/* Observe the owned input with five requested10ms waits; no repeated write.
 * Elapsed times are measured, not inferred from scheduler delay requests. */
static int SettleIrq(Owner*o)
{
 G96_TOUCH_RESULT*r=o->Result;uint64_t begin=o->Io->NowUs(o->Io->Context),now;uint32_t i;
 r->Stage=7;
 for(i=0;i<6;i++){
  if(Stopped(o))return 0;
  G96_IRQ_SAMPLE*s=&r->Settle[i];if(i)Wait(o,10);now=o->Io->NowUs(o->Io->Context);
  if(now<begin||now-begin>250000u||(i&&now-begin<r->Settle[i-1].ElapsedUs))return 0;
  if(Stopped(o))return 0;
  s->ElapsedUs=(uint32_t)(now-begin);
  if(!Read(o,0xf119000,&s->Control)||s->Control!=0xc0||!Read(o,0xf119004,&s->Input)||(s->Input&~1u)||!Read(o,0xf119008,&s->Config)||s->Config!=0xe2||!Read(o,0xf11900c,&s->Status)||(s->Status&~1u))return 0;
  r->SettleCount++;
 }
 r->BusQuiescent=Quiet(o);return r->BusQuiescent;
}
/* Bounded physical-test window after startup ACK and before one raw capture.
 * Fifty PASSIVE_LEVEL100ms waits; no controller writes occur in this window.
 * A held finger must be introduced after reset, not used as boot calibration. */
static int ContactWindow(Owner*o)
{
 uint64_t begin=o->Io->NowUs(o->Io->Context),last=begin,now;unsigned i;
 o->Result->Stage=8;
 for(i=0;i<50;i++){
  if(Stopped(o))return 0;
  Wait(o,100);now=o->Io->NowUs(o->Io->Context);
  if(now<last||now<begin||now-begin>8000000u)return 0;last=now;
  if(Stopped(o))return 0;
 }
 if(last-begin<5000000u)return 0;
 o->Result->BusQuiescent=Quiet(o);return o->Result->BusQuiescent;
}
static int RestoreLengths(Owner*o)
{
 G96_TOUCH_RESULT*r=o->Result;unsigned i;uint32_t now;
 if(!r->LengthsSaved)return 1;
 for(i=0;i<2;i++){
  uint32_t at=0xa9026c+i*4;
  if(!Read(o,at,&now))return 0;
  if(now!=r->LengthsBefore[i]&&now!=250&&now!=34&&now!=6&&(now<16||now>72||(now&7)))return 0;
  if(now!=r->LengthsBefore[i]){
   int written=Put(o,at,r->LengthsBefore[i]);
   if(!Read(o,at,&now)||now!=r->LengthsBefore[i])return 0;
   if(!written&&!r->Code)r->Code=9;
  }
  r->LengthsAfter[i]=now;
 }
 r->LengthsRestored=1;return 1;
}
static int RestorePins(Owner*o)
{
 G96_TOUCH_RESULT*r=o->Result;uint32_t ctl,in,irq;int written;
 r->Stage=90;
 if(!Read(o,0xf118000,&ctl)||(ctl!=0x201&&ctl!=0x2c0)||!Read(o,0xf118004,&in)||(in&~3u))return 0;
 if(in&2){
  written=Put(o,0xf118004,in&~2u);
  if(!Read(o,0xf118004,&in)||(in&~1u))return 0;if(!written&&!r->Code)r->Code=9;
 }
 if(in&~1u)return 0;Wait(o,50);if(!Read(o,0xf118004,&in)||in)return 0;
 if(ctl!=0x201){written=Put(o,0xf118000,0x201);if(!Read(o,0xf118000,&ctl)||ctl!=0x201)return 0;if(!written&&!r->Code)r->Code=9;}
 if(!Read(o,0xf10a000,&ctl)||(ctl!=1&&ctl!=0x81&&ctl!=0x281)||!Read(o,0xf10a004,&in)||(in&~3u))return 0;
 if(in&2){
  written=Put(o,0xf10a004,in&~2u);
  if(!Read(o,0xf10a004,&in)||(in&2))return 0;if(!written&&!r->Code)r->Code=9;
 }
 Wait(o,10);
 if(!Read(o,0xf10a004,&in)||in)return 0;
 if(ctl!=1){written=Put(o,0xf10a000,1);if(!Read(o,0xf10a000,&ctl)||ctl!=1)return 0;if(!written&&!r->Code)r->Code=9;}
 if(!Read(o,0xf119000,&ctl)||(ctl!=1&&ctl!=0xc0))return 0;
 if(ctl!=1){written=Put(o,0xf119000,1);if(!Read(o,0xf119000,&ctl)||ctl!=1)return 0;if(!written&&!r->Code)r->Code=9;}
 if(!Read(o,0xf119008,&ctl)||ctl!=0xe2||!Read(o,0xf119004,&in)||(in&~1u)||!Read(o,0xf11900c,&irq)||(irq&~1u))return 0;
 if(irq){written=Put(o,0xf11900c,0);r->IrqAcked=1;if(!Read(o,0xf11900c,&irq)||irq)return 0;if(!written&&!r->Code)r->Code=9;}
 if(!Snapshot(o,r->AfterPins,0))return 0;
 {unsigned i;for(i=0;i<12;i++)if(i!=9&&r->AfterPins[i]!=r->BeforePins[i])return 0;}
 return r->AfterPins[9]<=1;
}
int G96TouchRead(const G96_TOUCH_IO*io,G96_TOUCH_RESULT*r)
{
 Owner o={io,r,0,0,0,0,0,0,0};unsigned i;uint32_t now;r->Stage=1;
 if(!io||!io->StageInput||!io->PublishInput||!io->StopRequested||!io->Advance||io->PollLimit==0||io->PollLimit>G96_POLL_CYCLES){r->Code=20;return 0;}r->Poll.Limit=io->PollLimit;r->BusQuiescent=1;
 if(!Snapshot(&o,r->BeforePins,1)){r->Code=1;return 0;}
 if(!Quiet(&o)){r->Code=1;r->BusQuiescent=0;return -1;}
 for(i=0;i<2;i++)if(!Read(&o,0xa9026c+i*4,&r->LengthsBefore[i])||(r->LengthsBefore[i]&~0xffffffu)){r->Code=2;return 0;}
 r->LengthsSaved=1;
 if(!Read(&o,0xa90600,&r->CommandHistory[0])){r->Code=2;return 0;}
 if(Stopped(&o))goto cleanup;
 r->Stage=2;r->AnalogDirty=1;
 r->ResetDirty=1;
 if(!Put(&o,0xf10a000,0x81)||!Read(&o,0xf10a000,&now)||now!=0x81||
    !Put(&o,0xf118000,0x2c0)||!Read(&o,0xf118000,&now)||now!=0x2c0||
    !Put(&o,0xf119000,0xc0)||!Read(&o,0xf119000,&now)||now!=0xc0){r->Code=11;goto cleanup;}

 if(!Put(&o,0xf10a004,2)||!Read(&o,0xf10a004,&now)||now!=2||!Put(&o,0xf10a000,0x281)||!Read(&o,0xf10a000,&now)||now!=0x281){r->Code=3;goto cleanup;}
 Wait(&o,10);
 if(Stopped(&o))goto cleanup;
 r->ResetDirty=1;
 if(!Put(&o,0xf118004,0)||!Read(&o,0xf118004,&now)||now||!Put(&o,0xf118000,0x2c0)){r->Code=4;goto cleanup;}
 Wait(&o,15);
 if(Stopped(&o))goto cleanup;
 if(!Put(&o,0xf118004,2)||!Put(&o,0xf118000,0x2c0)||!Read(&o,0xf118004,&now)||now!=3){r->Code=4;goto cleanup;}
 Wait(&o,50);if(Stopped(&o))goto cleanup;Wait(&o,100);if(Stopped(&o))goto cleanup;
 if(!Snapshot(&o,r->OnPins,0)||r->OnPins[0]!=0x281||r->OnPins[1]!=3||r->OnPins[4]!=0x2c0||r->OnPins[5]!=3||r->OnPins[8]!=0xc0||(r->OnPins[9]&~1u)){r->Code=5;goto cleanup;}
 if(!io->Ready(io->Context)){r->Code=10;goto cleanup;}
 r->Stage=3;Transfer(&o,0);
 if(Stopped(&o))goto cleanup;
 if(r->TransportOk&&r->FullBlockChecksumValid&&r->BusQuiescent){
  r->Report.ContractVerified=G96InfoContract(r->Rx+8,242);
  if(r->Report.ContractVerified){r->Stage=4;Transfer(&o,1);}else r->Code=12;
  if(Stopped(&o))goto cleanup;
 }
 if(r->Report.TransportOk&&r->BusQuiescent){
  r->Ack.ContractVerified=G96AckEligible(&r->Report);
  if(r->Ack.ContractVerified){
   if(!SampleIrq(&o,r->ReportIrq,1)){r->Code=13;goto cleanup;}
   r->Stage=5;Transfer(&o,2);
   if(Stopped(&o))goto cleanup;
   if(r->Ack.TransportOk&&r->BusQuiescent){
    if(!SettleIrq(&o)){if(!r->Code)r->Code=16;if(r->Code!=G96_TOUCH_CANCELLED)r->BusQuiescent=0;goto cleanup;}
    if(!ContactWindow(&o)){if(!r->Code)r->Code=17;goto cleanup;}
    r->Post.ContractVerified=1;r->Stage=6;Transfer(&o,3);
    if(Stopped(&o))goto cleanup;
    if(r->Post.TransportOk&&!SampleIrq(&o,r->PostIrq,2))r->Code=14;
    if(!r->Code&&r->Post.TransportOk&&r->BusQuiescent){
     G96_POLL_IO poll={&o,io->PollLimit,PollRead,PollClear,PollQuiet,PollTenMs,PollClock,PollStage,PollPublish,PollIrq,PollStopped,PollAdvance};
     r->Stage=9;if(!G96Poll(&poll,&r->Poll)&&!r->Code)r->Code=r->Poll.Code==G96_POLL_CANCELLED?G96_TOUCH_CANCELLED:18;
    }
   }
  }else r->Code=15;
 }
 cleanup:
 if(!r->BusQuiescent||!Quiet(&o)){r->BusQuiescent=0;r->RestoreError=1;return -1;}
 if(!RestoreLengths(&o)){r->RestoreError=2;return -1;}
 if(!RestorePins(&o)){r->RestoreError=3;return -1;}
 if(!Quiet(&o)||!Read(&o,0xa90600,&r->CommandHistory[1])){r->RestoreError=4;return -1;}
 r->Restored=1;if(!r->Code)r->Stage=0;
 return r->Code==0&&r->TransportOk&&r->FullBlockChecksumValid&&r->Report.ContractVerified&&r->Report.TransportOk&&r->Ack.TransportOk&&r->Post.TransportOk&&r->Poll.Code==0&&r->Poll.Cycles==io->PollLimit?1:0;
}

int G96VerifyTouchOff(const G96_TOUCH_IO*io,G96_TOUCH_RESULT*r)
{
 Owner o={io,r,0,0,0,0,0,0,0};if(!Snapshot(&o,r->AfterPins,1)){r->Restored=0;r->RestoreError=5;return 0;}return 1;
}
