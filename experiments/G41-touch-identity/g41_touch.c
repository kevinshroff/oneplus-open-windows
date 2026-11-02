/* SPDX-License-Identifier: MIT
 * One source-framed Goodix version read with native AVDD/reset and exact undo.
 * The GPL G27 FIFO core is linked with the G41 source-verified IRQ correction.
 */
#include "g41_touch.h"
typedef struct {const G41_TOUCH_IO*Io;G41_TOUCH_RESULT*Result;uint32_t LastM,LastS,HaveM,HaveS,SAcks;} Owner;
static const uint32_t Pins[3]={0xf10a000,0xf118000,0xf119000};
static int Event(G41_TOUCH_RESULT*r,uint32_t k,uint32_t at,uint32_t v)
{
 G41_TOUCH_EVENT*e;if(r->TraceCount>=1024)return 0;e=&r->Trace[r->TraceCount++];e->Kind=k;e->Address=at;e->Value=v;return 1;
}
static int Read(Owner*o,uint32_t at,uint32_t*v)
{
 G41_TOUCH_RESULT*r=o->Result;if(r->Reads>=896||r->TraceCount>=1024)return 0;r->Reads++;
 if(!o->Io->Read(o->Io->Context,at,v)){Event(r,3,at,0);return 0;}
 if(at==0xa90610){o->LastM=*v;o->HaveM=1;}if(at==0xa90640){o->LastS=*v;o->HaveS=1;}
 return Event(r,1,at,*v);
}
static int Put(Owner*o,uint32_t at,uint32_t v)
{
 G41_TOUCH_RESULT*r=o->Result;
 int gpio=(at==0xf10a000&&(v==1||v==0x81||v==0x281))||((at==0xf10a004||at==0xf118004)&&v<=3)||(at==0xf118000&&(v==0x201||v==0x2c0))||(at==0xf119000&&(v==1||v==0xc0))||(at==0xf11900c&&v==0);
 int m_ack=at==0xa90618&&r->CommandAttempted&&o->HaveM&&v==o->LastM;
 int s_ack=at==0xa90648&&r->CommandAttempted&&o->HaveS&&v==o->LastS&&!o->SAcks;
 int spi=at==0xa9025c||at==0xa9026c||at==0xa90270||at==0xa9080c||at==0xa90700||(at==0xa90600&&v==0x18000000)||(at==0xa90604&&(v==4||v==2))||m_ack||s_ack;
 if(!gpio&&!spi)return 0;if(r->Writes>=128||r->TraceCount>=1024)return 0;
 if(m_ack)o->HaveM=0;if(s_ack){o->HaveS=0;o->SAcks++;}
 if(at==0xa90600){if(r->CommandAttempted)return 0;r->CommandAttempted=1;}
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
 static const uint32_t a[4]={0xa90040,0xa90610,0xa90800,0xa90804};
 static const uint32_t m[4]={0x1001,0xffffffff,0x0fffffff,0x81ffffff};unsigned i;uint32_t v;
 for(i=0;i<4;i++)if(!Read(o,a[i],&v)||(v&m[i]))return 0;
 /* Common vendor initialization clears both M/S status. Only clear this
  * command's observed S word, after both sequencers and FIFOs are idle. */
 if(!Read(o,0xa90640,&v))return 0;
 if(v&&(!Put(o,0xa90648,v)||!Read(o,0xa90640,&v)||v))return 0;
 return 1;
}
static int FifoRead(void*c,uint32_t off,uint32_t*v){return Read(c,0xa90000+off,v)?0:1;}
static int FifoWrite(void*c,uint32_t off,uint32_t v){return Put(c,0xa90000+off,v)?0:1;}
static int Barrier(void*c){Owner*o=c;return o->Io->Barrier(o->Io->Context);}
static void PollWait(Owner*o){o->Result->WaitCounts[4]++;o->Io->WaitPoll(o->Io->Context);}
static void Transfer(Owner*o)
{
 G41_TOUCH_RESULT*r=o->Result;struct g27_fifo s;struct g27_io io={o,FifoRead,FifoWrite,Barrier};
 uint64_t until;unsigned i;int code=G27_EINVAL;
 if(g27_goodix_read_frame(0x10014,28,r->Tx,36)||g27_init(&s,io,128)){r->Code=6;return;}
 r->StartCode=g27_start(&s,r->Tx,r->Rx,36);code=r->StartCode;
 if(code==0){
  until=o->Io->NowUs(o->Io->Context)+20000;
  for(i=0;i<128;i++){
   code=g27_step(&s);if(code!=G27_WAIT)break;
   if(o->Io->NowUs(o->Io->Context)>=until){code=G27_ETIME;break;}PollWait(o);
  }
  if(code==G27_WAIT)code=G27_ETIME;
 }
 r->StepCode=code;
 if(code==0&&s.state==G27_DONE){r->TransportOk=1;r->IdentityOk=g27_goodix_decode_version(r->Rx+8,28,&r->Version)==0;if(!r->IdentityOk)r->Code=7;}
 else{
  r->Code=8;
  if(r->CommandAttempted&&s.state!=G27_UNCERTAIN&&g27_cancel(&s)==0){
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
 r->State=(uint32_t)s.state;r->Steps=s.steps;r->TxDone=s.tx_done;r->RxDone=s.rx_done;r->CancelSent=s.cancel_sent;r->AbortSent=s.abort_sent;
 if(r->CommandAttempted&&s.state==G27_UNCERTAIN){r->BusQuiescent=0;return;}
 r->BusQuiescent=Quiet(o);
}
static int RestoreLengths(Owner*o)
{
 G41_TOUCH_RESULT*r=o->Result;unsigned i;uint32_t now;
 if(!r->LengthsSaved)return 1;
 for(i=0;i<2;i++){
  uint32_t at=0xa9026c+i*4;
  if(!Read(o,at,&now))return 0;
  if(now!=r->LengthsBefore[i]&&now!=36)return 0;
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
 G41_TOUCH_RESULT*r=o->Result;uint32_t ctl,in,irq;int written;
 r->Stage=90;
 if(!Read(o,0xf118000,&ctl)||(ctl!=0x201&&ctl!=0x2c0)||!Read(o,0xf118004,&in)||(in&~3u))return 0;
 if(in&2){
  written=Put(o,0xf118004,in&~2u);
  if(!Read(o,0xf118004,&in)||in)return 0;if(!written&&!r->Code)r->Code=9;
 }
 if(in)return 0;Wait(o,50);
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
 if(!Read(o,0xf119008,&ctl)||ctl!=0xe2||!Read(o,0xf119004,&in)||in||!Read(o,0xf11900c,&irq)||(irq&~1u))return 0;
 if(irq){written=Put(o,0xf11900c,0);r->IrqAcked=1;if(!Read(o,0xf11900c,&irq)||irq)return 0;if(!written&&!r->Code)r->Code=9;}
 return Snapshot(o,r->AfterPins,1);
}
int G41TouchRead(const G41_TOUCH_IO*io,G41_TOUCH_RESULT*r)
{
 Owner o={io,r,0,0,0,0,0};unsigned i;uint32_t now;r->Stage=1;r->BusQuiescent=1;
 if(!Snapshot(&o,r->BeforePins,1)){r->Code=1;return 0;}
 if(!Quiet(&o)){r->Code=1;r->BusQuiescent=0;return -1;}
 for(i=0;i<2;i++)if(!Read(&o,0xa9026c+i*4,&r->LengthsBefore[i])||(r->LengthsBefore[i]&~0xffffffu)){r->Code=2;return 0;}
 r->LengthsSaved=1;
 if(!Read(&o,0xa90600,&r->CommandHistory[0])){r->Code=2;return 0;}
 r->Stage=2;r->AnalogDirty=1;
 r->ResetDirty=1;
 if(!Put(&o,0xf10a000,0x81)||!Read(&o,0xf10a000,&now)||now!=0x81||
    !Put(&o,0xf118000,0x2c0)||!Read(&o,0xf118000,&now)||now!=0x2c0||
    !Put(&o,0xf119000,0xc0)||!Read(&o,0xf119000,&now)||now!=0xc0){r->Code=11;goto cleanup;}

 if(!Put(&o,0xf10a004,2)||!Read(&o,0xf10a004,&now)||now!=2||!Put(&o,0xf10a000,0x281)||!Read(&o,0xf10a000,&now)||now!=0x281){r->Code=3;goto cleanup;}
 Wait(&o,10);
 r->ResetDirty=1;
 if(!Put(&o,0xf118004,0)||!Read(&o,0xf118004,&now)||now||!Put(&o,0xf118000,0x2c0)){r->Code=4;goto cleanup;}
 Wait(&o,15);
 if(!Put(&o,0xf118004,2)||!Put(&o,0xf118000,0x2c0)||!Read(&o,0xf118004,&now)||now!=3){r->Code=4;goto cleanup;}
 Wait(&o,50);Wait(&o,100);
 if(!Snapshot(&o,r->OnPins,0)||r->OnPins[0]!=0x281||r->OnPins[1]!=3||r->OnPins[4]!=0x2c0||r->OnPins[5]!=3||r->OnPins[8]!=0xc0||(r->OnPins[9]&~1u)){r->Code=5;goto cleanup;}
 if(!io->Ready(io->Context)){r->Code=10;goto cleanup;}
 r->Stage=3;Transfer(&o);
 cleanup:
 if(!r->BusQuiescent){r->RestoreError=1;return -1;}
 if(!RestoreLengths(&o)){r->RestoreError=2;return -1;}
 if(!RestorePins(&o)){r->RestoreError=3;return -1;}
 if(!Quiet(&o)||!Read(&o,0xa90600,&r->CommandHistory[1])){r->RestoreError=4;return -1;}
 r->Restored=1;if(!r->Code)r->Stage=0;
 return r->Code==0&&r->TransportOk&&r->IdentityOk?1:0;
}
