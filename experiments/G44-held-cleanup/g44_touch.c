/* SPDX-License-Identifier: MIT
 * Restore only the completed G41 transaction, with no new transfer.
 * Cleanup of the completed G41 command only; no transfer function is linked here.
 */
#include "g44_touch.h"
typedef struct {const G44_TOUCH_IO*Io;G44_TOUCH_RESULT*Result;uint32_t LastM,LastS,HaveM,HaveS,SAcks,MAcks;} Owner;
static const uint32_t Pins[3]={0xf10a000,0xf118000,0xf119000};
static int Event(G44_TOUCH_RESULT*r,uint32_t k,uint32_t at,uint32_t v)
{
 G44_TOUCH_EVENT*e;if(r->TraceCount>=1024)return 0;e=&r->Trace[r->TraceCount++];e->Kind=k;e->Address=at;e->Value=v;return 1;
}
static int Read(Owner*o,uint32_t at,uint32_t*v)
{
 G44_TOUCH_RESULT*r=o->Result;if(r->Reads>=896||r->TraceCount>=1024)return 0;r->Reads++;
 if(!o->Io->Read(o->Io->Context,at,v)){Event(r,3,at,0);return 0;}
 if(at==0xa90610){o->LastM=*v;o->HaveM=1;}if(at==0xa90640){o->LastS=*v;o->HaveS=1;}
 return Event(r,1,at,*v);
}
static int Put(Owner*o,uint32_t at,uint32_t v)
{
 G44_TOUCH_RESULT*r=o->Result;
 int gpio=(at==0xf10a000&&(v==1||v==0x81||v==0x281))||((at==0xf10a004||at==0xf118004)&&v<=3)||(at==0xf118000&&(v==0x201||v==0x2c0))||(at==0xf119000&&(v==1||v==0xc0))||(at==0xf11900c&&v==0);
 int m_ack=at==0xa90618&&(r->CommandAttempted||r->State==G27_DONE)&&o->HaveM&&v==o->LastM&&!o->MAcks;
 int s_ack=at==0xa90648&&(r->CommandAttempted||r->State==G27_DONE)&&o->HaveS&&v==o->LastS&&!o->SAcks;
 int spi=at==0xa9026c||at==0xa90270||m_ack||s_ack;
 if(!gpio&&!spi)return 0;if(r->Writes>=128||r->TraceCount>=1024)return 0;
 if(m_ack){o->HaveM=0;o->MAcks++;}if(s_ack){o->HaveS=0;o->SAcks++;}
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
 /* The observed completed G41 command has empty FIFOs, S RX flags and M80.
  * Clear the observed S word before checking/clearing the latched M word. */
 if(!Read(o,0xa90640,&v)||(v!=0&&v!=0x0c000000))return 0;
 if(v){if(!Put(o,0xa90648,v)||!Read(o,0xa90640,&v)||v)return 0;}
 if(!Read(o,0xa90610,&v)||(v!=0&&v!=0x80))return 0;
 if(v){if(!Put(o,0xa90618,v)||!Read(o,0xa90610,&v)||v)return 0;}
 for(i=0;i<3;i++)if(!Read(o,a[i],&v)||(v&mask[i]))return 0;
 return 1;
}





static int RestoreLengths(Owner*o)
{
 G44_TOUCH_RESULT*r=o->Result;unsigned i;uint32_t now;
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
 G44_TOUCH_RESULT*r=o->Result;uint32_t ctl,in,irq;int written;
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


int G44RestoreTouchHeld(const G44_TOUCH_IO*io,G44_TOUCH_RESULT*r,const uint32_t*held)
{
 Owner o={io,r,0,0,0,0,0,0};unsigned i;uint32_t v;
 r->Stage=100;r->AnalogDirty=r->ResetDirty=r->LengthsSaved=1;
 r->State=G27_DONE; /* Ownership of the completed prior command, not a new one. */
 if(!Snapshot(&o,r->OnPins,0)){r->Code=1;return 0;}
 for(i=0;i<12;i++){uint32_t mask=(i==9||i==11)?~1u:0xffffffffu;if((r->OnPins[i]&mask)!=(held[i]&mask)){r->Code=1;return 0;}}
 for(i=0;i<2;i++)if(!Read(&o,0xa9026c+i*4,&v)||v!=36){r->Code=2;return 0;}
 if(!Read(&o,0xa90600,&r->CommandHistory[0])||r->CommandHistory[0]!=0x18000000){r->Code=2;return 0;}
 r->BusQuiescent=Quiet(&o);if(!r->BusQuiescent){r->RestoreError=1;return 0;}
 if(!RestoreLengths(&o)){r->RestoreError=2;return 0;}
 if(!RestorePins(&o)){r->RestoreError=3;return 0;}
 if(!Quiet(&o)||!Read(&o,0xa90600,&r->CommandHistory[1])||r->CommandHistory[1]!=r->CommandHistory[0]){r->RestoreError=4;return 0;}
 r->Restored=1;r->Stage=0;return 1;
}

int G44VerifyTouchOff(const G44_TOUCH_IO*io,G44_TOUCH_RESULT*r)
{
 Owner o={io,r,0,0,0,0,0,0};if(!Snapshot(&o,r->AfterPins,1)){r->Restored=0;r->RestoreError=5;return 0;}return 1;
}
