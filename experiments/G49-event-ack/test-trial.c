/* SPDX-License-Identifier: MIT */
#include "g49_trial.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const uint32_t Ra[17]={0x17a20000,0x17a20004,0x17a2000c,0x17a20d00,0x17a20d04,0x17a20d28,0x17a20d24,0x17a20d2c,0x17a20d34,0x17a20d38,0x17a20d3c,0x17a20d40,0x17a20d44,0x17100104,0x17100204,0x17100304,0x17100c08};
static const uint32_t Rb[17]={0x30000,0x4010100,0x800c8104,1,0,1,0,0,0x10108,0x50008,0x60000001,0,7,0,0,0,0};
static const uint32_t Pa[8]={0xf10a000,0xf10a004,0xf118000,0xf118004,0xf119000,0xf119004,0xf119008,0xf11900c},Pv[8]={1,0,0x201,0,1,0,0xe2,0};
typedef struct {uint32_t Reg[17],ObsCmd[3];
 uint32_t Spi[1024],InitialSpi[1024],Dfs[25],ClockVote,Pad[4],PinCtl[3],PinLatch[3],PinIrq[3],LastReadM,LastReadS;
 uint8_t WireTx[252],WireRx[252],ReportWireTx[36],ReportWireRx[36],AckWireTx[8],PostWireTx[36],PostWireRx[36];unsigned EventCleared,EventWrites;unsigned SpiCommands,SpiCancels,SpiAborts,TxBytes,RxWords,RxAt,PendingRx,PendingSpi,ClockDelay,Barriers,BarrierFail;uint64_t Now,ResetLowAt;G49_TRIAL_RESULT*Trial;int Rfail,Wfail,Scenario,Delay,Pending,Enabled,EnableHighFlag,Enables,Releases,Reads,Writes,OwnerUsed,IrqEverHigh;G49_RSC_RESULT*Single;G49_POWER_RESULT*Power;} Model;
static G49_RSC_RESULT*Current(Model*m){return m->Power&&m->Power->TxnCount?&m->Power->Transactions[m->Power->TxnCount-1]:m->Single;}
static void Complete(Model*m)
{
 m->Reg[4]=1;m->Reg[5]=1;m->Reg[11]=0x10101;m->Reg[6]=0x10000;
 if(m->Reg[8]==0x10108&&m->Reg[9]==0x40804){m->Enabled=(int)m->Reg[10];m->EnableHighFlag=(int)0x80000000u;if(m->Enabled)m->Enables++;else m->Releases++;}
 if(m->Reg[8]==0x108){m->Reg[12]=m->Reg[9]==0x40800?1800:m->Reg[9]==0x40808?7:(uint32_t)m->EnableHighFlag|(uint32_t)m->Enabled;}
}
static int BaseRead(void*context,uint32_t at,uint32_t*out)
{
 Model*m=context;G49_RSC_RESULT*x=Current(m);unsigned i;m->Reads++;if(m->Reads==m->Rfail)return 0;
 for(i=0;i<17;i++)if(at==Ra[i]){
  if(i==4&&m->Pending>0&&m->Scenario!=1&&!(m->Scenario==6&&m->Reg[8]==0x10108&&m->Reg[10]==1)){if(--m->Pending==0)Complete(m);}
  if(x&&x->Stage==90&&(m->Scenario==2||(m->Scenario==7&&m->Enabled))&&!m->OwnerUsed&&i==9){m->Reg[9]=0xdeadbeef;m->OwnerUsed=1;}
  *out=m->Reg[i];return 1;
 }
 for(i=0;i<8;i++)if(at==Pa[i]){*out=Pv[i];if(m->Scenario==20+(int)i)*out^=1;return 1;}
 if(at==0xc400000){*out=0x70000001;return 1;}if(at==0xc400004){*out=0x80040300;return 1;}
 {const uint32_t apid[3]={117,145,695},maps[3]={0x1010100,0x101c100,0x1c400},owner[3]={4,4,0};
 for(i=0;i<3;i++){
  uint32_t base=0xc440000+apid[i]*0x20;
  if(at==0xc402000+apid[i]*4){*out=maps[i];return 1;}if(at==0xc42d000+apid[i]*4){*out=owner[i];return 1;}
  if(at==base){*out=m->ObsCmd[i];return 1;}if(at==base+8){*out=1;return 1;}
  if(at==base+0x18||at==base+0x1c){
   static const uint8_t ids[3][8]={{32,0,0,2,81,73,1,0},{0,4,1,1,4,172,0,0},{0,4,1,1,4,171,0,0}};
   static const uint8_t cfg[2][8]={{8,7,0,0,7,7,0,0},{8,7,8,7,7,7,128,0}};
   const uint8_t*bytes=ids[i];unsigned j,offset=at==base+0x1c?4u:0u;
   if(i==2&&m->ObsCmd[i]==0x08000080){*out=m->Enabled?0xc7u:0x43u;if(m->Scenario==3&&m->Enabled)*out^=0x20;if(m->Scenario==106&&m->Enabled&&m->PinLatch[1])*out^=0x20;if(m->Scenario==4&&!m->Enabled&&m->Enables)*out=3;return 1;}
   if(i==2&&m->ObsCmd[i]==0x08000407)bytes=cfg[m->Enabled];
   *out=0;for(j=0;j<4;j++)*out|=(uint32_t)bytes[offset+j]<<(j*8);
   if(m->Scenario==5&&m->Enabled&&i==2&&m->ObsCmd[i]==0x08000407)*out^=1;
   return 1;
  }
 }}
 fprintf(stderr,"unexpected read%x\n",at);exit(20);
}
static int BaseWrite(void*context,uint32_t at,uint32_t value)
{
 Model*m=context;unsigned i;m->Writes++;if(m->Wfail==-m->Writes)return 0;
 if(at==0xc440ea0||at==0xc441220||at==0xc4456e0){i=at==0xc440ea0?0:at==0xc441220?1:2;m->ObsCmd[i]=value;return m->Wfail!=m->Writes;}
 if(!G49RscWriteAllowed(at,value)){fprintf(stderr,"unexpected write%x/%x\n",at,value);exit(21);}
 if(at==0x17a20d08){m->Reg[4]=0;m->Reg[11]=0;return m->Wfail!=m->Writes;}
 for(i=0;i<17;i++)if(at==Ra[i]){
  if(i>=8&&i<=10&&value==Rb[i]&&(m->Reg[7]||m->Reg[6]||m->Reg[5]!=1)){fputs("old WRITE payload restored without exclusion\n",stderr);exit(22);}
  m->Reg[i]=value;
  if(i==6&&value==0x1010000){
   if(m->Reg[7]!=1)exit(23);m->Pending=m->Delay+1;m->Reg[5]=0;
   if(m->Delay==0&&m->Scenario!=1&&!(m->Scenario==6&&m->Reg[8]==0x10108&&m->Reg[10]==1)){m->Pending=0;Complete(m);}
  }
  return m->Wfail!=m->Writes;
 }
 exit(24);
}
static void Wait1(void*context){Model*m=context;if(m->Power)m->Power->Waits1ms++;}
static void Wait10(void*context){(void)context;}
static void WaitUs(void*context){(void)context;}
#include "native-model-input.h"
static int Extra(uint32_t at){return(at>=0xa90000&&at<0xa91000)||(at>=0xf10a000&&at<=0xf11900c)||(at>=0xf12c000&&at<=0xf12f00c)||(at>=0x118000&&at<0x119000)||at==0x152008||at==0x12327c||at==0x123280||at==0xac0004||(at==0x17100130||at==0x17100230||at==0x17100330||at==0x17100c60);}
static unsigned FrameLength(Model*m){static const unsigned n[4]={250,34,6,16};return m->SpiCommands?n[m->SpiCommands-1]:250;}
static uint8_t*FrameTx(Model*m){return m->SpiCommands==1?m->WireTx:m->SpiCommands==2?m->ReportWireTx:m->SpiCommands==3?m->AckWireTx:m->PostWireTx;}
static uint8_t*FrameRx(Model*m){return m->SpiCommands==1?m->WireRx:m->SpiCommands==2?m->ReportWireRx:m->PostWireRx;}
static int FatalFrame(Model*m){return m->Scenario==101||(m->SpiCommands==2&&m->Scenario==201)||(m->SpiCommands==3&&m->Scenario==301)||(m->SpiCommands==4&&m->Scenario==401);}
static int StalledFrame(Model*m){return m->Scenario==102||m->Scenario==103||m->Scenario==104||(m->SpiCommands==2&&(m->Scenario==209||m->Scenario==210))||(m->SpiCommands==3&&(m->Scenario==302||m->Scenario==303))||(m->SpiCommands==4&&(m->Scenario==402||m->Scenario==403));}
static int RecoveryStuck(Model*m){return m->Scenario==104||(m->SpiCommands==2&&m->Scenario==210)||(m->SpiCommands==3&&m->Scenario==303)||(m->SpiCommands==4&&m->Scenario==403);}
static uint32_t PinIo(Model*m,unsigned p)
{
 if(p==2&&m->Scenario==113)return m->Enabled&&m->IrqEverHigh?1u:0u;
 if(p==1&&m->Scenario==114&&m->Trial->Touch.Stage==90&&!(m->PinLatch[1]&2)&&m->Now-m->ResetLowAt<50000)return 1;
 if(p==2)return m->Enabled&&m->PinCtl[0]==0x281&&m->PinLatch[0]&&m->PinLatch[1]&&m->EventCleared&&m->Scenario!=404?1:0;
 return m->PinLatch[p]|(m->PinCtl[p]&0x200?m->PinLatch[p]>>1:0);
}
static int Read(void*context,uint32_t at,uint32_t*out)
{
 Model*m=context;unsigned p,i;if(!Extra(at))return BaseRead(context,at,out);m->Reads++;if(m->Reads==m->Rfail)return 0;
 if(at==0x152008){*out=m->ClockVote;return 1;}
 if(at==0x1184e4){*out=0x80004000;if(m->ClockVote&0x4000000){if(m->ClockDelay)m->ClockDelay--;else*out=0x4000;}return 1;}
 if(at==0x1184f0){*out=(m->ClockVote&0x4000000)?0u:0x80000000u;return 1;}if(at==0x1184f4){*out=0x100000;return 1;}if(at==0x12327c){*out=0;return 1;}if(at==0x123280){*out=0x80000002;return 1;}
 if(at==0x118504){*out=m->Dfs[0];return 1;}
 for(i=0;i<8;i++){
  if(at==0x11850c+i*4){*out=m->Dfs[1+i];return 1;}if(at==0x11854c+i*4){*out=m->Dfs[9+i];return 1;}if(at==0x11858c+i*4){*out=m->Dfs[17+i];return 1;}
 }
 if(at==0xac0004){*out=0x30090000;return 1;}
 if(at>=0xf12c000&&at<=0xf12f00c){p=(at-0xf12c000)/0x1000;i=(at&0xfff)/4;
  if(p>=4||i>3)exit(60);*out=i==0?m->Pad[p]:i==1?(m->Pad[p]==0x85&&p==3?1:0):i==2?0xe2:0;return 1;
 }
 {const uint32_t pins[3]={0xf10a000,0xf118000,0xf119000};
 for(p=0;p<3;p++)if(at>=pins[p]&&at<=pins[p]+12){i=(at-pins[p])/4;
  if(i==0){if(m->Scenario==105&&p==0&&m->Trial->Touch.Stage==90)m->PinCtl[p]|=0x1000;*out=m->PinCtl[p];}
  else if(i==1)*out=PinIo(m,p);else if(i==2)*out=0xe2;else*out=m->PinIrq[p];return 1;
 }}
 if(at==0x17100130||at==0x17100230||at==0x17100330||at==0x17100c60){*out=0;return 1;}
 if(at>=0xa90000&&at<0xa91000){
  uint32_t off=at-0xa90000;
  if(!(m->ClockVote&0x4000000)){fputs("SPI read with clock off\n",stderr);exit(61);}
  if(off==0x610&&m->SpiCommands&&!m->SpiCancels&&!m->SpiAborts&&!FatalFrame(m)){
   if(m->TxBytes<FrameLength(m))m->Spi[0x610/4]|=0x40000000;
   if(m->PendingSpi&&!StalledFrame(m)&&--m->PendingSpi==0){
    if(m->SpiCommands==3){m->EventCleared=1;m->Spi[0x40/4]=0;m->Spi[0x610/4]=0x81;m->Spi[0x640/4]=0;}
    else m->PendingRx=1;
   }
   if(m->PendingRx&&!m->RxWords&&m->RxAt<FrameLength(m)){
    unsigned remaining=FrameLength(m)-m->RxAt;m->RxWords=(remaining+3)/4;if(m->RxWords>16)m->RxWords=16;
    m->Spi[0x610/4]=0x80|(remaining<=64?0x08000001u:0x04000000u)|((m->Scenario==108||m->Scenario==110)?0x200000u:0);
    if(remaining<=64){m->Spi[0x40/4]=0;m->Spi[0x640/4]=0x0c000000;}
   }
  }
  if(off==0x780){
   if(m->SpiCommands==3||!m->RxWords||m->RxAt>=((FrameLength(m)+3)&~3u))exit(62);*out=0;
   for(i=0;i<4;i++)*out|=(uint32_t)FrameRx(m)[m->RxAt++]<<(i*8);m->RxWords--;return 1;
  }
  if(off==0x804){*out=m->RxWords?(m->RxAt+m->RxWords*4>=FrameLength(m)?0x80000000u|((FrameLength(m)%4)<<28):0u)|m->RxWords:0;return 1;}
  if(off==0x800){*out=m->Scenario==109&&m->SpiCancels?6u:0u;return 1;}*out=m->Spi[off/4];if(off==0x610)m->LastReadM=*out;if(off==0x640)m->LastReadS=*out;return 1;
 }
 fprintf(stderr,"unexpected extra read%x\n",at);exit(63);
}
static int Write(void*context,uint32_t at,uint32_t value)
{
 Model*m=context;unsigned p,i;if(!Extra(at))return BaseWrite(context,at,value);m->Writes++;if(m->Wfail==-m->Writes)return 0;
 if(at==0x152008){m->ClockVote=value;if(value==0x44302380)m->ClockDelay=1;goto done;}
 if(at>=0xf12c000&&at<=0xf12f000&&(at&0xfff)==0){m->Pad[(at-0xf12c000)/0x1000]=value;goto done;}
 {const uint32_t pins[3]={0xf10a000,0xf118000,0xf119000};for(p=0;p<3;p++)if(at>=pins[p]&&at<=pins[p]+12){
  i=(at-pins[p])/4;
  if(i==0){m->PinCtl[p]=value;}
  else if(i==1){
   if(p==2)exit(65);
   if((m->Spi[0x40/4]&0x1001)&&((p==1&&!(value&2))||(p==0&&!(value&2)))){fputs("power/reset removed with busy SPI\n",stderr);exit(66);}
   m->PinLatch[p]=value&2;if(p==1&&(value&2)&&m->PinLatch[0]&&m->Enabled)m->IrqEverHigh=1;if(p==1&&!(value&2))m->ResetLowAt=m->Now;if(p==1&&(value&2)&&m->Scenario==107)m->PinIrq[2]=1;
  }else if(p==2&&i==3&&value==0)m->PinIrq[p]=0;else exit(67);goto done;
 }}
 if(at>=0xa90000&&at<0xa91000){
  unsigned off=at-0xa90000;
  if(!(m->ClockVote&0x4000000))exit(68);
  if(off==0x600){
   if(m->SpiCommands>=4||value!=(m->SpiCommands==2?0x08000000u:0x18000000u)||!m->Enabled||m->PinCtl[0]!=0x281||PinIo(m,0)!=3||PinIo(m,1)!=3||m->PinCtl[1]!=0x2c0||m->PinCtl[2]!=0xc0){fputs("command without power/reset/exclusive ownership\n",stderr);exit(69);}
   m->SpiCommands++;m->TxBytes=m->RxAt=m->RxWords=m->PendingSpi=m->PendingRx=0;
   if(m->SpiCommands==2&&(!m->Trial->Touch.FullBlockChecksumValid||!m->Trial->Touch.Report.ContractVerified)){fputs("frame2 before verified contract\n",stderr);exit(78);}
   if(m->SpiCommands==3&&!G49AckEligible(&m->Trial->Touch.Report))exit(79);
   if(m->SpiCommands==4&&!m->Trial->Touch.Ack.TransportOk)exit(81);
   m->Spi[0x40/4]=1;m->Spi[0x610/4]=FatalFrame(m)?8:0x40000000;m->Spi[off/4]=value;
   if(m->SpiCommands==4){
    memcpy(m->PostWireRx+8,m->ReportWireRx+8,8);m->PostWireRx[8]=0;
    if(m->Scenario==404||m->Scenario==405){unsigned sum=0;m->PostWireRx[8]=0x80;for(i=8;i<14;i++)sum+=m->PostWireRx[i];m->PostWireRx[14]=(uint8_t)sum;m->PostWireRx[15]=(uint8_t)(sum>>8);if(m->Scenario==405)m->PostWireRx[14]^=1;}
   }
  }else if(off==0x700){
   if(m->TxBytes>=((FrameLength(m)+3)&~3u))exit(70);
   for(i=0;i<4;i++)FrameTx(m)[m->TxBytes++]=(uint8_t)(value>>(i*8));
   if(m->TxBytes>=FrameLength(m)){
    if(m->SpiCommands==3){if(memcmp(m->AckWireTx,(uint8_t[]){0xf0,0,1,2,0x74,0,0,0},8)||++m->EventWrites>1)exit(82);}
    m->PendingSpi=2;m->Spi[0x610/4]=m->Scenario==110?0x200080u:m->Scenario==108?0x80u:m->Scenario==109?8u:0u;
   }
  }else if(off==0x618){if(value!=m->LastReadM)exit(71);m->Spi[0x610/4]&=~(value&~0x80u);}
  else if(off==0x648){if(value!=m->LastReadS||(m->Spi[0x40/4]&0x1001)||m->RxWords)exit(77);m->Spi[0x640/4]&=~value;}
  else if(off==0x604){
   if(value==4){if(++m->SpiCancels>1||m->SpiAborts)exit(72);if(m->Scenario!=103&&!RecoveryStuck(m)){m->Spi[0x40/4]=0;m->Spi[0x610/4]=m->Scenario==109?0x0c200011u:16u;m->RxWords=m->Scenario==109?1u:0u;m->PendingSpi=0;m->PendingRx=0;}}
   else if(value==2){if(!m->SpiCancels||++m->SpiAborts>1)exit(73);if(!RecoveryStuck(m)){m->Spi[0x40/4]=0;m->Spi[0x610/4]=32;m->RxWords=0;m->PendingSpi=0;m->PendingRx=0;}}else exit(74);
  }else{m->Spi[off/4]=value;if(off==0x7c)m->Dfs[0]=(m->Dfs[0]&~0x1eu)|(value<<1);}
  goto done;
 }
 fprintf(stderr,"unexpected extra write%x\n",at);exit(75);
 done:return m->Wfail!=m->Writes;
}
static int Barrier(void*context){Model*m=context;m->Barriers++;return m->Barriers==m->BarrierFail?1:0;}
static void WaitMs(void*context,uint32_t ms){Model*m=context;if(ms!=10&&ms!=15&&ms!=50&&ms!=100)exit(76);m->Now+=(uint64_t)ms*1000;}
static void Poll(void*context){((Model*)context)->Now+=10;}
static uint64_t Now(void*context){return((Model*)context)->Now;}
static int Ready(void*context)
{
 Model*m=context;G49_OBS_IO io={m,Read,Write,WaitUs};G49_OBS_RESULT*p=&m->Trial->Touch.PoweredPmic;static const uint8_t cfg[8]={8,7,8,7,7,7,128,0};unsigned i;
 G49Observe(&io,p);if(p->Code){m->Trial->Power.ObserverUncertain=1;return 0;}if(p->Status!=0xc7)return 0;for(i=0;i<8;i++)if(p->Configuration[i]!=cfg[i])return 0;return 1;
}
static int Touch(void*context){Model*m=context;G49_TOUCH_IO io={m,Read,Write,Barrier,Ready,WaitMs,Poll,Now};return G49TouchRead(&io,&m->Trial->Touch);}
static int Powered(void*context)
{
 Model*m=context;G49_TRIAL_RESULT*t=m->Trial;G49_SPI_IO io={m,Read,Write,WaitUs,Touch};
 t->PoweredHookCalled++;t->Touch.BusQuiescent=1;G49PrepareSpi(&io,&t->Spi);
 t->SafeRelease=(!t->Spi.VoteDirty||t->Spi.Restored)&&(!t->Spi.Engine.Dirty||t->Spi.Engine.Restored)&&!t->Spi.RestoreError&&!t->Spi.Engine.RestoreError&&(!t->Touch.AnalogDirty||t->Touch.Restored)&&t->Touch.BusQuiescent;
 return !t->Spi.Code&&t->Spi.Restored&&t->Touch.TransportOk&&t->Touch.FullBlockChecksumValid&&t->Touch.Report.ContractVerified&&t->Touch.Report.TransportOk&&t->Touch.Ack.TransportOk&&t->Touch.Post.TransportOk&&t->Touch.Restored;
}
static int Safe(void*context){return((Model*)context)->Trial->SafeRelease!=0;}
static int Restored(Model*m)
{
 unsigned i;int ok=!m->Enabled&&m->ClockVote==0x40002380&&m->PinCtl[0]==1&&m->PinLatch[0]==0&&m->PinCtl[1]==0x201&&m->PinLatch[1]==0&&m->PinIrq[2]==0&&m->PinCtl[2]==1;
 for(i=0;i<11;i++)ok=ok&&m->Reg[i]==Rb[i];for(i=0;i<4;i++)ok=ok&&m->Pad[i]==1;
 for(i=0;i<24;i++)ok=ok&&m->Spi[ConfigOffsets[i]/4]==NativeConfig[i];
 return ok&&m->Spi[0x26c/4]==0&&m->Spi[0x270/4]==0&&m->Spi[0x40/4]==0&&(m->Spi[0x610/4]&~0x80u)==0&&m->Spi[0x640/4]==0&&!m->RxWords;
}
int main(int argc,char**argv)
{
 Model m;G49_TRIAL_RESULT t;G49_POWER_IO io;unsigned i;int physical;
 if(argc!=5&&argc!=6)return 2;memset(&m,0,sizeof(m));memset(&t,0,sizeof(t));memset(&io,0,sizeof(io));
 m.Rfail=atoi(argv[1]);m.Wfail=atoi(argv[2]);m.Scenario=atoi(argv[3]);m.BarrierFail=(unsigned)atoi(argv[4]);m.Trial=&t;m.Power=&t.Power;m.ClockVote=0x40002380;t.SafeRelease=1;m.EnableHighFlag=m.Scenario==111?0:m.Scenario==112?0x40000000:(int)0x80000000u;
 memcpy(m.Reg,Rb,sizeof(Rb));memcpy(m.Dfs,NativeDfs,sizeof(NativeDfs));for(i=0;i<4;i++)m.Pad[i]=1;
 for(i=0;i<3;i++){m.ObsCmd[i]=0x08000007;m.PinCtl[i]=i==1?0x201:1;}
 for(i=0;i<24;i++)m.Spi[ConfigOffsets[i]/4]=NativeConfig[i];m.Spi[0x68/4]=m.Spi[0x6c/4]=0x102;m.Spi[0xe24/4]=0x20102864;m.Spi[0xe28/4]=0x20104800;
 m.Spi[0x610/4]=0x80;memcpy(m.InitialSpi,m.Spi,sizeof(m.Spi));
 memcpy(m.WireRx+8,ModelIc,242);if(m.Scenario==100)m.WireRx[249]^=1;
 if(m.Scenario==206)m.WireRx[107]^=1;if(m.Scenario==207)m.WireRx[40]=6;if(m.Scenario==208)m.WireRx[11]=2;
 if(m.Scenario>=206&&m.Scenario<=208){uint32_t sum=0;for(i=8;i<248;i++)sum+=m.WireRx[i];m.WireRx[248]=(uint8_t)sum;m.WireRx[249]=(uint8_t)(sum>>8);}
 {uint8_t*p=m.ReportWireRx+8;uint32_t sum=0;const uint8_t captured[26]={0x40,1,0,0,0,3,0x44,0,7,7};memcpy(p,captured,26);
  if(m.Scenario==203||m.Scenario==204||m.Scenario==205){memset(p,0,26);p[0]=0x80;p[2]=2;p[8]=0x10;p[10]=123;p[12]=0xc8;p[13]=1;p[14]=10;p[16]=0x20;p[18]=0x15;p[19]=3;p[20]=0xf3;p[21]=3;p[22]=20;}
  if(m.Scenario==204)p[2]=11;if(m.Scenario==205)p[2]=3;if(m.Scenario==305)p[2]=1;if(m.Scenario==306)p[0]=0x20;
  for(i=0;i<6;i++)sum+=p[i];p[6]=(uint8_t)sum;p[7]=(uint8_t)(sum>>8);sum=0;
  if(m.Scenario==203||m.Scenario==204||m.Scenario==205){for(i=8;i<24;i++)sum+=p[i];p[24]=(uint8_t)sum;p[25]=(uint8_t)(sum>>8);}
  if(m.Scenario==200)memset(p,0,26);if(m.Scenario==202)p[6]^=1;if(m.Scenario==203)p[25]^=1;
 }

 io.Rsc.Context=&m;io.Rsc.Read=Read;io.Rsc.Write=Write;io.Rsc.WaitMillisecond=Wait1;io.Observer.Context=&m;io.Observer.Read=Read;io.Observer.Write=Write;io.Observer.WaitMicrosecond=WaitUs;io.WaitTenMilliseconds=Wait10;io.Powered=Powered;io.SafeToRelease=Safe;
 G49PowerTrial(&io,&t.Power);
 if(t.Power.Restored&&t.Touch.Restored){G49_TOUCH_IO verify={&m,Read,Write,Barrier,Ready,WaitMs,Poll,Now};if(!G49VerifyTouchOff(&verify,&t.Touch)){t.Power.Restored=0;if(!t.Power.Code)t.Power.Code=109;}}
 physical=Restored(&m);
 printf("{\"ack_transport\":%u,\"post_transport\":%u,\"ack_TX\":%u,\"ack_RX\":%u,\"post_TX\":%u,\"post_RX\":%u,\"post_header_present\":%u,\"post_header_checksum\":%u,\"IRQ_samples\":%u,\"IRQ_before\":%u,\"IRQ_after\":%u,\"event_writes\":%u,",t.Touch.Ack.TransportOk,t.Touch.Post.TransportOk,t.Touch.Ack.TxDone,t.Touch.Ack.RxDone,t.Touch.Post.TxDone,t.Touch.Post.RxDone,t.Touch.Post.HeaderPresent,t.Touch.Post.HeaderChecksumValid,t.Touch.IrqSamples,t.Touch.ReportIrq[0],t.Touch.PostIrq[0],m.EventWrites);
 printf("\"power_code\":%u,\"power_restore_error\":%u,\"power_restored\":%u,\"spi_code\":%u,\"touch_code\":%u,\"touch_restore_error\":%u,\"transport_ok\":%u,\"identity_ok\":%u,\"header_length_valid\":%u,\"info_length\":%u,\"full_checksum_valid\":%u,\"report_transport\":%u,\"report_contract\":%u,\"report_header\":%u,\"report_body_complete\":%u,\"report_body\":%u,\"report_TX_done\":%u,\"report_RX_done\":%u,\"physical_model_restored\":%d,\"safe_release\":%u,\"reads\":%d,\"writes\":%d,\"barriers\":%u,\"commands\":%u,\"cancels\":%u,\"aborts\":%u,\"IRQ_ack\":%u,\"enabled\":%d,\"enables\":%d,\"releases\":%d,\"TX_done\":%u,\"RX_done\":%u,\"wire_TX\":[",t.Power.Code,t.Power.RestoreError,t.Power.Restored,t.Spi.Code,t.Touch.Code,t.Touch.RestoreError,t.Touch.TransportOk,t.Touch.IdentityOk,t.Touch.HeaderLengthValid,t.Touch.InfoLength,t.Touch.FullBlockChecksumValid,t.Touch.Report.TransportOk,t.Touch.Report.ContractVerified,t.Touch.Report.HeaderChecksumValid,t.Touch.Report.BodyComplete,t.Touch.Report.BodyChecksumValid,t.Touch.Report.TxDone,t.Touch.Report.RxDone,physical,t.SafeRelease,m.Reads,m.Writes,m.Barriers,m.SpiCommands,m.SpiCancels,m.SpiAborts,t.Touch.IrqAcked,m.Enabled,m.Enables,m.Releases,t.Touch.TxDone,t.Touch.RxDone);
 for(i=0;i<252;i++)printf("%s%u",i?",":"",m.WireTx[i]);puts("]}");
 if(argc==6){
  typedef struct {uint32_t Size,Version;uint64_t Magic;uint32_t Build,Processors,Irql,FirmwareBytes,FirmwareMatch,RegisterCount,FirmwareStatus,Maps;uint64_t Sequence,Time;uint8_t BuildId[16];} Status;
  struct {Status S;G49_TRIAL_RESULT T;uint32_t Fixed,Attempt;uint64_t Ticks,Frequency;} out;
  FILE*f;memset(&out,0,sizeof(out));out.S.Size=80;out.S.Version=1;out.S.Magic=0x314f52463934474fULL;out.S.Build=26100;out.S.Processors=8;out.S.FirmwareBytes=576;out.S.FirmwareMatch=1;out.S.RegisterCount=50;out.S.Maps=42;memcpy(out.S.BuildId,"G49-ack1",sizeof("G49-ack1"));out.T=t;out.Fixed=out.Attempt=1;out.Frequency=19200000;f=fopen(argv[5],"wb");if(!f||sizeof(out)!=69048||fwrite(&out,1,sizeof(out),f)!=sizeof(out))return 80;fclose(f);
 }
 return 0;
}
