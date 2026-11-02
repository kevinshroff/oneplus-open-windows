/* SPDX-License-Identifier: MIT */
#include "g43_recovery.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const uint32_t Ra[17]={0x17a20000,0x17a20004,0x17a2000c,0x17a20d00,0x17a20d04,0x17a20d28,0x17a20d24,0x17a20d2c,0x17a20d34,0x17a20d38,0x17a20d3c,0x17a20d40,0x17a20d44,0x17100104,0x17100204,0x17100304,0x17100c08};
static const uint32_t Rb[17]={0x30000,0x4010100,0x800c8104,1,0,1,0,0,0x10108,0x50008,0x60000001,0,7,0,0,0,0};
static const uint32_t Pa[8]={0xf10a000,0xf10a004,0xf118000,0xf118004,0xf119000,0xf119004,0xf119008,0xf11900c},Pv[8]={1,0,0x201,0,1,0,0xe2,0};
typedef struct {uint32_t Reg[17],ObsCmd[3];
 uint32_t Spi[1024],InitialSpi[1024],Dfs[25],ClockVote,Pad[4],PinCtl[3],PinLatch[3],PinIrq[3],LastReadM,LastReadS;
 uint8_t WireTx[36],WireRx[36];unsigned SpiCommands,SpiCancels,SpiAborts,TxBytes,RxWords,RxAt,PendingSpi,ClockDelay,Barriers,BarrierFail,MAcks,SAcks;uint64_t Now;G43_TRIAL_RESULT*Trial;int Rfail,Wfail,Scenario,Delay,Pending,Enabled,EnableHighFlag,Enables,Releases,Reads,Writes,OwnerUsed;G43_RSC_RESULT*Single;G43_POWER_RESULT*Power;} Model;
static G43_RSC_RESULT*Current(Model*m){return m->Power&&m->Power->TxnCount?&m->Power->Transactions[m->Power->TxnCount-1]:m->Single;}
static void Complete(Model*m)
{
 m->Reg[4]=1;m->Reg[5]=1;m->Reg[11]=0x10101;m->Reg[6]=0x10000;
 if(m->Reg[8]==0x10108&&m->Reg[9]==0x40804){m->Enabled=(int)m->Reg[10];m->EnableHighFlag=(int)0x80000000u;if(m->Enabled)m->Enables++;else m->Releases++;}
 if(m->Reg[8]==0x108){m->Reg[12]=m->Reg[9]==0x40800?1800:m->Reg[9]==0x40808?7:(uint32_t)m->EnableHighFlag|(uint32_t)m->Enabled;}
}
static int BaseRead(void*context,uint32_t at,uint32_t*out)
{
 Model*m=context;G43_RSC_RESULT*x=Current(m);unsigned i;m->Reads++;if(m->Reads==m->Rfail)return 0;
 for(i=0;i<17;i++)if(at==Ra[i]){
  if(i==4&&m->Pending>0&&m->Scenario!=1&&!(m->Scenario==6&&m->Reg[8]==0x10108&&m->Reg[10]==1)){if(--m->Pending==0)Complete(m);}
  if(x&&x->Stage==90&&(m->Scenario==210||(m->Scenario==7&&m->Enabled))&&!m->OwnerUsed&&i==9){m->Reg[9]=0xdeadbeef;m->OwnerUsed=1;}
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
   if(i==2&&m->ObsCmd[i]==0x08000080){*out=m->Enabled?0xc7u:0x43u;if(m->Scenario==207&&m->Enabled)*out^=0x40;if(m->Scenario==106&&m->Enabled&&m->PinLatch[1])*out^=0x20;if(m->Scenario==4&&!m->Enabled&&m->Enables)*out=3;return 1;}
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
 if(at==0x17a20d3c&&value==1){fputs("forbidden enable1\n",stderr);exit(90);}
 if(at==0xc440ea0||at==0xc441220||at==0xc4456e0){i=at==0xc440ea0?0:at==0xc441220?1:2;m->ObsCmd[i]=value;return m->Wfail!=m->Writes;}
 if(!G43RscWriteAllowed(at,value)){fprintf(stderr,"unexpected write%x/%x\n",at,value);exit(21);}
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
#include "g43_recovery_binding.h"
#define ConfigOffsets G43RecoveryEngineOffsets
#define NativeConfig G43OriginalEngine
#define NativeDfs G43OriginalDfs
static int Extra(uint32_t at){return(at>=0xa90000&&at<0xa91000)||(at>=0xf10a000&&at<=0xf11900c)||(at>=0xf12c000&&at<=0xf12f00c)||(at>=0x118000&&at<0x119000)||at==0x152008||at==0x12327c||at==0x123280||at==0xac0004||(at==0x17100130||at==0x17100230||at==0x17100330||at==0x17100c60);}
static uint32_t PinIo(Model*m,unsigned p)
{
 if(p==2)return 0;
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
 if(at==0x17100130||at==0x17100230||at==0x17100330||at==0x17100c60){*out=m->Scenario==209&&at==0x17100130?0x20u:0;return 1;}
 if(at>=0xa90000&&at<0xa91000){
  uint32_t off=at-0xa90000;
  if(!(m->ClockVote&0x4000000)){fputs("SPI read with clock off\n",stderr);exit(61);}
  if(off==0x610&&m->PendingSpi&&m->Scenario!=102&&m->Scenario!=103&&m->Scenario!=104){
   if(--m->PendingSpi==0){m->Spi[0x40/4]=0;m->Spi[0x610/4]=0x0c000001|((m->Scenario==108||m->Scenario==110)?0x200000u:0);m->RxWords=9;if(m->Scenario==108||m->Scenario==110)m->Spi[0x640/4]=0x0c000000;}
  }
  if(off==0x780){
   if(!m->RxWords||m->RxAt>=36)exit(62);*out=0;for(i=0;i<4;i++)*out|=(uint32_t)m->WireRx[m->RxAt++]<<(i*8);m->RxWords--;return 1;
  }
  if(off==0x804){*out=m->RxWords?0x80000000|m->RxWords:0;return 1;}
  if(off==0x800){*out=m->Scenario==201?1u:0u;return 1;}*out=m->Spi[off/4];if(off==0x610&&m->Spi[0x640/4])*out|=0x80;if(off==0x610&&m->Scenario==211&&m->MAcks)*out|=0x80;if(off==0x640&&m->Scenario==212&&m->SAcks)*out|=0x0c000000;if(off==0x610)m->LastReadM=*out;if(off==0x640)m->LastReadS=*out;return 1;
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
   m->PinLatch[p]=value&2;if(p==1&&(value&2)&&m->Scenario==107)m->PinIrq[2]=1;
  }else if(p==2&&i==3&&value==0)m->PinIrq[p]=0;else exit(67);goto done;
 }}
 if(at>=0xa90000&&at<0xa91000){
  unsigned off=at-0xa90000;
  if(!(m->ClockVote&0x4000000))exit(68);
  if(off==0x600||off==0x604||off==0x700){fputs("forbidden SPI command/cancel/FIFO write\n",stderr);exit(91);}
  else if(off==0x618){if(value!=m->LastReadM||++m->MAcks>1)exit(71);m->Spi[0x610/4]&=~value;}
  else if(off==0x648){if(value!=m->LastReadS||(m->Spi[0x40/4]&0x1001)||m->RxWords||++m->SAcks>1)exit(77);m->Spi[0x640/4]&=~value;if(m->Scenario==214)m->Spi[0x610/4]&=~0x80u;}
else{m->Spi[off/4]=value;if(off==0x7c)m->Dfs[0]=(m->Dfs[0]&~0x1eu)|(value<<1);}
  goto done;
 }
 fprintf(stderr,"unexpected extra write%x\n",at);exit(75);
 done:return m->Wfail!=m->Writes;
}

static void WaitMs(void*context,uint32_t ms){Model*m=context;if(ms!=10&&ms!=15&&ms!=50&&ms!=100)exit(76);m->Now+=(uint64_t)ms*1000;}






static int Restored(Model*m)
{
 unsigned i;int ok=!m->Enabled&&m->ClockVote==0x40002380&&m->PinCtl[0]==1&&m->PinLatch[0]==0&&m->PinCtl[1]==0x201&&m->PinLatch[1]==0&&m->PinIrq[2]==0&&m->PinCtl[2]==1;
 for(i=0;i<11;i++)ok=ok&&m->Reg[i]==Rb[i];for(i=0;i<4;i++)ok=ok&&m->Pad[i]==1;
 for(i=0;i<24;i++)ok=ok&&m->Spi[ConfigOffsets[i]/4]==NativeConfig[i];
 return ok&&m->Spi[0x26c/4]==0&&m->Spi[0x270/4]==0&&m->Spi[0x40/4]==0&&m->Spi[0x610/4]==0&&m->Spi[0x640/4]==0&&!m->RxWords;
}
int main(int argc,char**argv)
{
 Model m;G43_TRIAL_RESULT t;G43_POWER_IO io;G43_TOUCH_IO touch;unsigned i;int physical;
 if(argc!=4&&argc!=5)return 2;memset(&m,0,sizeof(m));memset(&t,0,sizeof(t));memset(&io,0,sizeof(io));memset(&touch,0,sizeof(touch));
 m.Rfail=atoi(argv[1]);m.Wfail=atoi(argv[2]);m.Scenario=atoi(argv[3]);m.Trial=&t;m.Power=&t.Power;m.ClockVote=0x44302380;m.Enabled=1;m.EnableHighFlag=(int)0x80000000u;
 memcpy(m.Reg,Rb,sizeof(Rb));m.Reg[12]=0x80000001;memcpy(m.Dfs,NativeDfs,sizeof(NativeDfs));for(i=0;i<4;i++)m.Pad[i]=0x85;
 for(i=0;i<3;i++){m.ObsCmd[i]=0x08000007;m.PinCtl[i]=i==0?0x281:i==1?0x2c0:0xc0;m.PinLatch[i]=i<2?2:0;}
 for(i=0;i<24;i++)m.Spi[ConfigOffsets[i]/4]=G43HeldEngine[i];m.Spi[0x68/4]=m.Spi[0x6c/4]=0x102;m.Spi[0xe24/4]=0x20102864;m.Spi[0xe28/4]=0x20104800;
 m.Spi[0x600/4]=0x18000000;m.Spi[0x26c/4]=m.Spi[0x270/4]=36;m.Spi[0x610/4]=0x80;m.Spi[0x640/4]=0x0c000000;
 if(m.Scenario==200)m.Spi[0x40/4]=1;if(m.Scenario==202)m.RxWords=1;if(m.Scenario==203)m.Spi[0x640/4]|=0x200;
 if(m.Scenario==204)m.Spi[0x610/4]|=0x200000;if(m.Scenario==205)m.ClockVote^=0x100;
 if(m.Scenario==206)m.Spi[0x268/4]^=1;if(m.Scenario==208)m.PinCtl[0]|=0x1000;if(m.Scenario==213)m.Delay=2;
 io.Rsc.Context=&m;io.Rsc.Read=Read;io.Rsc.Write=Write;io.Rsc.WaitMillisecond=Wait1;io.Observer.Context=&m;io.Observer.Read=Read;io.Observer.Write=Write;io.Observer.WaitMicrosecond=WaitUs;io.WaitTenMilliseconds=Wait10;
 touch.Context=&m;touch.Read=Read;touch.Write=Write;touch.WaitMs=WaitMs;
 G43RecoverHeld(&io,&touch,&t);physical=Restored(&m);
 printf("{\"power_code\":%u,\"power_restore_error\":%u,\"power_restored\":%u,\"touch_code\":%u,\"touch_restore_error\":%u,\"touch_restored\":%u,\"spi_restored\":%u,\"engine_restored\":%u,\"physical_model_restored\":%d,\"safe_release\":%u,\"reads\":%d,\"writes\":%d,\"commands\":%u,\"enables\":%d,\"releases\":%d,\"M_ACKs\":%u,\"S_ACKs\":%u,\"RSC_transactions\":%u,\"enabled\":%d}\n",t.Power.Code,t.Power.RestoreError,t.Power.Restored,t.Touch.Code,t.Touch.RestoreError,t.Touch.Restored,t.Spi.Restored,t.Spi.Engine.Restored,physical,t.SafeRelease,m.Reads,m.Writes,m.SpiCommands,m.Enables,m.Releases,m.MAcks,m.SAcks,t.Power.TxnCount,m.Enabled);
 if(argc==5){
  typedef struct {uint32_t Size,Version;uint64_t Magic;uint32_t Build,Processors,Irql,FirmwareBytes,FirmwareMatch,RegisterCount,FirmwareStatus,Maps;uint64_t Sequence,Time;uint8_t BuildId[16];} Status;
  struct {Status S;G43_TRIAL_RESULT T;uint32_t Fixed,Attempt;uint64_t Ticks,Frequency;} out;
  FILE*f;memset(&out,0,sizeof(out));out.S.Size=80;out.S.Version=1;out.S.Magic=0x314f52463334474fULL;out.S.Build=26100;out.S.Processors=8;out.S.FirmwareBytes=576;out.S.FirmwareMatch=1;out.S.RegisterCount=50;out.S.Maps=28;memcpy(out.S.BuildId,"G43-recover1",13);out.T=t;out.Fixed=out.Attempt=1;out.Frequency=19200000;f=fopen(argv[4],"wb");if(!f||sizeof(out)!=55864||fwrite(&out,1,sizeof(out),f)!=sizeof(out))return 80;fclose(f);
 }
 return 0;
}
