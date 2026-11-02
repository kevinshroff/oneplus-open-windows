/* SPDX-License-Identifier: MIT */
#include "g36_spi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct {
 int ReadFail,WriteFail,BaselineFlip,IdentityFlip,PadOwnerFlip,VoteOwnerFlip,Delay;
 unsigned Reads,Writes,Remaining;uint32_t Vote,Control[4];G36_SPI_RESULT *Result;
} Model;
static int Read(void *ctx,uint32_t at,uint32_t *out)
{
 static const uint32_t identities[7]={0x30090000,0,0,0x102,0x102,0x20102864,0x20104800};
 static const uint32_t addresses[7]={0xac0004,0xa90040,0xa90064,0xa90068,0xa9006c,0xa90e24,0xa90e28};
 Model*m=ctx;unsigned i;m->Reads++;if((int)m->Reads==m->ReadFail)return 0;
 if(at==0x152008){*out=m->Vote;if(m->VoteOwnerFlip&&m->Result->Stage==91){m->Vote^=0x80;*out=m->Vote;m->VoteOwnerFlip=0;}}
 else if(at==0x1184e4){*out=0x80004000;if(m->Vote&0x4000000){if(m->Remaining)m->Remaining--;else *out=0x4000;}}
 else if(at==0x1184f0)*out=0x80000000;
 else if(at==0x1184f4)*out=0x100000;
 else if(at==0x12327c)*out=0;
 else if(at==0x123280)*out=0x80000002;
 else if(at>=0xf12c000&&at<=0xf12f00c&&(at&0xfff)<=12){
  unsigned pin=(at-0xf12c000)/0x1000,off=(at&0xfff)/4;
  if(off==0){if((int)pin==m->PadOwnerFlip&&m->Result->Stage==90)m->Control[pin]|=0x1000;*out=m->Control[pin];}
  else if(off==1)*out=(m->Control[pin]==0x85&&pin==3)?1u:0u;
  else *out=off==2?0xe2:0;
 }else{
  for(i=0;i<7;i++)if(at==addresses[i]){
   if(!(m->Vote&0x4000000)||m->Remaining){fputs("engine read while clock off\n",stderr);exit(20);}
   *out=identities[i];if((int)i==m->IdentityFlip)*out^=1;return 1;
  }
  fprintf(stderr,"unexpected read %x\n",at);exit(21);
 }
 if(m->Result->Stage==1&&(int)m->Reads==m->BaselineFlip)*out^=1;
 return 1;
}
static int Write(void*ctx,uint32_t at,uint32_t value)
{
 Model*m=ctx;unsigned pin;m->Writes++;
 if(m->WriteFail==-(int)m->Writes)return 0;
 if(at==0x152008){
  if((value&~0x4300000u)!=0x40002380)exit(22);
  if(!(value&0x4000000))for(pin=0;pin<4;pin++)if(m->Control[pin]!=1)exit(23);
  m->Vote=value;if((value&0x4300000)==0x4300000)m->Remaining=(unsigned)m->Delay;
 }else{
  if(at<0xf12c000||at>0xf12f000||(at&0xfff)||(value!=1&&value!=0x85))exit(24);
  pin=(at-0xf12c000)/0x1000;m->Control[pin]=value;
 }
 return m->WriteFail!=(int)m->Writes;
}
static void Wait(void*ctx){(void)ctx;}
int main(int argc,char**argv)
{
 Model m;G36_SPI_RESULT r;G36_SPI_IO io;unsigned i;int restored;
 if(argc!=8)return 2;memset(&m,0,sizeof(m));memset(&r,0,sizeof(r));
 m.ReadFail=atoi(argv[1]);m.WriteFail=atoi(argv[2]);m.BaselineFlip=atoi(argv[3]);m.IdentityFlip=atoi(argv[4]);m.PadOwnerFlip=atoi(argv[5]);m.VoteOwnerFlip=atoi(argv[6]);m.Delay=atoi(argv[7]);if(m.Delay<0||m.Delay>8)return 2;
 m.Vote=0x40002380;for(i=0;i<4;i++)m.Control[i]=1;m.Result=&r;
 io.Context=&m;io.Read=Read;io.Write=Write;io.WaitMicrosecond=Wait;G36PrepareSpi(&io,&r);
 restored=m.Vote==0x40002380;for(i=0;i<4;i++)restored=restored&&m.Control[i]==1;
 printf("{\"code\":%u,\"restore_error\":%u,\"restored\":%u,\"physical_model_restored\":%d,\"reads\":%u,\"writes\":%u,\"stage\":%u,\"dirty_pins\":%u,\"vote\":%u,\"trace\":[",r.Code,r.RestoreError,r.Restored,restored,r.Reads,r.Writes,r.Stage,r.DirtyPins,m.Vote);
 for(i=0;i<r.TraceCount;i++)printf("%s[%u,%u,%u]",i?",":"",r.Trace[i].Kind,r.Trace[i].Address,r.Trace[i].Value);puts("]}");return 0;
}
