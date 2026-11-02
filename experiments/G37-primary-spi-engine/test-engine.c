/* SPDX-License-Identifier: MIT */
#include "g37_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const uint32_t Off[24]={0xe1c,0xe18,0x28,0x24,0x224,0x230,0x22c,0x250,0x24c,0x254,0x258,0x25c,0x260,0x264,0x268,0x278,0x284,0x288,0x7c,0x48,0x80c,0x810,0x814,0x614};
static const uint32_t Ga[10]={0xa90040,0xa90610,0xa90640,0xa90800,0xa90804,0x17100130,0x17100230,0x17100330,0x17100c60,0xa90064};
static const uint32_t Gm[10]={0x1001,0xffffffff,0xffffffff,0x0fffffff,0x81ffffff,0x20,0x20,0x20,0xc00,1};
typedef struct {uint32_t Reg[24],Initial[24],Dfs[25],DfsInitial[25];int Rfail,Wfail,GuardFlip,OwnerFlip,ClockMode,Delay,Remaining;unsigned Reads,Writes;G37_ENGINE_RESULT*R;} Model;
static int Read(void*context,uint32_t at,uint32_t*out)
{
 Model*m=context;unsigned i;m->Reads++;if((int)m->Reads==m->Rfail)return 0;
 for(i=0;i<24;i++)if(at==0xa90000+Off[i]){
  if(m->OwnerFlip==(int)i&&m->R->Stage==90){m->Reg[i]^=0x80000000;m->OwnerFlip=-1;}
  *out=m->Reg[i];return 1;
 }
 for(i=0;i<10;i++)if(at==Ga[i]){*out=m->GuardFlip==(int)i?Gm[i]:0;return 1;}
 if(at==0x118504){
  if(m->Remaining>0){m->Remaining--;if(!m->Remaining)m->Dfs[0]=1|(m->Reg[18]<<1);}
  *out=m->Dfs[0];return 1;
 }
 for(i=0;i<8;i++){
  if(at==0x11850c+i*4){*out=m->Dfs[1+i];return 1;}
  if(at==0x11854c+i*4){*out=m->Dfs[9+i];return 1;}
  if(at==0x11858c+i*4){*out=m->Dfs[17+i];return 1;}
 }
 if(at==0x1184f4){*out=m->ClockMode==3?0x100100:0x100000;return 1;}
 fprintf(stderr,"unexpected read%x\n",at);exit(20);
}
static int Write(void*context,uint32_t at,uint32_t value)
{
 Model*m=context;unsigned i;m->Writes++;if(m->Wfail==-(int)m->Writes)return 0;
 for(i=0;i<24;i++)if(at==0xa90000+Off[i]){
  m->Reg[i]=value;
  if(i==18&&(m->Dfs[0]&1)){
   if(m->Delay)m->Remaining=m->Delay;else m->Dfs[0]=1|(value<<1);
  }
  return m->Wfail!=(int)m->Writes;
 }
 fprintf(stderr,"unexpected write%x\n",at);exit(21);
}
static void Wait(void*c){(void)c;}
int main(int argc,char**argv)
{
 Model m;G37_ENGINE_RESULT r;G37_ENGINE_IO io;unsigned i;int restored;
 if(argc!=8)return 2;memset(&m,0,sizeof(m));memset(&r,0,sizeof(r));
 m.Rfail=atoi(argv[1]);m.Wfail=atoi(argv[2]);m.GuardFlip=atoi(argv[3]);m.OwnerFlip=atoi(argv[4]);m.ClockMode=atoi(argv[5]);m.Delay=atoi(argv[6]);
 if(m.Delay<0||m.Delay>9)return 2;
 for(i=0;i<24;i++)m.Reg[i]=0x80000000u|((i+1)*0x321u);
 m.Reg[11]|=1;m.Reg[18]=1;m.Dfs[0]=3;for(i=0;i<8;i++){m.Dfs[1+i]=0x100101;m.Dfs[9+i]=i;m.Dfs[17+i]=~i;}m.Dfs[1]=0x100000;
 if(m.ClockMode==1)for(i=0;i<8;i++)m.Dfs[1+i]=0x100100;
 if(m.ClockMode==2||m.ClockMode==3)m.Dfs[0]=0;
 if(m.ClockMode==4)m.Dfs[0]=5;
 if(m.ClockMode==5)m.Dfs[1]=0x100002;
 if(m.ClockMode==6)m.Dfs[1]=0x102000;
 if(m.ClockMode==7)m.Dfs[1]=0x100001;
 if(m.ClockMode==8)m.Dfs[1]=0;
 if(atoi(argv[7])){m.Reg[18]=0;m.Dfs[0]=1;}
 memcpy(m.Initial,m.Reg,sizeof(m.Reg));memcpy(m.DfsInitial,m.Dfs,sizeof(m.Dfs));m.R=&r;
 io.Context=&m;io.Read=Read;io.Write=Write;io.WaitMicrosecond=Wait;G37ConfigureEngine(&io,&r);
 restored=memcmp(m.Initial,m.Reg,sizeof(m.Reg))==0&&memcmp(m.DfsInitial,m.Dfs,sizeof(m.Dfs))==0;
 printf("{\"code\":%u,\"restore_error\":%u,\"restored\":%u,\"model_restored\":%d,\"reads\":%u,\"writes\":%u,\"stage\":%u,\"index\":%u,\"bus_hz\":%u,\"trace\":[",r.Code,r.RestoreError,r.Restored,restored,r.Reads,r.Writes,r.Stage,r.Index,r.BusHz);
 for(i=0;i<r.TraceCount;i++)printf("%s[%u,%u,%u]",i?",":"",r.Trace[i].Kind,r.Trace[i].Address,r.Trace[i].Value);puts("]}");return 0;
}
