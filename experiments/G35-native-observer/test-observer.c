/* SPDX-License-Identifier: MIT
 * Run the actual portable observer core against a transaction/fault model.
 */
#include "g35_observer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "g35_fixture.h"
typedef struct {
 int ReadFail,WriteFail,Delay,BadRoute,Busy,BadStatusCommand,BadStatusMask,BadIdentity,BadByte;
 unsigned RawStatus,Reads,Writes,Requests,Active,Remaining;
 uint32_t Last[3],Data[2];
 G35_OBS_RESULT *Result;
} Model;
static uint32_t InitialValue(uint32_t at)
{
 unsigned i;for(i=0;i<sizeof(Initial)/sizeof(Initial[0]);i++)if(Initial[i].at==at)return Initial[i].value;
 fprintf(stderr,"unexpected model read address %x\n",at);exit(20);
}
static const uint32_t Bases[3]={0xc440ea0,0xc441220,0xc4456e0};
static int Read(void *context,uint32_t at,uint32_t *value)
{
 Model *m=context;unsigned i;
 if((int)++m->Reads==m->ReadFail)return 0;
 *value=InitialValue(at);
 if((at==0xc400000&&m->BadRoute==6)||(at==0xc400004&&m->BadRoute==7))*value^=1;
 for(i=0;i<3;i++){
  if(at==Bases[i]){*value=m->Last[i];return 1;}
  if(at==Bases[i]+8){
   if(m->Active&&i==(m->Active<=2?m->Active-1:2u)){
    if(m->Remaining){m->Remaining--;*value=0;}
    else *value=1|((int)m->Active-1==m->BadStatusCommand?(uint32_t)m->BadStatusMask:0u);
   }else *value=1;
   if(m->Result->Stage>=20&&m->Result->Stage<25&&(int)(m->Result->Stage-20)==m->Busy)*value=0;
   return 1;
  }
  if(at==Bases[i]+0x18||at==Bases[i]+0x1c){*value=m->Data[(at-Bases[i]-0x18)/4];return 1;}
 }
 for(i=0;i<3;i++){
  uint32_t apid=i==0?117:i==1?145:695;
  if(at==0xc402000+apid*4&&(int)(i*2)==m->BadRoute)*value^=0x100;
  if(at==0xc42d000+apid*4&&(int)(i*2+1)==m->BadRoute)*value^=1;
 }
 return 1;
}
static int Write(void *context,uint32_t at,uint32_t value)
{
 static const uint32_t Commands[5]={0x08000007,0x08000007,0x08000007,0x08000080,0x08000407};
 static const uint8_t Values[5][8]={{32,0,0,2,81,73,1,0},{0,4,1,1,4,172,0,0},
  {0,4,1,1,4,171,0,0},{0x43,0,0,0,0,0,0,0},{8,7,0,0,7,7,0,0}};
 Model *m=context;unsigned request=m->Requests,i;uint8_t b[8];m->Writes++;
 if(request>=5||at!=Bases[request<2?request:2]||value!=Commands[request]){
  fprintf(stderr,"unexpected observer WRITE %x %x at request %u\n",at,value,request);exit(21);
 }
 if(m->WriteFail==-(int)m->Writes)return 0;
 m->Last[request<2?request:2]=value;m->Active=++m->Requests;m->Remaining=(unsigned)m->Delay;
 memcpy(b,Values[request],8);
 if((int)request==m->BadIdentity)b[m->BadByte]^=1;
 if(request==3)b[0]=(uint8_t)m->RawStatus;
 m->Data[0]=m->Data[1]=0;
 for(i=0;i<8;i++)m->Data[i/4]|=(uint32_t)b[i]<<((i%4)*8);
 return m->WriteFail!=(int)m->Writes;
}
static void Wait(void *context){(void)context;}
static void Bytes(const uint8_t *p,unsigned length)
{
 unsigned i;printf("[");for(i=0;i<length;i++)printf("%s%u",i?",":"",p[i]);printf("]");
}
int main(int argc,char **argv)
{
 Model m;G35_OBS_RESULT r;G35_OBS_IO io;unsigned i;int args[9];
 memset(&m,0,sizeof(m));memset(&r,0,sizeof(r));m.BadRoute=m.Busy=m.BadStatusCommand=m.BadIdentity=-1;m.RawStatus=0x43;
 if(argc!=11)return 2;
 for(i=0;i<9;i++)args[i]=atoi(argv[i+1]);m.RawStatus=(unsigned)atoi(argv[10]);
 m.ReadFail=args[0];m.WriteFail=args[1];m.Delay=args[2];m.BadRoute=args[3];m.Busy=args[4];
 m.BadStatusCommand=args[5];m.BadStatusMask=args[6];m.BadIdentity=args[7];m.BadByte=args[8];m.Result=&r;
 if(m.BadByte<0||m.BadByte>7||m.Delay<0||m.Delay>12)return 2;
 for(i=0;i<3;i++)m.Last[i]=InitialValue(Bases[i]);
 io.Context=&m;io.Read=Read;io.Write=Write;io.WaitMicrosecond=Wait;G35Observe(&io,&r);
 printf("{\"code\":%u,\"stage\":%u,\"reads\":%u,\"writes\":%u,\"commands\":%u,\"polls\":%u,\"applied_commands\":%u,\"status\":%u,\"configuration\":",r.Code,r.Stage,r.Reads,r.Writes,r.Commands,r.Polls,m.Requests,r.Status);Bytes(r.Configuration,8);
 printf(",\"trace\":[");for(i=0;i<r.TraceCount;i++)printf("%s[%u,%u,%u]",i?",":"",r.Trace[i].Kind,r.Trace[i].Address,r.Trace[i].Value);puts("]}");return 0;
}
