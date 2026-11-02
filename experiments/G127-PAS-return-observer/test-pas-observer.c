/* SPDX-License-Identifier: MIT */
#include "OpenPasObserver.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "fixtures.h"
static OP_OBSERVER O;
static unsigned Calls,Reenter,Reentered;
static OP_U64 Status,Response[4];
static void *This=(void *)0x123400;
static OP_U64 Fake(void *self,OP_U32 cmd,OP_U32 param,OP_U64 *args,OP_U64 *result)
{
 (void)self;Calls++;
 if(Reenter&&!Reentered){Reentered=1;assert(OpenPasCall(&O,self,cmd,param,args,result)==OP_ERR(15));}
 if(result)for(unsigned i=0;i<4;i++)result[i]=Response[i];
 return Status;
}
static void Reset(unsigned abi)
{
 Calls=Reenter=Reentered=0;Status=0;Response[0]=1;
 Response[1]=Response[2]=Response[3]=0;
 OpenPasInit(&O,Fake,This,abi);assert(!OpenPasArm(&O));
}
static void Args(unsigned step,OP_U32 *cmd,OP_U32 *param,OP_U64 args[10])
{
 unsigned image=step<3?36:1,stage=step%3;
 for(unsigned i=0;i<10;i++)args[i]=0;
 *cmd=0x42000200u+(stage==2?5:stage+1);*param=stage==0?0x82:stage==1?3:1;
 args[0]=image;args[1]=stage==0?0x38000000ULL:stage==1?(image==36?0x9e980000ULL:0x9ea00000ULL):0;
 args[2]=stage==1?(image==36?0x80000ULL:0x4880000ULL):0;
}
static void Prime(unsigned steps)
{
 OP_U64 args[10],out[4];OP_U32 cmd,param;
 for(unsigned i=0;i<steps;i++){Args(i,&cmd,&param,args);assert(!OpenPasCall(&O,This,cmd,param,args,out));}
 assert(Calls==steps);
}
int main(void)
{
 unsigned tests=0,masked=0;
 for(unsigned i=0;i<sizeof(Fixtures)/sizeof(Fixtures[0]);i++){
  const Fixture *f=&Fixtures[i];Reset(f->ABI);
  unsigned stage=(f->Command&255)==1?0:(f->Command&255)==2?1:2;
  unsigned step=(f->Image==36?0:3)+stage;Prime(step);
  Status=f->Status;for(unsigned j=0;j<4;j++)Response[j]=f->Result[j];
  OP_U64 args[10]={f->Image,f->Arg1,f->Arg2},out[4]={0};unsigned before=Calls;
  OP_U64 rc=OpenPasCall(&O,This,f->Command,f->Param,args,out);
  assert(Calls==before+1&&!memcmp(out,Response,sizeof(out)));
  OP_RECORD *r=&O.Records[O.Count-1];assert(r->Entered&&r->Returned&&r->OriginalStatus==Status&&!memcmp(r->Results,Response,sizeof(out)));
  if(f->Good)assert(!rc&&!O.Fault&&O.Phase[f->Image==36?0:1]==stage+1);
  else {assert(rc>>63&&O.Fault);if(!Status&&Response[1])masked++;}
  assert(OpenPasCall(&O,This,f->Command,f->Param,args,out)>>63&&Calls==before+1);
  tests++;
 }
 assert(masked>=6);
 for(unsigned abi=1;abi<=2;abi++){
  Reset(abi);Prime(6);assert(O.AuthEnteredMask==3&&O.AuthAcceptedMask==3&&O.Phase[0]==3&&O.Phase[1]==3);
  assert(!OpenPasDisarm(&O)&&OpenPasArm(&O)==OP_ERR(15));tests++;
 }
 for(unsigned failure=0;failure<7;failure++){
  Reset(2);OP_U64 args[10]={36,0x38000000,0},out[4]={0};OP_U32 cmd=0x42000201,param=0x82;void *self=This;
  if(failure==0)args[1]=0;
  if(failure==1)self=(void *)1;
  if(failure==2)cmd=0x02000201;
  if(failure==3)cmd=0x82000201;
  if(failure==4)param=0xfffffff0;
  if(failure==5)args[0]=1;
  if(failure==6){cmd=0x42000206;param=1;}
  assert(OpenPasCall(&O,self,cmd,param,args,out)>>63&&!Calls&&O.Fault);tests++;
 }
 for(unsigned k=0;k<3;k++){
  Reset(2);Prime(1);OP_U64 args[10]={36,0x9e980000,0x80000},out[4];
  if(k==0)args[1]+=4096;if(k==1)args[2]-=4096;if(k==2)args[2]+=4096;
  assert(OpenPasCall(&O,This,0x42000202,3,args,out)==OP_ERR(2)&&Calls==1);tests++;
 }
 Reset(1);{OP_U64 args[10]={36,0x100000000ULL,0},out[4];assert(OpenPasCall(&O,This,0x42000201,0x82,args,out)==OP_ERR(2)&&!Calls);}tests++;
 Reset(1);{OP_U64 args[10]={0x100000024ULL,0x38000000,0},out[4];assert(OpenPasCall(&O,This,0x42000201,0x82,args,out)==OP_ERR(2)&&!Calls&&O.Fault);}tests++;
 Reset(1);{OP_U64 args[10]={36,0x38000000,0},out[4];assert(OpenPasCall(&O,This,0x42010201,0x82,args,out)==OP_ERR(2)&&!Calls&&O.Fault);}tests++;
 Reset(2);{OP_U64 args[10]={36,0x100000000ULL,0},out[4];assert(!OpenPasCall(&O,This,0x42000201,0x82,args,out)&&Calls==1);}tests++;
 for(unsigned k=0;k<3;k++){
  Reset(2);OP_U64 args[10]={36,0x38000000,0},out[4];O.Count=k==0?OP_RECORDS:k==1?OP_RECORDS+1:0xffffffffu;
  assert(OpenPasCall(&O,This,0x42000201,0x82,args,out)==OP_ERR(9)&&!Calls&&O.Fault==OP_CAPACITY);tests++;
 }
 for(unsigned k=0;k<2;k++){
  Reset(2);OP_U64 args[10]={36,0x38000000,0},out[4];
  assert(OpenPasCall(&O,This,0x42000201,0x82,k?args:NULL,k?NULL:out)==OP_ERR(2)&&!Calls);tests++;
 }
 Reset(2);Reenter=1;{OP_U64 args[10]={36,0x38000000,0},out[4];assert(OpenPasCall(&O,This,0x42000201,0x82,args,out)==OP_ERR(15)&&Calls==1&&(O.Fault&OP_REENTRANT));}tests++;
 Reset(2);O.Busy=1;assert(OpenPasDisarm(&O)==OP_ERR(6)&&O.Active);tests++;
 for(unsigned k=0;k<3;k++){
  Reset(2);OP_U64 args[10]={2,0xdead,0xbeef},out[4];Status=OP_ERR(7);
  if(k==0)assert(!OpenPasDisarm(&O));
  OP_U32 cmd=k==2?0x42000601:0x42000201;
  assert(OpenPasCall(&O,(void *)0xabc,cmd,0x55,args,out)==Status&&Calls==1&&!O.Count&&!O.Fault&&!memcmp(out,Response,sizeof(out)));tests++;
 }
 for(unsigned k=0;k<3;k++){
  Reset(2);OP_U64 args[10]={36,0x38000000,0},out[4];
  if(k==0)Status=1;if(k==1)Response[0]=0;if(k==2)Response[1]=1;
  assert(OpenPasCall(&O,This,0x42000201,0x82,args,out)>>63&&Calls==1&&O.Fault);tests++;
 }
 OpenPasInit(NULL,Fake,This,2);assert(OpenPasArm(NULL)==OP_ERR(2)&&OpenPasDisarm(NULL)==OP_ERR(2)&&OpenPasCall(NULL,This,0,0,NULL,NULL)==OP_ERR(2));tests++;
 for(unsigned k=0;k<2;k++){OpenPasInit(&O,Fake,This,k?3:0);assert(OpenPasArm(&O)==OP_ERR(2)&&!O.Active&&!O.Consumed);tests++;}
 printf("{\"passed\":true,\"cases\":%u,\"actual_original_SCM_fixtures\":%zu,\"masked_service_errors_rejected\":%u,\"ASan_UBSan\":true,\"native_operations\":0}\n",tests,sizeof(Fixtures)/sizeof(Fixtures[0]),masked);return 0;
}
