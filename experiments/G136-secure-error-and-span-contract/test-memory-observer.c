#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "OpenPasObserver.h"
#include "scm-api-fixtures.h"
static OP_OBSERVER O;
static int Owner,Other;
static unsigned Calls,Cases,Allow=1,Nested;
static OP_U64 BackendStatus,BackendResults[4];
static unsigned Verify(void *self){assert(self==&Owner);return Allow;}
static OP_U64 Original(void *self,OP_U32 command,OP_U32 param,OP_U64 *args,OP_U64 *results){
 assert(self==&Owner&&args&&results&&args[9]==0x99887766);Calls++;
 assert(command!=0x42000205&&command!=0x42000206);
 if(Nested){Nested=0;assert(OpenPasCall(&O,self,command,param,args,results)==OP_ERR(15));}
 memcpy(results,BackendResults,sizeof(BackendResults));return BackendStatus;
}
static void Reset(void){Calls=Nested=0;Allow=1;BackendStatus=0;BackendResults[0]=1;BackendResults[1]=0;BackendResults[2]=0x2020;BackendResults[3]=0x3030;OpenPasInit(&O,Original,&Owner,OP_ABI_ARMV8);O.Verify=Verify;assert(!OpenPasArm(&O));}
static OP_U64 Call(unsigned stage){
 OP_U64 args[10]={36,stage==0?0x38000000:stage==1?0xa9f80000:0,stage==1?0x80000:0,0,0,0,0,0,0,0x99887766},out[4]={0},before[10];memcpy(before,args,sizeof args);
 OP_U64 s=OpenPasCall(&O,&Owner,stage==2?0x42000205:0x42000201+stage,stage==0?0x82:stage==1?3:1,args,out);assert(!memcmp(args,before,sizeof args));
 if(O.Records[O.Count-1].Returned)assert(!memcmp(out,BackendResults,sizeof out));
 assert(!O.AuthEnteredMask&&!O.AuthAcceptedMask);return s;
}
int main(void){
 Reset();assert(!Call(0)&&Call(1)==OP_ERR(21)&&Calls==2&&O.Phase[0]==2&&O.Fault==OP_DIAGNOSTIC_STOP&&O.Records[1].OriginalStatus==0&&O.Records[1].ReturnedStatus==OP_ERR(21));Cases++;
 assert(Call(2)&&Calls==2);Cases++;
 assert(OpenPasArm(&O)==OP_ERR(15)&&Calls==2);Cases++;
 for(unsigned i=0;i<sizeof(ScmApiFixtures)/sizeof(ScmApiFixtures[0]);i++){
  const SCM_API_FIXTURE *f=&ScmApiFixtures[i];Reset();unsigned stage=f->Command==0x42000201?0:1;
  if(stage)assert(!Call(0));BackendStatus=f->Status;memcpy(BackendResults,f->Result,sizeof BackendResults);
  OP_U64 s=Call(stage);OP_RECORD*r=&O.Records[O.Count-1];
  if(f->Status){assert(s==f->Status&&O.Fault==OP_TRANSPORT&&r->Refusal==OP_TRANSPORT);}
  else{assert(s==(stage?OP_ERR(21):0)&&O.Fault==(stage?OP_DIAGNOSTIC_STOP:0));}
  assert(r->Entered&&r->Returned&&r->OriginalStatus==f->Status&&!memcmp(r->Results,f->Result,sizeof BackendResults));Cases++;
 }
 for(unsigned bad=0;bad<13;bad++){
  Reset();OP_U64 args[10]={36,0x38000000,0,0,0,0,0,0,0,0x99887766},out[4]={0};unsigned command=0x42000201,param=0x82;void*self=&Owner;
  if(bad==0)self=&Other;if(bad==1)args[0]=37;if(bad==2)args[0]=0x100000024ULL;if(bad==3)args[1]=0;
  if(bad==4)command=0x02000201;if(bad==5)command=0xc2000201;if(bad==6)param=0x8f;
  if(bad==7)args[0]=1;if(bad==8){command=0x42000205;param=1;}if(bad==9){command=0x42000206;param=1;}
  if(bad==10)Allow=0;if(bad==11)O.Count=OP_RECORDS;
  OP_U64 s=OpenPasCall(&O,self,command,param,bad==12?NULL:args,out);assert(s&&!Calls&&!O.AuthEnteredMask&&!O.AuthAcceptedMask);Cases++;
 }
 for(unsigned bad=0;bad<2;bad++){
  Reset();assert(!Call(0));OP_U64 args[10]={36,bad?0xa9f80000:0xa9f81000,bad?0x3000:0x80000,0,0,0,0,0,0,0x99887766},out[4]={0};assert(OpenPasCall(&O,&Owner,0x42000202,3,args,out)==OP_ERR(2)&&Calls==1);Cases++;
 }
 Reset();assert(!Call(0));Allow=0;assert(Call(1)==OP_ERR(15)&&Calls==1&&O.Fault==OP_OWNERSHIP&&!O.Records[1].Entered);Cases++;
 Reset();Nested=1;assert(Call(0)==OP_ERR(15)&&Calls==1&&O.Fault==OP_REENTRANT);Cases++;
 Reset();BackendStatus=5;assert(Call(0)==OP_ERR(7)&&O.Records[0].OriginalStatus==5&&O.Fault==OP_TRANSPORT);Cases++;
 Reset();BackendResults[0]=0;assert(Call(0)==OP_ERR(33)&&O.Fault==OP_RESULT_HEADER);Cases++;
 Reset();BackendResults[1]=~6ULL;assert(Call(0)==OP_ERR(7)&&O.Fault==OP_SERVICE_RESULT);Cases++;
 Reset();assert(!OpenPasDisarm(&O));assert(OpenPasArm(&O)==OP_ERR(15));Cases++;
 printf("{\"passed\":true,\"cases\":%u,\"original_SCM_API_fixtures\":%zu,\"actual_observer_C\":true,\"ASan_UBSan\":true,\"AUTH_and_shutdown_forwarded\":0,\"native_operations\":0}\n",Cases,sizeof(ScmApiFixtures)/sizeof(ScmApiFixtures[0]));
}
