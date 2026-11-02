/* SPDX-License-Identifier: MIT
 * Actual policy code, native G144 INIT/MEM API fixtures; AUTH is modeled.
 * Qualification callbacks are test boundaries, never native ownership proof.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "OpenPasObserver.h"
#include "native-API-fixtures.h"
static OP_OBSERVER O;
static int Owner,Other;
static unsigned Calls,Copies,Payloads,Cases,Own,CopyResult,PayloadResult;
static unsigned LoseAtCopy,LoseAtPayload,NestAtCopy,NestAtPayload,NestOriginal;
static unsigned FailureStage,FailureKind;
static OP_U64 Call(unsigned stage);
static void Pass(const char *s){printf("%s\"%s\"",Cases?",":"",s);Cases++;}
static unsigned Verify(void *self){assert(self==&Owner);return Own;}
static unsigned CopyAdmission(void *self){
 assert(self==&Owner && Calls==2 && O.Busy && O.Phase[0]==2 && !O.CopyAllowed);
 assert(!O.AuthEnteredMask && !O.AuthAcceptedMask);Copies++;
 if(LoseAtCopy)Own=0;
 if(NestAtCopy){NestAtCopy=0;assert(Call(1)==OP_ERR(15));}
 return CopyResult;
}
static unsigned PayloadAdmission(void *self){
 assert(self==&Owner && Calls==2 && O.Busy && O.Phase[0]==2 && O.CopyAllowed==1);
 assert(!O.AuthEnteredMask && !O.AuthAcceptedMask);Payloads++;
 if(LoseAtPayload)Own=0;
 if(NestAtPayload){NestAtPayload=0;assert(Call(2)==OP_ERR(15));}
 return PayloadResult;
}
static OP_U64 Original(void *self,OP_U32 command,OP_U32 param,OP_U64 *args,OP_U64 *results){
 assert(self==&Owner && args && results && args[9]==0x99887766 && args[0]==36);
 unsigned stage=command==0x42000201?0:command==0x42000202?1:command==0x42000205?2:99;
 assert(stage<3 && Calls==stage && param==(stage==0?0x82u:stage==1?3u:1u));
 if(stage==2)assert(Copies==1 && Payloads==1 && O.CopyAllowed==1 && O.AuthEnteredMask==1);
 Calls++;
 OP_U64 status=stage<2?NativeStatus[stage]:0;
 if(stage<2)memcpy(results,NativeResults[stage],4*sizeof(*results));
 else{results[0]=1;results[1]=results[2]=results[3]=0;} /* explicit AUTH fixture */
 if(NestOriginal){NestOriginal=0;assert(Call(stage)==OP_ERR(15));}
 if(stage==FailureStage){
  if(FailureKind==1)status=OP_ERR(7);
  if(FailureKind==2)status=5;
  if(FailureKind==3)results[0]=0;
  if(FailureKind==4)results[1]=0xdead;
 }
 return status;
}
static void Reset(unsigned arm){
 Calls=Copies=Payloads=0;Own=CopyResult=PayloadResult=1;
 LoseAtCopy=LoseAtPayload=NestAtCopy=NestAtPayload=NestOriginal=0;FailureStage=99;FailureKind=0;
 OpenPasInit(&O,Original,&Owner,OP_ABI_ARMV8);
 O.Verify=Verify;O.AuthorizeDtbCopy=CopyAdmission;O.VerifyDtbPayload=PayloadAdmission;
 if(arm)assert(!OpenPasArm(&O));
}
static OP_U64 Call(unsigned stage){
 OP_U64 args[10]={36,stage==0?0x38000000:stage==1?0x9e980000:0,
  stage==1?0x80000:0,0,0,0,0,0,0,0x99887766},out[4]={0},before[10];
 memcpy(before,args,sizeof args);
 OP_U64 s=OpenPasCall(&O,&Owner,stage==2?0x42000205:0x42000201+stage,
                     stage==0?0x82:stage==1?3:1,args,out);
 assert(!memcmp(args,before,sizeof args));return s;
}
int main(void){
 printf("{\"passed\":true,\"results\":[");
 Reset(1);assert(!Call(0)&&!Call(1)&&!Call(2));
 assert(Calls==3&&Copies==1&&Payloads==1&&O.Phase[0]==3&&O.Phase[1]==0&&
        O.AuthEnteredMask==1&&O.AuthAcceptedMask==1&&O.CopyAllowed==1&&!O.Fault);
 for(unsigned n=0;n<3;n++)assert(O.Records[n].Entered&&O.Records[n].Returned&&
   !O.Records[n].OriginalStatus&&!O.Records[n].ReturnedStatus&&!O.Records[n].Refusal);
 Pass("one-DTB-sequence-with-separate-copy-and-payload-checks");
 assert(Call(2)==OP_ERR(15)&&Calls==3);Pass("duplicate-auth-not-forwarded");
 for(unsigned value=0;value<=2;value+=2){
  Reset(1);CopyResult=value;assert(!Call(0)&&Call(1)==OP_ERR(21));
  assert(Calls==2&&Copies==1&&!Payloads&&!O.CopyAllowed&&O.Phase[0]==2&&
   O.Fault==OP_COPY_ADMISSION&&O.Records[1].OriginalStatus==0&&O.Records[1].ReturnedStatus==OP_ERR(21));
  assert(Call(2)==OP_ERR(15)&&Calls==2&&!O.AuthEnteredMask);
  Pass(value?"noncanonical-copy-admission-refused":"copy-admission-denied-after-memory-success");
  Reset(1);PayloadResult=value;assert(!Call(0)&&!Call(1)&&Call(2)==OP_ERR(21));
  assert(Calls==2&&Copies==1&&Payloads==1&&O.Fault==OP_PAYLOAD_MISMATCH&&!O.AuthEnteredMask&&
    !O.Records[2].Entered&&!O.Records[2].Returned&&O.Phase[0]==2);
  Pass(value?"noncanonical-payload-check-refused":"payload-mismatch-stops-before-auth");
 }
 for(unsigned stage=0;stage<3;stage++)for(unsigned kind=1;kind<=4;kind++){
  Reset(1);for(unsigned n=0;n<stage;n++)assert(!Call(n));FailureStage=stage;FailureKind=kind;
  OP_U64 s=Call(stage);OP_RECORD*r=&O.Records[O.Count-1];
  assert(s==(kind==3?OP_ERR(33):OP_ERR(7))&&r->Entered&&r->Returned&&Calls==stage+1);
  assert(O.Fault==(kind<=2?OP_TRANSPORT:kind==3?OP_RESULT_HEADER:OP_SERVICE_RESULT));
  if(kind==1)assert(r->OriginalStatus==OP_ERR(7));
  if(kind==2)assert(r->OriginalStatus==5);
  assert(O.Phase[0]==stage&&!O.AuthAcceptedMask);
  assert(Copies==(stage==2?1u:0u)&&Payloads==(stage==2?1u:0u));
  assert(O.AuthEnteredMask==(stage==2?1u:0u));
  assert(Call(stage)==OP_ERR(15)&&Calls==stage+1);
  char label[64];snprintf(label,sizeof label,"stage-%u-error-%u-retained-no-retry",stage,kind);Pass(label);
 }
 for(unsigned mode=0;mode<4;mode++){
  Reset(1);if(mode==0)LoseAtCopy=1;if(mode==1)LoseAtPayload=1;if(mode==2)NestAtCopy=1;if(mode==3)NestAtPayload=1;
  assert(!Call(0));
  if(mode==0||mode==2)assert(Call(1)==OP_ERR(15));
  else assert(!Call(1)&&Call(2)==OP_ERR(15));
  assert(Calls==2&&!O.AuthEnteredMask&&O.Fault==(mode<2?OP_OWNERSHIP:OP_REENTRANT));
  const char*names[]={"copy-callback-owner-change","payload-callback-owner-change","copy-callback-reentrancy","payload-callback-reentrancy"};Pass(names[mode]);
 }
 for(unsigned stage=0;stage<3;stage++){
  Reset(1);for(unsigned n=0;n<stage;n++)assert(!Call(n));NestOriginal=1;
  assert(Call(stage)==OP_ERR(15)&&Calls==stage+1&&O.Fault==OP_REENTRANT&&!O.AuthAcceptedMask);
  char label[64];snprintf(label,sizeof label,"original-stage-%u-reentrancy",stage);Pass(label);
 }
 for(unsigned which=0;which<3;which++){
  Reset(0);if(which==0)O.Verify=NULL;if(which==1)O.AuthorizeDtbCopy=NULL;if(which==2)O.VerifyDtbPayload=NULL;
  assert(OpenPasArm(&O)==OP_ERR(2)&&!O.Consumed&&!Calls);
  const char*names[]={"missing-owner-predicate","missing-copy-predicate","missing-payload-predicate"};Pass(names[which]);
 }
 Reset(1);assert(!Call(0));O.AuthorizeDtbCopy=NULL;assert(Call(1)==OP_ERR(21)&&Calls==2&&!O.CopyAllowed);Pass("copy-predicate-disappeared");
 Reset(1);assert(!Call(0)&&!Call(1));O.VerifyDtbPayload=NULL;assert(Call(2)==OP_ERR(21)&&Calls==2&&!O.AuthEnteredMask);Pass("payload-predicate-disappeared");
 Reset(1);assert(!Call(0)&&!Call(1));O.Verify=NULL;assert(Call(2)==OP_ERR(15)&&Calls==2&&!O.AuthEnteredMask);Pass("owner-predicate-disappeared");
 for(unsigned stage=0;stage<3;stage++){
  Reset(1);for(unsigned n=0;n<stage;n++)assert(!Call(n));
  OP_U64 args[10]={1,0x38000000,0,0,0,0,0,0,0,0x99887766},out[4]={0};
  assert(OpenPasCall(&O,&Owner,stage==2?0x42000205:0x42000201+stage,stage==0?0x82:stage==1?3:1,args,out)==OP_ERR(21));
  assert(Calls==stage&&O.Fault==OP_DIAGNOSTIC_STOP&&O.Phase[1]==0);
  char label[64];snprintf(label,sizeof label,"main-stage-%u-blocked",stage);Pass(label);
 }
 Reset(1);assert(!Call(0)&&!Call(1)&&!Call(2));
 {OP_U64 args[10]={1,0x38000000},out[4]={0};assert(OpenPasCall(&O,&Owner,0x42000201,0x82,args,out)==OP_ERR(21)&&Calls==3);}
 Pass("main-remains-blocked-after-DTB-success");
 Reset(1);{OP_U64 args[10]={36},out[4]={0};assert(OpenPasCall(&O,&Owner,0x42000206,1,args,out)==OP_ERR(15)&&!Calls&&O.Fault==OP_SHUTDOWN);}Pass("shutdown-not-forwarded");
 Reset(1);assert(Call(2)==OP_ERR(15)&&!Calls&&!O.AuthEnteredMask);Pass("AUTH-before-init-refused");
 Reset(1);assert(!Call(0));{OP_U64 args[10]={36,0xa9f80000,0x80000},out[4]={0};assert(OpenPasCall(&O,&Owner,0x42000202,3,args,out)==OP_ERR(2)&&Calls==1&&!Copies);}Pass("old-relocated-memory-base-refused");
 Reset(1);assert(!Call(0));{OP_U64 args[10]={36,0x9e980000,0x3000},out[4]={0};assert(OpenPasCall(&O,&Owner,0x42000202,3,args,out)==OP_ERR(2)&&Calls==1&&!Copies);}Pass("changed-reservation-size-refused");
 Reset(1);assert(!OpenPasDisarm(&O)&&OpenPasArm(&O)==OP_ERR(15));Pass("one-use-arm");
 Reset(1);{OP_U64 args[10]={36,0x38000000},out[4]={0};assert(OpenPasCall(&O,&Other,0x42000201,0x82,args,out)==OP_ERR(2)&&!Calls);}Pass("wrong-protocol-owner");
 printf("],\"cases\":%u,\"actual_observer_C\":true,\"ASan_UBSan\":true,\"native_operations\":0,\"hardware_admission\":\"modeled callbacks\",\"AUTH\":\"modeled API result\"}\n",Cases);
 return 0;
}
