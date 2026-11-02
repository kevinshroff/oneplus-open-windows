/* Actual dual-image policy. Only native G144 DTB INIT/MEM tuples are native;
 * all main/DTB AUTH results, public returns and admission predicates are models. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "OpenPasObserver.h"
#include "native-API-fixtures.h"
static OP_OBSERVER O;
static int Protocol;
static unsigned Calls,Own,Copies[2],Payloads[2],CopyResult[2],PayloadResult[2],Cases;
static unsigned FailureAt,FailureKind,LoseCopy,LosePayload,NestCopy,NestPayload,NestApi,NestFinish;
static OP_U64 Step(unsigned,unsigned);
static void Pass(const char*s){printf("%s\"%s\"",Cases?",":"",s);Cases++;}
static unsigned Verify(void*self){
 assert(self==&Protocol);
 if(NestFinish){NestFinish=0;assert(Step(1,0)==OP_ERR(15));}
 return Own;
}
static unsigned Copy(unsigned index,void*self){
 assert(self==&Protocol&&O.Busy&&Calls==2+3*index&&O.Phase[index]==2&&!O.CopyAllowed[index]);Copies[index]++;
 if(LoseCopy==index+1)Own=0;
 if(NestCopy==index+1){NestCopy=0;assert(Step(index,1)==OP_ERR(15));}
 return CopyResult[index];
}
static unsigned Payload(unsigned index,void*self){
 assert(self==&Protocol&&O.Busy&&Calls==2+3*index&&O.Phase[index]==2&&O.CopyAllowed[index]==1);Payloads[index]++;
 if(LosePayload==index+1)Own=0;
 if(NestPayload==index+1){NestPayload=0;assert(Step(index,2)==OP_ERR(15));}
 return PayloadResult[index];
}
static unsigned DtbCopy(void*self){return Copy(0,self);}
static unsigned MainCopy(void*self){return Copy(1,self);}
static unsigned DtbPayload(void*self){return Payload(0,self);}
static unsigned MainPayload(void*self){return Payload(1,self);}
static OP_U64 Original(void*self,OP_U32 command,OP_U32 param,OP_U64*args,OP_U64*results){
 unsigned stage=Calls%3,index=Calls/3;assert(Calls<6&&self==&Protocol&&O.Busy&&args&&results&&args[9]==0x99887766);
 assert(args[0]==(index?1u:36u)&&command==(stage==2?0x42000205:0x42000201+stage)&&param==(stage==0?0x82:stage==1?3:1));
 if(index)assert(O.DtbPublicComplete&&O.AuthAcceptedMask>=1);
 if(stage==2)assert(Copies[index]==1&&Payloads[index]==1&&O.CopyAllowed[index]==1&&(O.AuthEnteredMask&(1u<<index)));
 unsigned number=Calls++;OP_U64 status=index==0&&stage<2?NativeStatus[stage]:0;
 if(index==0&&stage<2)memcpy(results,NativeResults[stage],4*sizeof(*results));else{results[0]=1;results[1]=results[2]=results[3]=0;}
 if(NestApi==number+1){NestApi=0;assert(Step(index,stage)==OP_ERR(15));}
 if(number==FailureAt){if(FailureKind==1)status=OP_ERR(7);if(FailureKind==2)status=5;if(FailureKind==3)results[0]=0;if(FailureKind==4)results[1]=0xdead;}
 return status;
}
static void Reset(unsigned arm){
 Calls=0;Own=1;memset(Copies,0,sizeof(Copies));memset(Payloads,0,sizeof(Payloads));
 CopyResult[0]=CopyResult[1]=PayloadResult[0]=PayloadResult[1]=1;
 FailureAt=99;FailureKind=LoseCopy=LosePayload=NestCopy=NestPayload=NestApi=NestFinish=0;
 OpenPasInit(&O,Original,&Protocol,OP_ABI_ARMV8);O.Verify=Verify;O.AuthorizeDtbCopy=DtbCopy;O.VerifyDtbPayload=DtbPayload;O.AuthorizeMainCopy=MainCopy;O.VerifyMainPayload=MainPayload;
 if(arm)assert(!OpenPasArm(&O));
}
static OP_U64 Step(unsigned index,unsigned stage){
 OP_U64 args[10]={index?1u:36u,stage==0?0x38000000:stage==1?(index?0x9ea00000:0x9e980000):0,stage==1?(index?0x4880000:0x80000):0,0,0,0,0,0,0,0x99887766},out[4]={0},before[10];memcpy(before,args,sizeof(args));
 OP_U64 s=OpenPasCall(&O,&Protocol,stage==2?0x42000205:0x42000201+stage,stage==0?0x82:stage==1?3:1,args,out);assert(!memcmp(before,args,sizeof(args)));return s;
}
static void Dtb(unsigned finish){assert(!Step(0,0)&&!Step(0,1)&&!Step(0,2)&&Calls==3);if(finish)assert(!OpenPasFinishDtb(&O,0));}
int main(void){
 printf("{\"passed\":true,\"results\":[");
 Reset(1);Dtb(1);assert(!Step(1,0)&&!Step(1,1)&&!Step(1,2));
 assert(Calls==6&&O.Count==6&&O.Phase[0]==3&&O.Phase[1]==3&&O.AuthEnteredMask==3&&O.AuthAcceptedMask==3&&O.CopyAllowed[0]==1&&O.CopyAllowed[1]==1&&!O.Fault);
 for(unsigned i=0;i<6;i++)assert(O.Records[i].Entered&&O.Records[i].Returned&&!O.Records[i].OriginalStatus&&!O.Records[i].ReturnedStatus&&!O.Records[i].Refusal);
 Pass("DTB-public-completion-and-distinct-main-copy-payload-grants");
 assert(Step(1,2)==OP_ERR(15)&&Calls==6);Pass("main-AUTH-duplicate-denied");
 Reset(1);Dtb(0);assert(Step(1,0)==OP_ERR(21)&&Calls==3&&O.Fault==OP_DTB_PUBLIC);Pass("accepted-DTB-AUTH-without-public-return-is-insufficient");
 for(unsigned status=7;status<=9;status+=2){
  Reset(1);Dtb(0);assert(OpenPasFinishDtb(&O,status)==OP_ERR(7)&&O.DtbPublicStatus==status&&O.AuthAcceptedMask==1&&O.Fault==OP_DTB_PUBLIC);assert(Step(1,0)==OP_ERR(15)&&Calls==3);Pass(status==7?"late-DTB-public-failure-retains-accepted-AUTH":"duplicate-DTB-public-status9-denies-main");
 }
 Reset(1);Dtb(1);assert(OpenPasFinishDtb(&O,0)==OP_ERR(15)&&O.Fault==OP_ORDER);Pass("public-completion-is-one-use");
 for(unsigned phase=0;phase<3;phase++){
  Reset(1);for(unsigned i=0;i<phase;i++)assert(!Step(0,i));assert(OpenPasFinishDtb(&O,0)==OP_ERR(15)&&!O.DtbPublicComplete&&O.Fault==OP_ORDER);Pass("public-mark-before-DTB-AUTH-is-refused");
 }
 Reset(0);assert(OpenPasFinishDtb(&O,0)==OP_ERR(15)&&!Calls);Pass("unarmed-context-cannot-import-DTB-success");
 Reset(1);Dtb(0);assert(!OpenPasDisarm(&O)&&OpenPasFinishDtb(&O,0)==OP_ERR(15));Pass("disarmed-context-cannot-complete-DTB");
 for(unsigned value=0;value<=2;value+=2){
  Reset(1);Dtb(0);Own=value;assert(OpenPasFinishDtb(&O,0)==OP_ERR(15)&&!O.DtbPublicComplete&&O.Fault==OP_OWNERSHIP);Pass(value?"noncanonical-public-owner-refused":"public-owner-lost");
  Reset(1);Dtb(1);CopyResult[1]=value;assert(!Step(1,0)&&Step(1,1)==OP_ERR(21)&&Calls==5&&O.Phase[1]==2&&!O.CopyAllowed[1]&&O.Fault==OP_COPY_ADMISSION&&O.AuthAcceptedMask==1);assert(Step(1,2)==OP_ERR(15)&&Calls==5);Pass(value?"noncanonical-main-copy-refused":"main-MEM-success-not-copy-permission");
  Reset(1);Dtb(1);PayloadResult[1]=value;assert(!Step(1,0)&&!Step(1,1)&&Step(1,2)==OP_ERR(21)&&Calls==5&&O.Fault==OP_PAYLOAD_MISMATCH&&O.AuthEnteredMask==1&&!O.Records[5].Entered);Pass(value?"noncanonical-main-payload-refused":"main-payload-failure-prevents-AUTH");
 }
 Reset(1);Dtb(0);NestFinish=1;assert(OpenPasFinishDtb(&O,0)==OP_ERR(15)&&O.Fault==OP_REENTRANT&&!O.DtbPublicComplete&&Calls==3);Pass("public-mark-owner-reentrancy-refused");
 for(unsigned stage=0;stage<3;stage++)for(unsigned kind=1;kind<=4;kind++){
  Reset(1);Dtb(1);for(unsigned n=0;n<stage;n++)assert(!Step(1,n));FailureAt=3+stage;FailureKind=kind;
  OP_U64 s=Step(1,stage);OP_RECORD*r=&O.Records[O.Count-1];assert(s==(kind==3?OP_ERR(33):OP_ERR(7))&&Calls==4+stage&&r->Entered&&r->Returned&&O.Phase[1]==stage&&O.AuthAcceptedMask==1);
  assert(O.Fault==(kind<=2?OP_TRANSPORT:kind==3?OP_RESULT_HEADER:OP_SERVICE_RESULT));if(kind==2)assert(r->OriginalStatus==5);
  assert(Step(1,stage)==OP_ERR(15)&&Calls==4+stage);char label[64];snprintf(label,sizeof(label),"main-stage-%u-error-%u-preserved-no-retry",stage,kind);Pass(label);
 }
 for(unsigned mode=0;mode<4;mode++){
  Reset(1);Dtb(1);if(mode==0)LoseCopy=2;if(mode==1)LosePayload=2;if(mode==2)NestCopy=2;if(mode==3)NestPayload=2;
  assert(!Step(1,0));if(mode==0||mode==2)assert(Step(1,1)==OP_ERR(15));else assert(!Step(1,1)&&Step(1,2)==OP_ERR(15));
  assert(Calls==5&&O.AuthEnteredMask==1&&O.Fault==(mode<2?OP_OWNERSHIP:OP_REENTRANT));Pass("main-predicate-owner-or-reentrancy-failure-refused");
 }
 for(unsigned stage=0;stage<3;stage++){
  Reset(1);Dtb(1);for(unsigned n=0;n<stage;n++)assert(!Step(1,n));NestApi=4+stage;assert(Step(1,stage)==OP_ERR(15)&&Calls==4+stage&&O.AuthAcceptedMask==1&&O.Fault==OP_REENTRANT);Pass("main-original-call-reentrancy-refused");
 }
 for(unsigned which=0;which<2;which++){
  Reset(0);if(which)O.VerifyMainPayload=NULL;else O.AuthorizeMainCopy=NULL;assert(OpenPasArm(&O)==OP_ERR(2)&&!O.Consumed);Pass("missing-main-predicate-cannot-arm");
  Reset(1);Dtb(1);assert(!Step(1,0));if(which){assert(!Step(1,1));O.VerifyMainPayload=NULL;assert(Step(1,2)==OP_ERR(21)&&Calls==5);}else{O.AuthorizeMainCopy=NULL;assert(Step(1,1)==OP_ERR(21)&&Calls==5);}Pass("main-predicate-disappeared-fails-closed");
 }
 Reset(1);Dtb(1);assert(!Step(1,0));{OP_U64 args[10]={1,0xaa000000,0x4880000},out[4]={0};assert(OpenPasCall(&O,&Protocol,0x42000202,3,args,out)==OP_ERR(2)&&Calls==4);}Pass("relocated-main-base-refused");
 Reset(1);Dtb(1);assert(!Step(1,0));{OP_U64 args[10]={1,0x9ea00000,0x4881000},out[4]={0};assert(OpenPasCall(&O,&Protocol,0x42000202,3,args,out)==OP_ERR(2)&&Calls==4);}Pass("changed-main-reservation-refused");
 for(unsigned image=0;image<2;image++){
  Reset(1);Dtb(1);OP_U64 args[10]={image?1:36},out[4]={0};assert(OpenPasCall(&O,&Protocol,0x42000206,1,args,out)==OP_ERR(15)&&Calls==3&&O.Fault==OP_SHUTDOWN);Pass("shutdown-remains-blocked-after-public-DTB-completion");
 }
 Reset(1);Dtb(1);assert(!Step(1,0)&&!Step(1,1)&&!Step(1,2));assert(!OpenPasDisarm(&O)&&OpenPasArm(&O)==OP_ERR(15));Pass("complete-dual-sequence-cannot-rearm");
 printf("],\"cases\":%u,\"actual_observer_C\":true,\"ASan_UBSan\":true,\"native_operations\":0,\"main_API_and_public_return\":\"explicit models\"}\n",Cases);
}
