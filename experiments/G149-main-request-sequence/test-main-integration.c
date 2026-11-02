/* Combine actual PAS policy and actual G148 verifier/SHA with captured files.
 * UEFI access/ownership, DTB success and all main secure replies remain models. */
#include "model-support.h"
#include "OpenPasObserver.h"
#include "native-API-fixtures.h"
static OP_OBSERVER Pas;
static int PasThis;
static unsigned PasCalls,MainCopies,MainChecks;
static unsigned PasOwner(VOID*self){assert(self==&PasThis);return !OwnerGone;}
static unsigned DtbReady(VOID*self){assert(self==&PasThis&&Pas.Busy);return 1;}
static unsigned MainCopy(VOID*self){
 assert(self==&PasThis&&Pas.Busy&&PasCalls==5&&Pas.DtbPublicComplete&&Pas.Phase[1]==2&&!Reads);
 MainCopies++;return 1;
}
static unsigned MainPayload(VOID*self){
 assert(self==&PasThis&&Pas.Busy&&PasCalls==5&&MainCopies==1&&Pas.CopyAllowed[1]==1&&!Reads);
 MainChecks++;return OpenMainPayloadVerify(&Checker)==EFI_SUCCESS;
}
static OP_U64 SecureFixture(VOID*self,OP_U32 command,OP_U32 param,OP_U64*args,OP_U64*results){
 unsigned index=PasCalls/3,stage=PasCalls%3;
 assert(PasCalls<6&&self==&PasThis&&Pas.Busy&&args[0]==(index?1u:36u)&&args[9]==0x99887766);
 assert(command==(stage==2?0x42000205u:0x42000201u+stage)&&param==(stage==0?0x82u:stage==1?3u:1u));
 if(index&&stage==2)assert(Checker.Report.Complete&&Checker.Report.VerifiedBytes==64910785&&Admissions==2&&Reads==ExpectedReads&&MainChecks==1);
 PasCalls++;
 if(!index&&stage<2){memcpy(results,NativeResults[stage],4*sizeof(*results));return NativeStatus[stage];}
 results[0]=1;results[1]=results[2]=results[3]=0;return 0;
}
static OP_U64 PasStep(unsigned index,unsigned stage){
 OP_U64 args[10]={index?1u:36u,stage==0?0x38000000:stage==1?(index?0x9ea00000:0x9e980000):0,stage==1?(index?0x4880000:0x80000):0,0,0,0,0,0,0,0x99887766},out[4]={0};
 return OpenPasCall(&Pas,&PasThis,stage==2?0x42000205u:0x42000201u+stage,stage==0?0x82u:stage==1?3u:1u,args,out);
}
static void Integrated(const char*name){
 Case=name;Reads=Owners=Admissions=PreAdmitted=OwnerGone=PasCalls=MainCopies=MainChecks=0;memset(&Checker,0,sizeof(Checker));assert(!OpenMainPayloadInit(&Checker,Read,ModelAdmit,Owner,&Cookie));
 OpenPasInit(&Pas,SecureFixture,&PasThis,OP_ABI_ARMV8);Pas.Verify=PasOwner;Pas.AuthorizeDtbCopy=DtbReady;Pas.VerifyDtbPayload=DtbReady;Pas.AuthorizeMainCopy=MainCopy;Pas.VerifyMainPayload=MainPayload;assert(!OpenPasArm(&Pas));
 UINT64 changed[5]={0};UINT8 prior[5]={0};unsigned changes=0;
 if(Is("hash-last")){unsigned index=KindIndex(1,53);changed[changes++]=ModelBase[index]+ModelBytes[index]-1;}
 if(Is("changed-untouched"))for(unsigned i=0;i<5;i++)changed[changes++]=Untouched[i][0];
 for(unsigned i=0;i<changes;i++){prior[i]=Ram[changed[i]-0x9ea00000];Ram[changed[i]-0x9ea00000]^=0x5a;}
 assert(!mprotect(Ram,0x4880000,PROT_READ));
 assert(!PasStep(0,0)&&!PasStep(0,1)&&!PasStep(0,2)&&!OpenPasFinishDtb(&Pas,0));
 assert(!PasStep(1,0)&&!PasStep(1,1)&&PasCalls==5&&!Reads);OP_U64 auth=PasStep(1,2);
 assert(!mprotect(Ram,0x4880000,PROT_READ|PROT_WRITE));for(unsigned i=0;i<changes;i++)Ram[changed[i]-0x9ea00000]=prior[i];
 if(Is("success")||Is("changed-untouched"))assert(!auth&&PasCalls==6&&Pas.Phase[1]==3&&Pas.AuthAcceptedMask==3&&!Pas.Fault&&Checker.Report.Complete);
 else assert(auth==OP_ERR(21)&&PasCalls==5&&Pas.Phase[1]==2&&Pas.AuthEnteredMask==1&&Pas.AuthAcceptedMask==1&&Pas.Fault==OP_PAYLOAD_MISMATCH&&!Pas.Records[5].Entered&&!Checker.Report.Complete);
 if(Is("admit-after"))assert(Checker.Report.VerifiedBytes==64910785&&Checker.Report.Fault==OMP_POST_ADMISSION);
 if(Is("hash-last"))assert(Checker.Report.Fault==OMP_HASH);
 assert(MainCopies==1&&MainChecks==1&&OpenMainPayloadVerify(&Checker)==EFI_ALREADY_STARTED&&!OpenPasDisarm(&Pas));
 printf("{\"case\":\"%s\",\"secure_calls_modeled\":%u,\"main_AUTH_forwarded\":%u,\"payload_complete\":%u,\"payload_fault\":%u,\"payload_read_calls\":%u,\"payload_verified_bytes\":%llu}\n",name,PasCalls,(Pas.AuthEnteredMask>>1)&1,Checker.Report.Complete,Checker.Report.Fault,Reads,(unsigned long long)Checker.Report.VerifiedBytes);
}
int main(int argc,char**argv){
 (VOID)Run; /* Reuse model helpers without rerunning their standalone suite. */
 assert(argc==2);Ram=mmap(NULL,0x4880000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(Ram!=MAP_FAILED);memset(Ram,0xa5,0x4880000);
 for(unsigned i=0;i<OMP_EXTENTS;i++){
  assert(mMainPlan[i].Base==ModelBase[i]&&mMainPlan[i].Bytes==ModelBytes[i]&&mMainPlan[i].Kind==ModelKind[i]);UINT8*dest=Ram+ModelBase[i]-0x9ea00000;
  if(ModelKind[i]==2){memset(dest,0,ModelBytes[i]);continue;}
  char path[2048];int n=snprintf(path,sizeof(path),"%s/%s",argv[1],FileName[i]);assert(n>0&&(unsigned)n<sizeof(path));FILE*f=fopen(path,"rb");assert(f&&fread(dest,1,ModelBytes[i],f)==ModelBytes[i]&&fgetc(f)==EOF&&!fclose(f));
 }
 const char*names[]={"success","hash-last","admit-after","changed-untouched"};for(unsigned i=0;i<4;i++)Integrated(names[i]);assert(!munmap(Ram,0x4880000));
 puts("{\"passed\":true,\"cases\":4,\"actual_PAS_and_main_verifier_C\":true,\"real_SHA\":true,\"ASan_UBSan\":true,\"native_operations\":0}");
}
