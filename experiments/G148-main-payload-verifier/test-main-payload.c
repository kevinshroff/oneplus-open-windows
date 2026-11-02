/* Actual verifier/streaming SHA C; admitted memory and reads are model inputs. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#undef NULL
#include "OpenMainPayload.c"
#include "model-fixtures.h"
static OMP_CHECKER Checker;
static const char *Case;
static UINT8 *Ram;
static unsigned Reads,Owners,Admissions,PreAdmitted,OwnerGone,Cookie,Cases;
static int Is(const char*s){return !strcmp(Case,s);}
VOID*EFIAPI CopyMem(VOID*d,CONST VOID*s,UINTN n){return memcpy(d,s,n);}
VOID*EFIAPI ZeroMem(VOID*d,UINTN n){return memset(d,0,n);}
VOID*EFIAPI SetMem(VOID*d,UINTN n,UINT8 v){return memset(d,v,n);}
INTN EFIAPI CompareMem(CONST VOID*a,CONST VOID*b,UINTN n){return memcmp(a,b,n);}
static unsigned Find(UINT64 at,UINTN n){
 for(unsigned i=0;i<OMP_EXTENTS;i++){
  UINT64 base=ModelBase[i],bytes=ModelBytes[i];
  if(at>=base&&at<base+bytes&&n<=base+bytes-at)return i;
 }
 assert(!"Read outside exact original loader extent");return OMP_EXTENTS;
}
static unsigned EFIAPI Owner(VOID*ctx){
 assert(ctx==&Cookie);Owners++;
 if(Is("reentrant-owner")&&Owners==1)assert(OpenMainPayloadVerify(&Checker)==EFI_ACCESS_DENIED);
 if(Is("owner-initial"))return 0;
 if(Is("owner-noncanonical"))return 2;
 if(Is("owner-before-read")&&Owners==3)return 0;
 if(Is("owner-after-read")&&Reads)return 0;
 return !OwnerGone;
}
static unsigned EFIAPI ModelAdmit(VOID*ctx){
 assert(ctx==&Cookie&&Admissions<2);Admissions++;
 if(Is("reentrant-admit")&&Admissions==1)assert(OpenMainPayloadVerify(&Checker)==EFI_ACCESS_DENIED);
 if(Is("admit-before")&&Admissions==1)return 0;
 if(Is("admit-before-noncanonical")&&Admissions==1)return 2;
 if(Admissions==1)PreAdmitted=1;
 if(Is("admit-after")&&Admissions==2)return 0;
 if(Is("admit-after-noncanonical")&&Admissions==2)return 2;
 if(Is("owner-after-final-admit")&&Admissions==2)OwnerGone=1;
 return 1;
}
static EFI_STATUS EFIAPI Read(VOID*ctx,UINT64 at,UINTN*n,VOID*out){
 assert(ctx==&Cookie&&PreAdmitted&&!OwnerGone&&n&&*n>0&&*n<=OMP_CHUNK&&out==Checker.Scratch);
 unsigned index=Find(at,*n);Reads++;
 assert(at!=0xc7b7000&&at!=0xc7b7008&&at!=0xb000000);
 if((Is("read-error-first")&&Reads==1)||(Is("read-error-last")&&index==88))return EFI_DEVICE_ERROR;
 if(Is("read-warning"))return 1;
 UINTN count=*n;
 if((Is("short-first")&&Reads==1)||(Is("short-last")&&index==88))count--;
 if(Is("zero-producer-omits-byte")&&mMainPlan[index].Kind==2)count--;
 memcpy(out,Ram+at-0x9ea00000,count);
 if(!Is("zero-producer-omits-byte"))*n=count;
 if(Is("oversize-read"))*n=OMP_CHUNK+1;
 if(Is("reentrant-read")&&Reads==1)assert(OpenMainPayloadVerify(&Checker)==EFI_ACCESS_DENIED);
 return EFI_SUCCESS;
}
static unsigned KindIndex(unsigned kind,unsigned ordinal){
 for(unsigned i=0;i<OMP_EXTENTS;i++)if(mMainPlan[i].Kind==kind&&ordinal--==0)return i;
 assert(!"Bad test extent ordinal");return OMP_EXTENTS;
}
static void Run(const char*name){
 Case=name;Reads=Owners=Admissions=PreAdmitted=OwnerGone=0;memset(&Checker,0,sizeof(Checker));
 assert(OpenMainPayloadVerify(&Checker)==EFI_INVALID_PARAMETER&&!Reads);
 assert(OpenMainPayloadInit(&Checker,Read,ModelAdmit,Owner,&Cookie)==EFI_SUCCESS);
 assert(sizeof(Checker.Report)==6536&&Checker.Report.Size==6536&&Checker.Report.Version==1);
 UINT64 changed[5]={0};UINT8 prior[5]={0};unsigned changes=0;
 if(!strncmp(name,"hash-",5)||!strncmp(name,"zero-",5)&&!Is("zero-producer-omits-byte")){
  unsigned kind=!strncmp(name,"hash-",5)?1:2;
  unsigned ordinal=strstr(name,"first")?0:strstr(name,"middle")?(kind==1?27:17):(kind==1?53:34);
  unsigned index=KindIndex(kind,ordinal);changed[0]=mMainPlan[index].Base+mMainPlan[index].Bytes-1;changes=1;
 }else if(Is("changed-untouched")){
  for(unsigned i=0;i<5;i++)changed[changes++]=Untouched[i][0];
 }
 for(unsigned i=0;i<changes;i++){UINTN n=(UINTN)(changed[i]-0x9ea00000);prior[i]=Ram[n];Ram[n]^=0x5a;}
 assert(!mprotect(Ram,0x4880000,PROT_READ));
 EFI_STATUS s=OpenMainPayloadVerify(&Checker);OMP_REPORT*r=&Checker.Report;
 assert(!mprotect(Ram,0x4880000,PROT_READ|PROT_WRITE));
 for(unsigned i=0;i<changes;i++)Ram[changed[i]-0x9ea00000]=prior[i];
 assert(r->Status==s&&r->Attempted==1&&!Checker.Busy&&r->ReadCalls==Reads&&r->OwnerChecks==Owners&&r->AdmissionCalls==Admissions);
 assert(r->ReadBytes<=64910785&&r->VerifiedBytes<=r->ReadBytes&&r->CompletedExtents<=89);
 if(Is("success")||Is("changed-untouched")){
  assert(s==EFI_SUCCESS&&r->Complete&&r->Phase==OMP_DONE&&!r->Fault&&r->CompletedExtents==89&&r->CompletedFiles==54&&r->CompletedZeroTails==35&&r->ReadBytes==64910785&&r->VerifiedBytes==64910785&&Admissions==2&&Reads==ExpectedReads&&Owners==2*Reads+4);
  for(unsigned i=0;i<89;i++)assert(r->Extents[i].Complete&&r->Extents[i].Status==0&&r->Extents[i].ReadBytes==mMainPlan[i].Bytes);
 }else{
  assert(s!=EFI_SUCCESS&&!r->Complete&&r->Fault);
  if(!strncmp(name,"hash-",5))assert(r->Fault==OMP_HASH&&s==EFI_SECURITY_VIOLATION&&r->FailureAddress==mMainPlan[r->CurrentIndex].Base&&!r->Extents[r->CurrentIndex].Complete);
  else if(!strncmp(name,"zero-",5))assert(r->Fault==OMP_ZERO&&s==EFI_SECURITY_VIOLATION);
  else if(strstr(name,"reentrant"))assert(r->Fault&OMP_REENTRANT);
  else if(!strncmp(name,"owner-",6))assert(r->Fault==OMP_OWNER);
  else if(!strncmp(name,"admit-before",12))assert(r->Fault==OMP_ADMISSION&&!Reads&&Admissions==1);
  else if(!strncmp(name,"admit-after",11))assert(r->Fault==OMP_POST_ADMISSION&&r->CompletedExtents==89&&r->VerifiedBytes==64910785&&Admissions==2);
  else if(!strncmp(name,"read-",5)){assert(r->Fault==OMP_READ_ERROR&&s==EFI_DEVICE_ERROR);if(Is("read-warning"))assert(r->LastReadStatus==1);}
  else assert(r->Fault==OMP_READ_SIZE&&s==EFI_BAD_BUFFER_SIZE);
  if(changes&&mMainPlan[r->CurrentIndex].Kind==2)assert(r->FailureAddress==changed[0]);
 }
 OMP_REPORT saved=*r;unsigned reads=Reads,owners=Owners,admissions=Admissions;
 assert(OpenMainPayloadVerify(&Checker)==EFI_ALREADY_STARTED&&OpenMainPayloadInit(&Checker,Read,ModelAdmit,Owner,&Cookie)==EFI_ALREADY_STARTED);
 assert(!memcmp(&saved,r,sizeof(saved))&&reads==Reads&&owners==Owners&&admissions==Admissions);
 Cases++;printf("{\"case\":\"%s\",\"status\":\"%llx\",\"fault\":%u,\"complete\":%u,\"reads\":%u,\"admissions\":%u,\"verified_bytes\":%llu}\n",name,(unsigned long long)s,r->Fault,r->Complete,Reads,Admissions,(unsigned long long)r->VerifiedBytes);
}
int main(int argc,char**argv){
 assert(argc==2);Ram=mmap(NULL,0x4880000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(Ram!=MAP_FAILED);memset(Ram,0xa5,0x4880000);
 for(unsigned i=0;i<OMP_EXTENTS;i++){
  const OMP_PLAN*p=&mMainPlan[i];assert(p->Base==ModelBase[i]&&p->Bytes==ModelBytes[i]&&p->Kind==ModelKind[i]);
  UINT8*dest=Ram+ModelBase[i]-0x9ea00000;
  if(ModelKind[i]==2){memset(dest,0,ModelBytes[i]);continue;}
  char path[2048];assert(FileName[i]);int n=snprintf(path,sizeof(path),"%s/%s",argv[1],FileName[i]);assert(n>0&&(unsigned)n<sizeof(path));FILE*f=fopen(path,"rb");assert(f);assert(fread(dest,1,ModelBytes[i],f)==ModelBytes[i]&&fgetc(f)==EOF&&!fclose(f));
 }
 OMP_CHECKER z={0};
 assert(OpenMainPayloadInit(NULL,Read,ModelAdmit,Owner,&Cookie)==EFI_INVALID_PARAMETER);
 assert(OpenMainPayloadInit(&z,NULL,ModelAdmit,Owner,&Cookie)==EFI_INVALID_PARAMETER);
 assert(OpenMainPayloadInit(&z,Read,NULL,Owner,&Cookie)==EFI_INVALID_PARAMETER);
 assert(OpenMainPayloadInit(&z,Read,ModelAdmit,NULL,&Cookie)==EFI_INVALID_PARAMETER);
 assert(OpenMainPayloadInit(&z,Read,ModelAdmit,Owner,NULL)==EFI_INVALID_PARAMETER&&!z.Initialized);Cases+=5;
 const char*names[]={"success","changed-untouched","owner-initial","owner-noncanonical","owner-before-read","owner-after-read","owner-after-final-admit","admit-before","admit-before-noncanonical","admit-after","admit-after-noncanonical","read-error-first","read-error-last","read-warning","short-first","short-last","oversize-read","hash-first","hash-middle","hash-last","zero-first","zero-middle","zero-last","zero-producer-omits-byte","reentrant-owner","reentrant-admit","reentrant-read"};
 for(unsigned i=0;i<sizeof(names)/sizeof(*names);i++)Run(names[i]);
 assert(!munmap(Ram,0x4880000));printf("{\"passed\":true,\"cases\":%u,\"actual_C_and_SHA\":true,\"ASan_UBSan\":true,\"native_operations\":0}\n",Cases);
}
