/* Actual PAS policy, finite main admission and verifier/SHA are linked.
 * Original loader writes are pre-populated model RAM, not native file copies.
 * UEFI/AT/MMIO, protocol ownership and secure replies remain explicit models. */
#include "model-support.h"
#include "OpenPasObserver.h"
#include "native-API-fixtures.h"
#include <PiDxe.h>
#include "OpenMainAdmission.h"
#include "OpenDspAdmission.h"
#include "admission-fixtures.h"
static OP_OBSERVER Pas;
static int PasThis;
static unsigned PasCalls,MainCopies,MainChecks;
static EFI_BOOT_SERVICES Bs;
static EFI_DXE_SERVICES Ds;
EFI_BOOT_SERVICES *gBS=&Bs;
EFI_DXE_SERVICES *gDS=&Ds;
static unsigned CurrentCheck,Checks,CpuQueries,DeviceQueries,MmioReads,Live;
static void Log(const CHAR8*f,...){(VOID)f;}
VOID EFIAPI MemoryFence(VOID){__sync_synchronize();}
VOID *EFIAPI AllocatePool(UINTN n){assert(n<=0x10000&&!Live);Live++;return calloc(1,n);}
VOID EFIAPI FreePool(VOID*p){assert(p&&Live==1);Live--;free(p);}
static EFI_STATUS EFIAPI Gcd(EFI_PHYSICAL_ADDRESS at,EFI_GCD_MEMORY_SPACE_DESCRIPTOR*d){
 memset(d,0,sizeof(*d));
 if(at==0x9ea00000){
  CurrentCheck=Checks++;assert(CurrentCheck<3);CpuQueries=DeviceQueries=MmioReads=0;
  d->BaseAddress=0x8a800000;d->Length=0x18a80000;d->GcdMemoryType=EfiGcdMemoryTypeReserved;d->Capabilities=EFI_MEMORY_UC;
  if(Is("copy-gcd-owner")&&CurrentCheck==0)d->ImageHandle=(VOID*)1;
  return EFI_SUCCESS;
 }
 const UINT64 pages[]={0xaf08000,0xaf09000,0xae00000,0xae6a000,0xae6b000};
 unsigned i;for(i=0;i<5;i++)if(at==pages[i])break;assert(i<5);
 d->BaseAddress=at;d->Length=4096;d->GcdMemoryType=EfiGcdMemoryTypeMemoryMappedIo;d->Capabilities=EFI_MEMORY_UC;
 return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Map(UINTN*bytes,EFI_MEMORY_DESCRIPTOR*map,UINTN*key,UINTN*stride,UINT32*version){
 *stride=48;*version=1;*key=1;
 if(!map){*bytes=48;return EFI_BUFFER_TOO_SMALL;}
 assert(*bytes>=48&&Live==1);memset(map,0,48);*bytes=48;
 map->PhysicalStart=0x8a800000;map->NumberOfPages=0x18a80;map->Type=EfiReservedMemoryType;map->Attribute=EFI_MEMORY_UC;return EFI_SUCCESS;
}
OP_U64 OpenDspCurrentEl(VOID){return 1;}
OP_U64 OpenDspAt(VOID*ctx,OP_U64 at,unsigned write){
 assert(*(UINT64*)ctx==1&&!Live);
 if(at>=0x9ea00000&&at<0xa3280000){
  unsigned q=CpuQueries++;assert(q<31702&&at==ExpectedPages[q/2]&&write==(q&1));
  if(((Is("pre-AT-last-fault")&&CurrentCheck==1)||(Is("post-AT-last-fault")&&CurrentCheck==2))&&at==ExpectedPages[15850])return 1;
  return (0x44ULL<<56)|at;
 }
 const UINT64 pages[]={0xaf08000,0xaf09000,0xae00000,0xae6a000,0xae6b000};
 assert(!write&&DeviceQueries<5&&at==pages[DeviceQueries++]);return at;
}
UINT32 OpenMainModelRead(UINT64 at){
 assert(!Live&&CpuQueries==31702&&DeviceQueries==5);MmioReads++;
 const UINT64 clocks[]={0xaf08000,0xaf0800c,0xaf080a4,0xaf09000,0xaf09004};
 for(unsigned i=0;i<5;i++)if(at==clocks[i])return NativeClock[i];
 if(at==0xae00000)return NativeVersion;
 assert(at==0xae6a604||at==0xae6b604);
 if(((Is("pre-demura")&&CurrentCheck==1)||(Is("post-demura")&&CurrentCheck==2))&&at==0xae6b604)return 1;
 return 0;
}
static unsigned EFIAPI MainAdmit(VOID*ctx){
 assert(ctx==&Cookie&&Admissions<2);Admissions++;
 EFI_STATUS s=OpenMainRefreshAdmission(TRUE,Log);
 if(s==EFI_SUCCESS&&Admissions==1)PreAdmitted=1;
 if(Is("owner-after-final-admit")&&Admissions==2)OwnerGone=1;
 return s==EFI_SUCCESS;
}
static unsigned PasOwner(VOID*self){assert(self==&PasThis);return !OwnerGone;}
static unsigned DtbReady(VOID*self){assert(self==&PasThis&&Pas.Busy);return 1;}
static unsigned MainCopy(VOID*self){
 assert(self==&PasThis&&Pas.Busy&&PasCalls==5&&Pas.DtbPublicComplete&&Pas.Phase[1]==2&&!Reads);
 MainCopies++;return OpenMainAuthorizeCopy(TRUE,Log)==EFI_SUCCESS;
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
 Case=name;Reads=Owners=Admissions=PreAdmitted=OwnerGone=PasCalls=MainCopies=MainChecks=0;memset(&Checker,0,sizeof(Checker));assert(!OpenMainPayloadInit(&Checker,Read,MainAdmit,Owner,&Cookie));
 OpenPasInit(&Pas,SecureFixture,&PasThis,OP_ABI_ARMV8);Pas.Verify=PasOwner;Pas.AuthorizeDtbCopy=DtbReady;Pas.VerifyDtbPayload=DtbReady;Pas.AuthorizeMainCopy=MainCopy;Pas.VerifyMainPayload=MainPayload;assert(!OpenPasArm(&Pas));
 UINT64 changed[5]={0};UINT8 prior[5]={0};unsigned changes=0;
 if(Is("hash-last")){unsigned index=KindIndex(1,53);changed[changes++]=ModelBase[index]+ModelBytes[index]-1;}
 if(Is("changed-untouched"))for(unsigned i=0;i<5;i++)changed[changes++]=Untouched[i][0];
 for(unsigned i=0;i<changes;i++){prior[i]=Ram[changed[i]-0x9ea00000];Ram[changed[i]-0x9ea00000]^=0x5a;}
 assert(!mprotect(Ram,0x4880000,PROT_READ));
 assert(!PasStep(0,0)&&!PasStep(0,1)&&!PasStep(0,2)&&!OpenPasFinishDtb(&Pas,0));
 assert(!PasStep(1,0));OP_U64 mem=PasStep(1,1);assert(PasCalls==5&&!Reads);
 OP_U64 auth=mem?OP_ERR(21):PasStep(1,2);
 assert(!mprotect(Ram,0x4880000,PROT_READ|PROT_WRITE));for(unsigned i=0;i<changes;i++)Ram[changed[i]-0x9ea00000]=prior[i];
 if(Is("success")||Is("changed-untouched"))assert(!auth&&PasCalls==6&&Pas.Phase[1]==3&&Pas.AuthAcceptedMask==3&&!Pas.Fault&&Checker.Report.Complete);
 else if(Is("copy-gcd-owner")){
  assert(mem==OP_ERR(21)&&PasCalls==5&&Pas.CopyAllowed[1]==0&&Pas.Fault==OP_COPY_ADMISSION&&!Checker.Report.Attempted&&MainChecks==0&&!Reads);
 }else assert(auth==OP_ERR(21)&&PasCalls==5&&Pas.Phase[1]==2&&Pas.AuthEnteredMask==1&&Pas.AuthAcceptedMask==1&&Pas.Fault==OP_PAYLOAD_MISMATCH&&!Pas.Records[5].Entered&&!Checker.Report.Complete);
 if(!strncmp(name,"post-",5))assert(Checker.Report.VerifiedBytes==64910785&&Checker.Report.Fault==OMP_POST_ADMISSION);
 if(!strncmp(name,"pre-",4))assert(!Reads&&Checker.Report.Fault==OMP_ADMISSION);
 if(Is("owner-after-final-admit"))assert(Checker.Report.VerifiedBytes==64910785&&Checker.Report.Fault==OMP_OWNER);
 if(Is("hash-last"))assert(Checker.Report.Fault==OMP_HASH);
 const OPEN_MAIN_ADMISSION_REPORT*r=OpenGetMainAdmissionReport();assert(r&&r->CopyAttempts==1&&!Live);
 if(Is("success")||Is("changed-untouched"))assert(r->AcceptedRefreshes==2&&!r->Fault&&Checks==3&&MmioReads==43);
 else if(Is("hash-last"))assert(r->AcceptedRefreshes==1&&r->RefreshAttempts==1&&Checks==2);
 else if(Is("copy-gcd-owner"))assert(!r->CopyGranted&&r->Fault==OMA_CHECK&&Checks==1);
 else if(Is("owner-after-final-admit"))assert(r->AcceptedRefreshes==2&&!r->Fault);
 else assert(r->Fault==OMA_CHECK&&r->AcceptedRefreshes==(!strncmp(name,"post-",5)?1u:0u));
 assert(MainCopies==1&&MainChecks==(!Is("copy-gcd-owner")));
 if(!Is("copy-gcd-owner"))assert(OpenMainPayloadVerify(&Checker)==EFI_ALREADY_STARTED);
 unsigned saved=Checks,secure=PasCalls;
 /* A hash mismatch consumes the verifier/PAS sequence before the second
  * refresh. The admission module cannot observe that external hash result;
  * the caller's latched policy, rather than an invented spent budget, blocks
  * another AUTH attempt without making another admission/secure call. */
 if(auth)assert(PasStep(1,2)&&PasCalls==secure&&Checks==saved);
 assert(OpenMainAuthorizeCopy(TRUE,Log)==EFI_ALREADY_STARTED&&Checks==saved);
 if(r->Fault||r->RefreshAttempts==2)assert(OpenMainRefreshAdmission(TRUE,Log)==EFI_ALREADY_STARTED&&Checks==saved);
 assert(!OpenPasDisarm(&Pas));
 printf("{\"case\":\"%s\",\"secure_calls_modeled\":%u,\"main_AUTH_forwarded\":%u,\"payload_complete\":%u,\"payload_fault\":%u,\"payload_read_calls\":%u,\"payload_verified_bytes\":%llu}\n",name,PasCalls,(Pas.AuthEnteredMask>>1)&1,Checker.Report.Complete,Checker.Report.Fault,Reads,(unsigned long long)Checker.Report.VerifiedBytes);
}
int main(int argc,char**argv){
 (VOID)Run; /* Reuse model helpers without rerunning their standalone suite. */
 assert(argc==3);Bs.GetMemoryMap=Map;Ds.GetMemorySpaceDescriptor=Gcd;assert(!OpenMainAdmissionInit());Ram=mmap(NULL,0x4880000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(Ram!=MAP_FAILED);memset(Ram,0xa5,0x4880000);
 for(unsigned i=0;i<OMP_EXTENTS;i++){
  assert(mMainPlan[i].Base==ModelBase[i]&&mMainPlan[i].Bytes==ModelBytes[i]&&mMainPlan[i].Kind==ModelKind[i]);UINT8*dest=Ram+ModelBase[i]-0x9ea00000;
  if(ModelKind[i]==2){memset(dest,0,ModelBytes[i]);continue;}
  char path[2048];int n=snprintf(path,sizeof(path),"%s/%s",argv[1],FileName[i]);assert(n>0&&(unsigned)n<sizeof(path));FILE*f=fopen(path,"rb");assert(f&&fread(dest,1,ModelBytes[i],f)==ModelBytes[i]&&fgetc(f)==EOF&&!fclose(f));
 }
 Integrated(argv[2]);assert(!munmap(Ram,0x4880000));
}
