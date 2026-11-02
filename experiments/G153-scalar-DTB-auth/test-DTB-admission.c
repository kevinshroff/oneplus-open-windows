/* Actual UEFI component; services, AT, MMIO and target dereference are models. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include "OpenSha256.h"
static VOID ModelHashTarget(CONST VOID*,UINTN,UINT8*);
#define OpenShaAll ModelHashTarget
#define OPEN_DTB_ADMISSION_MODEL 1
#include "OpenDtbAdmission.c"
#undef OpenShaAll
#include "admission-fixtures.h"
static EFI_BOOT_SERVICES Bs;
static EFI_DXE_SERVICES Ds;
EFI_BOOT_SERVICES *gBS=&Bs;
EFI_DXE_SERVICES *gDS=&Ds;
static const char *Case,*Fault;
static unsigned When,CurrentPass,Checks,Reads,HashCalls,Allocations,Frees,Live;
static unsigned CpuAt[3],DeviceAt[3],DataReads[3],MapCalls[3];
static int Is(const char*s){return !strcmp(Case,s);}
static int Bad(const char*s){return CurrentPass==When&&!strcmp(Fault,s);}
static void Log(const CHAR8*f,...){(void)f;}
VOID *EFIAPI CopyMem(VOID*d,CONST VOID*s,UINTN n){return memcpy(d,s,n);}
VOID *EFIAPI ZeroMem(VOID*p,UINTN n){return memset(p,0,n);}
INTN EFIAPI CompareMem(CONST VOID*a,CONST VOID*b,UINTN n){return memcmp(a,b,n);}
VOID EFIAPI MemoryFence(VOID){__sync_synchronize();}
VOID *EFIAPI AllocatePool(UINTN n){
 if(Bad("pool-fail"))return NULL;
 assert(n<=0x10000&&!Live);Allocations++;Live++;return calloc(1,n);
}
VOID EFIAPI FreePool(VOID*p){assert(p&&Live==1);Frees++;Live--;free(p);}
static EFI_STATUS EFIAPI Gcd(EFI_PHYSICAL_ADDRESS address,EFI_GCD_MEMORY_SPACE_DESCRIPTOR*d){
 memset(d,0,sizeof(*d));
 if(address==DTB_BASE){
  CurrentPass=Checks++;assert(CurrentPass<3);
  if(Bad("gcd-error"))return EFI_DEVICE_ERROR;if(Bad("gcd-warning"))return EFI_WARN_UNKNOWN_GLYPH;
  d->BaseAddress=PIL_BASE;d->Length=PIL_BYTES;d->GcdMemoryType=EfiGcdMemoryTypeReserved;d->Capabilities=EFI_MEMORY_UC;
  if(Bad("gcd-base"))d->BaseAddress+=4096;if(Bad("gcd-size"))d->Length-=4096;
  if(Bad("gcd-type"))d->GcdMemoryType=EfiGcdMemoryTypeSystemMemory;
  if(Bad("gcd-attributes"))d->Attributes=EFI_MEMORY_WB;if(Bad("gcd-capability"))d->Capabilities=0;
  if(Bad("gcd-image-owner"))d->ImageHandle=(VOID*)1;if(Bad("gcd-device-owner"))d->DeviceHandle=(VOID*)1;
  return EFI_SUCCESS;
 }
 unsigned i;for(i=0;i<5;i++)if(address==mMmioPages[i])break;assert(i<5);
 if(Bad("device-gcd-error"))return EFI_DEVICE_ERROR;if(Bad("device-gcd-warning"))return EFI_WARN_UNKNOWN_GLYPH;
 d->BaseAddress=address;d->Length=4096;d->GcdMemoryType=EfiGcdMemoryTypeMemoryMappedIo;d->Capabilities=EFI_MEMORY_UC;
 if(Is("device-UC-RO-XP"))d->Attributes=EFI_MEMORY_UC|EFI_MEMORY_RO|EFI_MEMORY_XP;
 if(Bad("device-gcd-type"))d->GcdMemoryType=EfiGcdMemoryTypeSystemMemory;
 if(Bad("device-gcd-short"))d->Length=4095;if(Bad("device-gcd-base"))d->BaseAddress++;
 if(Bad("device-gcd-overflow")){d->BaseAddress=MAX_UINT64-7;d->Length=16;}
 if(Bad("device-gcd-capability"))d->Capabilities=0;
 if(Bad("device-gcd-WB"))d->Attributes=EFI_MEMORY_WB;
 if(Bad("device-gcd-mixed"))d->Attributes=EFI_MEMORY_UC|EFI_MEMORY_WC;
 if(Bad("device-gcd-RP"))d->Attributes=EFI_MEMORY_UC|EFI_MEMORY_RP;
 return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Map(UINTN*bytes,EFI_MEMORY_DESCRIPTOR*map,UINTN*key,UINTN*stride,UINT32*version){
 unsigned first=map==NULL;MapCalls[CurrentPass]++;*key=1;*stride=48;*version=1;
 if(first){
  *bytes=48;
  if(Bad("map-first-error"))return EFI_DEVICE_ERROR;if(Bad("map-first-warning"))return EFI_WARN_UNKNOWN_GLYPH;
  if(Bad("map-first-zero"))*bytes=0;if(Bad("map-first-large"))*bytes=0x8001;
  if(Bad("map-first-stride-small"))*stride=8;if(Bad("map-first-stride-large"))*stride=264;
  if(Bad("map-first-stride-unaligned"))*stride=49;
  return EFI_BUFFER_TOO_SMALL;
 }
 assert(Live==1&&*bytes>=48*2);
 if(Bad("map-second-error"))return EFI_DEVICE_ERROR;if(Bad("map-second-warning"))return EFI_WARN_UNKNOWN_GLYPH;
 UINTN count=Bad("map-duplicate")?2:1;
 memset(map,0,count*48);
 for(UINTN i=0;i<count;i++){
  EFI_MEMORY_DESCRIPTOR*m=(VOID*)((UINT8*)map+i*48);
  m->PhysicalStart=PIL_BASE;m->NumberOfPages=PIL_BYTES/4096;m->Type=EfiReservedMemoryType;m->Attribute=EFI_MEMORY_UC;
  if(Bad("map-missing"))m->PhysicalStart=0xc0000000;
  if(Bad("map-type"))m->Type=EfiConventionalMemory;if(Bad("map-attribute"))m->Attribute=EFI_MEMORY_WB;
  if(Bad("map-base"))m->PhysicalStart+=4096;if(Bad("map-pages"))m->NumberOfPages--;
  if(Bad("map-overflow")){m->PhysicalStart=MAX_UINT64-7;m->NumberOfPages=1;}
  if(Bad("map-page-overflow"))m->NumberOfPages=MAX_UINT64/4096+1;
 }
 *bytes=count*48;
 if(Bad("map-second-zero"))*bytes=0;if(Bad("map-second-large"))*bytes=0x10001;
 if(Bad("map-second-stride-zero"))*stride=0;if(Bad("map-second-stride-small"))*stride=8;
 if(Bad("map-second-stride-large"))*stride=264;if(Bad("map-second-stride-unaligned"))*stride=49;
 if(Bad("map-size-unaligned"))(*bytes)--;if(Bad("map-version"))*version=0;
 return EFI_SUCCESS;
}
OP_U64 OpenDspCurrentEl(VOID){return Is("EL2")?2:Bad("bad-EL")?3:1;}
OP_U64 OpenDspAt(void*context,OP_U64 at,unsigned write){
 assert(!Live&&*(UINT64*)context>=1&&*(UINT64*)context<=2);
 if(at>=DTB_BASE&&at<DTB_BASE+3*4096){
  unsigned index=(unsigned)((at-DTB_BASE)/4096);CpuAt[CurrentPass]++;
  if((Bad("CPU-read-fault")&&!write)||(Bad("CPU-write-fault")&&write)||
     (Bad("CPU-last-page-fault")&&index==2))return 1;
  if((Bad("CPU-read-alias")&&!write)||(Bad("CPU-write-alias")&&write))return (0x44ULL<<56)|(at+4096);
  if(Bad("CPU-WB")||Bad("CPU-last-page-WB")&&index==2)return (0xffULL<<56)|at;
  return (0x44ULL<<56)|at;
 }
 unsigned i;for(i=0;i<5;i++)if(at==mMmioPages[i])break;assert(i<5&&!write);
 DeviceAt[CurrentPass]++;
 if(Bad("device-AT-fault"))return 1;if(Bad("device-AT-alias"))return at+4096;
 if(Bad("device-AT-NC"))return (0x44ULL<<56)|at;if(Bad("device-AT-GRE"))return (0xcULL<<56)|at;
 return (Is("device-nGnRE")?4ULL<<56:0)|at;
}
UINT32 OpenDtbModelRead(UINT64 address){
 assert(CpuAt[CurrentPass]==6&&DeviceAt[CurrentPass]==5&&!Live);
 Reads++;DataReads[CurrentPass]++;assert(DataReads[CurrentPass]==mDtb.Check[CurrentPass].MmioReads);
 unsigned i;for(i=0;i<5;i++)if(address==mClockAddress[i])break;
 if(i<5){
  UINT32 v=NativeClock[i];
  if((Bad("clock-reset")&&i==0)||(Bad("gate-loss-before-demura")&&DataReads[CurrentPass]==17&&i==0)||
     (Bad("gate-loss-after-demura")&&DataReads[CurrentPass]==23&&i==0))v|=1;
  if(Bad("clock-MDP-off")&&i==1)v|=0x80000000u;if(Bad("clock-MDP-unrequested")&&i==1)v&=~1u;
  if(Bad("clock-AHB-off")&&i==2)v|=0x80000000u;if(Bad("clock-AHB-unrequested")&&i==2)v&=~1u;
  if(Bad("clock-core-off")&&i==3)v&=~0x80000000u;
  if(Bad("clock-hw-trigger")&&i==3)v|=2;if(Bad("clock-sw-override")&&i==3)v|=4;
  if(Bad("clock-collapse")&&i==3)v|=1;if(Bad("clock-down-complete")&&i==4)v|=0x8000;
  if(Bad("clock-up-incomplete")&&i==4)v&=~0x10000u;return v;
 }
 if(address==0xae00000)return Bad("display-version")?0x90000000u:NativeVersion;
 assert(address==0xae6a604||address==0xae6b604);
 if(Bad("demura0")&&address==0xae6a604)return 1;if(Bad("demura1")&&address==0xae6b604)return 1;
 if(Bad("demura-unknown-bits"))return 0x80000000u;
 return 0;
}
static VOID ModelHashTarget(CONST VOID*data,UINTN n,UINT8*digest){
 assert((UINTN)data==DTB_BASE&&n==8376&&CurrentPass==1&&mDtb.Check[1].Complete&&!Live);
 HashCalls++;UINT8 payload[sizeof(ActualPayload)];memcpy(payload,ActualPayload,sizeof(payload));
 if(Is("hash-mismatch"))payload[17]^=1;
 OpenShaAll(payload,n,digest);
 assert(!memcmp(digest,Is("hash-mismatch")?MutatedPayloadDigest:ActualPayloadDigest,32));
}

int main(int argc,char**argv){
 assert(argc==2);Case=Fault=argv[1];When=0;
 if(!strncmp(Case,"payload-",8)){When=1;Fault=Case+8;}
 if(!strncmp(Case,"posthash-",9)){When=2;Fault=Case+9;}
 Bs.GetMemoryMap=Map;Ds.GetMemorySpaceDescriptor=Gcd;
 assert(OpenGetDtbAdmissionReport()==NULL);
 assert(OpenDtbAuthorizeCopy(TRUE,Log)==EFI_INVALID_PARAMETER);
 assert(OpenDtbAdmissionInit()==EFI_SUCCESS);
 if(Is("before-copy")){
  assert(OpenDtbVerifyPayload(TRUE,Log)==EFI_NOT_READY&&OpenDtbAuthorizeCopy(TRUE,Log)==EFI_ALREADY_STARTED&&!Reads&&!HashCalls);goto done;
 }
 if(!strncmp(Case,"forbidden-",10)){
  UINT64 at=Is("forbidden-c7b7000")?0xc7b7000:Is("forbidden-c7b7008")?0xc7b7008:0xb000000;UINT32 v;
  assert(!Word(&mDtb.Check[0],at,&v)&&mDtb.Check[0].Reason==DTB_ARGUMENT&&!Reads);goto done;
 }
 if(Is("read-budget")){UINT32 v;mDtb.Check[0].MmioReads=64;assert(!Word(&mDtb.Check[0],mClockAddress[0],&v)&&mDtb.Check[0].Reason==DTB_BUDGET&&!Reads);goto done;}
 if(Is("null-log")){assert(OpenDtbAuthorizeCopy(TRUE,NULL)==EFI_INVALID_PARAMETER&&!mDtb.CopyAttempts&&!Reads);goto done;}
 BOOLEAN footprint=Is("no-footprint")?FALSE:Is("noncanonical-footprint")?2:TRUE;
 EFI_STATUS copy=OpenDtbAuthorizeCopy(footprint,Log);
 if(copy!=EFI_SUCCESS){
  assert(!mDtb.CopyGranted&&!HashCalls&&mDtb.CopyAttempts==1);
  assert(OpenDtbAuthorizeCopy(TRUE,Log)==EFI_ALREADY_STARTED);
  assert(OpenDtbVerifyPayload(TRUE,Log)==EFI_NOT_READY&&!HashCalls);goto done;
 }
 assert(mDtb.CopyGranted&&mDtb.Check[0].Complete&&DataReads[0]==43);
 if(Is("duplicate-copy")){unsigned saved=Reads;assert(OpenDtbAuthorizeCopy(TRUE,Log)==EFI_ALREADY_STARTED&&Reads==saved);goto done;}
 EFI_STATUS payload=OpenDtbVerifyPayload(TRUE,Log);
 if(Is("success")||Is("EL2")||Is("device-nGnRE")||Is("device-UC-RO-XP")){
  assert(payload==EFI_SUCCESS&&mDtb.PayloadMatched&&mDtb.PayloadHashed&&mDtb.HashOutcome==3&&HashCalls==1&&Reads==129);
  for(unsigned i=0;i<3;i++)assert(mDtb.Check[i].Complete&&mDtb.Check[i].CpuPages==3&&mDtb.Check[i].AtQueries==11&&mDtb.Check[i].MmioPages==5);
  unsigned saved=Reads;assert(OpenDtbVerifyPayload(TRUE,Log)==EFI_ALREADY_STARTED&&Reads==saved&&HashCalls==1);
 }else if(Is("hash-mismatch"))assert(payload==EFI_SECURITY_VIOLATION&&mDtb.PayloadHashed&&!mDtb.PayloadMatched&&mDtb.HashOutcome==2&&HashCalls==1&&!mDtb.Check[2].Complete);
 else{
  assert(payload!=EFI_SUCCESS&&When>0);
  assert(HashCalls==(When==2?1u:0u));assert(mDtb.PayloadMatched==(When==2?1u:0u));
 }
done:
 assert(!Live&&Allocations==Frees&&OpenDtbAdmissionInit()==EFI_ALREADY_STARTED);
 printf("{\"case\":\"%s\",\"copy\":\"%llx\",\"payload\":\"%llx\",\"reads\":%u,\"hash_calls\":%u,\"checks\":%u,\"reason\":[%u,%u,%u]}\n",Case,
  (unsigned long long)mDtb.CopyStatus,(unsigned long long)mDtb.PayloadStatus,Reads,HashCalls,Checks,mDtb.Check[0].Reason,mDtb.Check[1].Reason,mDtb.Check[2].Reason);
 return 0;
}
