/* Actual UEFI component; services, AT, MMIO and target dereference are models. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
#define OPEN_MAIN_ADMISSION_MODEL 1
#include "OpenMainAdmission.c"
#include "admission-fixtures.h"
static void CheckExpectedPage(UINT64 at,unsigned write);
static EFI_BOOT_SERVICES Bs;
static EFI_DXE_SERVICES Ds;
EFI_BOOT_SERVICES *gBS=&Bs;
EFI_DXE_SERVICES *gDS=&Ds;
static const char *Case,*Fault;
static unsigned When,CurrentPass,Checks,Reads,Allocations,Frees,Live;
static unsigned CpuAt[3],DeviceAt[3],DataReads[3],MapCalls[3];
static int Is(const char*s){return !strcmp(Case,s);}
static int Bad(const char*s){return CurrentPass==When&&!strcmp(Fault,s);}
static int Reentered;
static void Reenter(void);
static void Log(const CHAR8*f,...){(void)f;if(Bad("reenter-log"))Reenter();}
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
 if(address==MAIN_BASE){
  CurrentPass=Checks++;assert(CurrentPass<3);
  if(Bad("reenter-GCD"))Reenter();
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
 if(Bad("reenter-map"))Reenter();
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
 UINTN count=Bad("map-duplicate")||Bad("map-tail-owner")||Bad("map-gap-owner")||Is("map-irrelevant")?2:1;
 memset(map,0,count*48);
 for(UINTN i=0;i<count;i++){
  EFI_MEMORY_DESCRIPTOR*m=(VOID*)((UINT8*)map+i*48);
  m->PhysicalStart=PIL_BASE;m->NumberOfPages=PIL_BYTES/4096;m->Type=EfiReservedMemoryType;m->Attribute=EFI_MEMORY_UC;
  if(i==1&&(Bad("map-tail-owner")||Bad("map-gap-owner")||Is("map-irrelevant"))){
   m->PhysicalStart=Bad("map-tail-owner")?0xa3000000:Bad("map-gap-owner")?0xa1060000:0xc0000000;
   m->NumberOfPages=1;m->Type=EfiConventionalMemory;
  }
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
 if(at>=MAIN_BASE&&at<MAIN_BASE+MAIN_BYTES){
  CheckExpectedPage(at,write);
  CpuAt[CurrentPass]++;
  if(Bad("reenter-AT"))Reenter();
  if((Bad("CPU-read-fault")&&!write)||(Bad("CPU-write-fault")&&write)||
     (Bad("CPU-last-page-fault")&&at==ExpectedPages[MAIN_CPU_PAGES-1])||
     (Bad("CPU-before-gap-fault")&&at==0xa104f000)||
     (Bad("CPU-after-gap-fault")&&at==0xa109c000)||
     (Bad("CPU-last-write-fault")&&at==ExpectedPages[MAIN_CPU_PAGES-1]&&write))return 1;
  if((Bad("CPU-read-alias")&&!write)||(Bad("CPU-write-alias")&&write))return (0x44ULL<<56)|(at+4096);
  if(Bad("CPU-WB")||(Bad("CPU-last-page-WB")&&at==ExpectedPages[MAIN_CPU_PAGES-1]))return (0xffULL<<56)|at;
  return (0x44ULL<<56)|at;
 }
 unsigned i;for(i=0;i<5;i++)if(at==mMmioPages[i])break;assert(i<5&&!write);
 DeviceAt[CurrentPass]++;
 if(Bad("device-AT-fault"))return 1;if(Bad("device-AT-alias"))return at+4096;
 if(Bad("device-AT-NC"))return (0x44ULL<<56)|at;if(Bad("device-AT-GRE"))return (0xcULL<<56)|at;
 return (Is("device-nGnRE")?4ULL<<56:0)|at;
}
UINT32 OpenMainModelRead(UINT64 address){
 assert(CpuAt[CurrentPass]==2*MAIN_CPU_PAGES&&DeviceAt[CurrentPass]==5&&!Live);
 if(Bad("reenter-MMIO"))Reenter();
 Reads++;DataReads[CurrentPass]++;assert(DataReads[CurrentPass]==mMain.Check[CurrentPass].MmioReads);
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
/* The page fixture comes from a separate projection of the pinned89 writes,
 * not from the generated firmware page-run header. Every AT is checked. */
static void CheckExpectedPage(UINT64 at,unsigned write){
 unsigned q=CpuAt[CurrentPass];assert(q<2*MAIN_CPU_PAGES);
 assert(at==ExpectedPages[q/2]&&write==(q&1));
}
static void Reenter(void){
 if(Reentered)return;
 Reentered=1;
 assert(OpenMainRefreshAdmission(TRUE,Log)==EFI_ACCESS_DENIED);
 assert(OpenMainAuthorizeCopy(TRUE,Log)==EFI_ACCESS_DENIED);
 assert(OpenMainAdmissionInit()==EFI_ALREADY_STARTED);
}
static unsigned ExpectedReason(const char*f){
 if(!strncmp(f,"reenter-",8))return MAIN_REENTRY;
 if(!strcmp(f,"no-footprint")||!strcmp(f,"noncanonical-footprint"))return MAIN_SOURCE;
 if(!strncmp(f,"gcd-",4))return MAIN_GCD;
 if(!strncmp(f,"map-",4)||!strcmp(f,"pool-fail"))return MAIN_MEMORY_MAP;
 if(!strncmp(f,"CPU-",4)||!strcmp(f,"bad-EL"))return MAIN_CPU;
 if(!strncmp(f,"device-",7))return MAIN_MMIO_MAP;
 if(!strncmp(f,"clock-",6)||!strncmp(f,"gate-loss-",10))return MAIN_CLOCK;
 if(!strcmp(f,"display-version"))return MAIN_VERSION;
 if(!strncmp(f,"demura",6))return MAIN_DEMURA;
 assert(0);return 0;
}
static void NoMore(void){
 unsigned saved=Reads,maps=Checks,ats=CpuAt[0]+CpuAt[1]+CpuAt[2];
 assert(OpenMainAuthorizeCopy(TRUE,Log)==EFI_ALREADY_STARTED);
 assert(OpenMainRefreshAdmission(TRUE,Log)==EFI_ALREADY_STARTED);
 assert(Reads==saved&&Checks==maps&&CpuAt[0]+CpuAt[1]+CpuAt[2]==ats);
}
int main(int argc,char**argv){
 assert(argc==2);Case=Fault=argv[1];When=0;
 if(!strncmp(Case,"pre-",4)){When=1;Fault=Case+4;}
 if(!strncmp(Case,"post-",5)){When=2;Fault=Case+5;}
 Bs.GetMemoryMap=Map;Ds.GetMemorySpaceDescriptor=Gcd;
 assert(OpenGetMainAdmissionReport()==NULL);
 assert(OpenMainAuthorizeCopy(TRUE,Log)==EFI_INVALID_PARAMETER);
 assert(OpenMainRefreshAdmission(TRUE,Log)==EFI_INVALID_PARAMETER);
 assert(OpenMainAdmissionInit()==EFI_SUCCESS);
 assert(OpenGetMainAdmissionReport()==&mMain&&mMain.Size==368&&mMain.Version==1&&!mMain.Reserved);
 if(Is("before-copy")){
  assert(OpenMainRefreshAdmission(TRUE,Log)==EFI_NOT_READY&&mMain.Fault==OMA_SEQUENCE&&!Reads&&!Checks);
  NoMore();goto done;
 }
 if(!strncmp(Case,"forbidden-",10)){
  UINT64 at=Is("forbidden-c7b7000")?0xc7b7000:Is("forbidden-c7b7008")?0xc7b7008:0xb000000;UINT32 v;
  assert(!Word(&mMain.Check[0],at,&v)&&mMain.Check[0].Reason==MAIN_ARGUMENT&&!Reads);goto done;
 }
 if(Is("read-budget")){
  UINT32 v;mMain.Check[0].MmioReads=64;
  assert(!Word(&mMain.Check[0],mClockAddress[0],&v)&&mMain.Check[0].Reason==MAIN_BUDGET&&!Reads);goto done;
 }
 if(Is("null-log")){
  assert(OpenMainAuthorizeCopy(TRUE,NULL)==EFI_INVALID_PARAMETER&&!mMain.CopyAttempts&&!Reads);
  assert(OpenMainRefreshAdmission(TRUE,NULL)==EFI_INVALID_PARAMETER&&!mMain.RefreshAttempts&&!Reads);goto done;
 }
 BOOLEAN good=Is("success")||Is("EL2")||Is("device-nGnRE")||Is("device-UC-RO-XP")||Is("map-irrelevant");
 for(unsigned i=0;i<3;i++){
  BOOLEAN footprint=Bad("no-footprint")?FALSE:Bad("noncanonical-footprint")?2:TRUE;
  /* For source refusals, no service has yet advanced CurrentPass. */
  footprint=i==When&&(!strcmp(Fault,"no-footprint")||!strcmp(Fault,"noncanonical-footprint"))?
      (!strcmp(Fault,"no-footprint")?FALSE:2):TRUE;
  EFI_STATUS status=i?OpenMainRefreshAdmission(footprint,Log):OpenMainAuthorizeCopy(footprint,Log);
  if(status!=EFI_SUCCESS){
   assert(!good&&i==When&&!mMain.Check[i].Complete);
   assert(mMain.Check[i].Reason==ExpectedReason(Fault)&&mMain.Check[i].Status==status);
   assert(mMain.CopyGranted==(i!=0)&&mMain.AcceptedRefreshes==(i==2));
   assert(mMain.Fault&OMA_CHECK);
   if(!strncmp(Fault,"reenter-",8))assert(Reentered&&(mMain.Fault&OMA_REENTRANT));
   NoMore();goto done;
  }
  assert(mMain.Check[i].Complete&&mMain.Check[i].Status==EFI_SUCCESS&&DataReads[i]==43);
  assert(mMain.Check[i].CpuPages==MAIN_CPU_PAGES&&mMain.Check[i].AtQueries==2*MAIN_CPU_PAGES+5&&mMain.Check[i].MmioPages==5);
  if(Is("duplicate-copy")&&i==0){
   unsigned saved=Reads;
   assert(OpenMainAuthorizeCopy(TRUE,Log)==EFI_ALREADY_STARTED&&Reads==saved&&!mMain.Fault);goto done;
  }
 }
 assert(good&&mMain.AcceptedRefreshes==2&&mMain.CopyAttempts==1&&mMain.RefreshAttempts==2&&!mMain.Fault&&Reads==129);
 NoMore();
done:
 assert(!Live&&Allocations==Frees&&OpenMainAdmissionInit()==EFI_ALREADY_STARTED&&!mBusy);
 printf("{\"case\":\"%s\",\"copy\":\"%llx\",\"refresh\":[\"%llx\",\"%llx\"],\"reads\":%u,\"checks\":%u,\"fault\":%u,\"cpu_pages\":[%llu,%llu,%llu],\"reason\":[%u,%u,%u]}\n",Case,
  (unsigned long long)mMain.CopyStatus,(unsigned long long)mMain.RefreshStatus[0],(unsigned long long)mMain.RefreshStatus[1],Reads,Checks,mMain.Fault,
  (unsigned long long)mMain.Check[0].CpuPages,(unsigned long long)mMain.Check[1].CpuPages,(unsigned long long)mMain.Check[2].CpuPages,
  mMain.Check[0].Reason,mMain.Check[1].Reason,mMain.Check[2].Reason);
 return 0;
}
