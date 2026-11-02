/* G201: exactly one fixed cover zero-fill in AfterReadyToBoot.
 * Later BeforeExit/Exit callbacks observe only. G182/G195/G200 unchanged. */
#include <Uefi.h>
#include <PiDxe.h>
#include <Guid/EventGroup.h>
#include <Guid/Acpi.h>
#include <Protocol/AcpiTable.h>
#include <Protocol/Cpu.h>
#include <Library/BaseLib.h>
#include <Library/ArmLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PlatformMemoryMapLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include "g201_handoff.h"
#include "g201_plan.h"
#include "g201_report_aml.h"
#include "G203Dispatch.h"
STATIC G201_REPORT *mReport;
STATIC EFI_EVENT mBeforeEvent,mExitEvent;
STATIC BOOLEAN mAttempted,mCpuPresent;
STATIC BOOLEAN mPublishAttempted;
STATIC EFI_ACPI_TABLE_PROTOCOL *mAcpi;
typedef struct {G201_REPORT *State;G201_ENV *Env;} READ_CONTEXT;
STATIC UINT64 CurrentRsdp(VOID)
{
 UINT64 address=0;UINTN found=0;
 if(gST->NumberOfTableEntries>128)return 0;
 for(UINTN i=0;i<gST->NumberOfTableEntries;i++)if(CompareGuid(&gST->ConfigurationTable[i].VendorGuid,&gEfiAcpi20TableGuid)){
  found++;address=(UINT64)(UINTN)gST->ConfigurationTable[i].VendorTable;
 }
 return found==1?address:0;
}
STATIC BOOLEAN SourceProfile(VOID)
{
 ARM_MEMORY_REGION_DESCRIPTOR_EX *r=GetPlatformMemoryMap();
 BOOLEAN frame=FALSE,reg[6]={FALSE,FALSE,FALSE,FALSE,FALSE,FALSE};
 CONST UINT64 pages[6]={0xaf08000,0xaf09000,0xae05000,0xae07000,0xae09000,0xae0b000};
 if(r==NULL)return FALSE;
 for(UINTN i=0;i<MAX_ARM_MEMORY_REGION_DESCRIPTOR_COUNT;i++){
  if(r[i].Address==0&&r[i].Length==0){
   if(!frame)return FALSE;for(UINTN j=0;j<6;j++)if(!reg[j])return FALSE;return TRUE;
  }
  if(r[i].Length==0||r[i].Length>MAX_UINT64-r[i].Address)return FALSE;
  if(AsciiStrCmp(r[i].Name,"Display Reserved")==0){
   if(frame||r[i].Address!=0xb8000000ULL||r[i].Length!=0x02b00000ULL||
      r[i].MemoryType!=EfiReservedMemoryType||r[i].ResourceType!=EFI_RESOURCE_MEMORY_RESERVED||
      r[i].ArmAttributes!=ARM_MEMORY_REGION_ATTRIBUTE_WRITE_THROUGH)return FALSE;
   frame=TRUE;
  }
  for(UINTN j=0;j<6;j++)if(r[i].Address<=pages[j]&&r[i].Address+r[i].Length>=pages[j]+4096&&
    r[i].MemoryType==EfiMemoryMappedIO&&r[i].ResourceType==EFI_RESOURCE_MEMORY_MAPPED_IO&&
    r[i].ArmAttributes==ARM_MEMORY_REGION_ATTRIBUTE_DEVICE)reg[j]=TRUE;
 }
 return FALSE;
}
STATIC int ReadRam(void *Context,UINT64 at,void *out,UINTN n)
{
 READ_CONTEXT *c=Context;if(!G201RamCovered(c->Env,at,n))return 0;
 CopyMem(out,(CONST VOID *)(UINTN)at,n);return 1;
}
STATIC int ReadRegister(void *Context,UINT64 at,UINT32 *out)
{
 BOOLEAN allowed=(BOOLEAN)(at==0xaf08000||at==0xaf0800c||at==0xaf080a4||at==0xaf09000||at==0xaf09004);(VOID)Context;
 for(UINTN i=0;i<4;i++)for(UINTN j=0;j<12;j++)if(at==(UINT64)G201PipePages[i]+G201Off[j])allowed=TRUE;
 if(!allowed)return 0;MemoryFence();*out=*(volatile CONST UINT32 *)(UINTN)at;MemoryFence();return 1;
}
STATIC int ReadRow(void *Context,UINT32 y,UINT32 *out)
{
 (VOID)Context;if(y>=G201_HEIGHT)return 0;
 volatile CONST UINT32 *pixels=(volatile CONST UINT32 *)(UINTN)(G201_FB_PAGE+G201_FB_OFFSET+(UINT64)y*G201_WIDTH*4u);
 MemoryFence();for(UINTN x=0;x<G201_WIDTH;x++)out[x]=pixels[x];MemoryFence();return 1;
}
STATIC int WriteZeroRow(void *Context,UINT32 y,UINT32 *written)
{
 READ_CONTEXT *c=Context;
 if(y>=G201_HEIGHT||written!=&c->State->Clear.WrittenWords||*written!=y*G201_WIDTH)return 0;
 volatile UINT32 *pixels=(volatile UINT32 *)(UINTN)(G201_FB_PAGE+G201_FB_OFFSET+(UINT64)y*G201_WIDTH*4u);
 for(UINTN x=0;x<G201_WIDTH;x++){pixels[x]=0;(*written)++;}
 MemoryFence();return 1;
}
STATIC BOOLEAN CacheGeometry(UINTN line)
{ return (BOOLEAN)(line>=16&&line<=4096&&(line&(line-1))==0); }
STATIC int SyncPixels(void *Context)
{
 READ_CONTEXT *c=Context;UINTN line=ArmDataCacheLineLength();UINT64 start,end;UINT32 lines;
 c->State->CacheLineBytes=(UINT32)line;
 if(line>MAX_UINT32||!G201PixelCachePlan((UINT32)line,&start,&end,&lines))return 0;
 (VOID)lines;
 /* Exact line addresses within fixed pixels only. No global cache operation,
  * translation change or display/clock/panel register write. The clean keeps
  * any prior dirty content; invalidation makes the following read independent
  * of a stale cached copy. Stores are synchronized to PoC before verification. */
 ArmDataSynchronizationBarrier();
 for(UINT64 at=start;at<end;at+=line){ArmCleanInvalidateDataCacheEntryByMVA((UINTN)at);c->State->PixelCacheLines++;}
 ArmDataSynchronizationBarrier();c->State->PixelCachePasses++;return 1;
}
STATIC VOID PublishReport(VOID)
{
 UINTN line=ArmDataCacheLineLength(),bytes=EFI_PAGES_TO_SIZE(EFI_SIZE_TO_PAGES(sizeof(*mReport)));
 if(!CacheGeometry(line))return;
 ArmDataSynchronizationBarrier();
 /* Allocation-aligned, owned NVS lines only. Does not touch cover registers. */
 for(UINTN at=(UINTN)mReport;at<(UINTN)mReport+bytes;at+=line)ArmCleanDataCacheEntryByMVA(at);
 ArmDataSynchronizationBarrier();
}
VOID OpenCoverHandoffRecordSchedule(UINT32 step,EFI_STATUS status)
{
 if(!mReport)return;
 switch(step){
 case G203_PREPARED:mReport->Schedule.EntryCalls++;mReport->Schedule.PrepareStatus=status;break;
 case G203_WORK_CREATED:mReport->Schedule.WorkCreateStatus=status;break;
 case G203_READY_CREATED:mReport->Schedule.ReadyCreateStatus=status;break;
 case G203_READY_ENTERED:mReport->Schedule.ReadyCalls++;break;
 case G203_AFTER_CREATED:mReport->Schedule.AfterCreateStatus=status;if(!EFI_ERROR(status))mReport->Schedule.AfterRegistered=1;break;
 case G203_BRIDGE_ENTERED:mReport->Schedule.BridgeCalls++;break;
 case G203_WORK_SIGNALED:mReport->Schedule.WorkSignalStatus=status;if(!EFI_ERROR(status))mReport->Schedule.WorkSignaled=1;break;
 case G203_WORK_ENTERED:mReport->Schedule.WorkCalls++;break;
 case G203_REPORT_PUBLISHED:mReport->Schedule.ReportPublishStatus=status;break;
 default:return;
 }
 if(EFI_ERROR(status))mReport->FaultRetained=1;
 PublishReport();
}
STATIC BOOLEAN CaptureEnv(G201_ENV *e)
{
 CONST UINT64 targets[7]={G201_FB_PAGE,0xaf08000,0xaf09000,0xae05000,0xae07000,0xae09000,0xae0b000};
 UINTN bytes=G201_MAP_CAPACITY,key=0,stride=0;UINT32 version=0;EFI_STATUS status;
 ZeroMem(e,sizeof(*e));e->SourceProfile=SourceProfile()?1:0;e->CpuArchPresent=mCpuPresent?1:0;e->Rsdp=CurrentRsdp();
 status=gBS->GetMemoryMap(&bytes,(EFI_MEMORY_DESCRIPTOR *)e->Map,&key,&stride,&version);e->GetMapStatus=(UINT64)status;
 if(EFI_ERROR(status)||bytes>G201_MAP_CAPACITY||stride>MAX_UINT32)return FALSE;
 e->MapBytes=(UINT32)bytes;e->MapKey=key;e->DescriptorBytes=(UINT32)stride;e->DescriptorVersion=version;
 for(UINTN i=0;i<7;i++){
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR d;ZeroMem(&d,sizeof(d));status=gDS->GetMemorySpaceDescriptor(targets[i],&d);
  if(EFI_ERROR(status)){e->GetGcdStatus=(UINT64)status;continue;}
  e->Gcd[i].Base=d.BaseAddress;e->Gcd[i].Bytes=d.Length;e->Gcd[i].Capabilities=d.Capabilities;e->Gcd[i].Attributes=d.Attributes;
  e->Gcd[i].Kind=(UINT32)d.GcdMemoryType;e->Gcd[i].Valid=1;
 }
 return TRUE;
}
VOID OpenCoverHandoffReadyAttempt(VOID)
{
 READ_CONTEXT c={mReport,mReport?&mReport->ReadEnv:NULL};
 G201_IO io={&c,ReadRam,ReadRegister,ReadRow,NULL,SyncPixels};
 if(mReport==NULL||mReport->ReadyRuns)return;mReport->ReadyRuns=1;
 if(!CaptureEnv(&mReport->ReadEnv)){mReport->Read.Status=G201_SERVICE_FAILED;goto done;}
 G201Observe(&mReport->ReadEnv,&io,&mReport->Read,1,1);
 if(mReport->Read.Status!=G201_READ_COMPLETE){mReport->Clear.Status=G201_PRIOR_STAGE_FAILED;goto done;}
 if(!CaptureEnv(&mReport->ClearEnv)){mReport->Clear.Status=G201_SERVICE_FAILED;goto done;}
 c.Env=&mReport->ClearEnv;io.WriteZeroRow=WriteZeroRow;
 G201ClearOnce(&mReport->ClearEnv,&io,&mReport->Read,&mReport->Clear);
 done:
 if(mReport->Read.Status!=G201_READ_COMPLETE||mReport->Clear.Status!=G201_READ_COMPLETE)mReport->FaultRetained=1;
 PublishReport();
}
STATIC VOID EFIAPI BeforeExit(EFI_EVENT Event,VOID *Context)
{
 READ_CONTEXT c={mReport,mReport?&mReport->LateEnv:NULL};
 G201_IO io={&c,ReadRam,ReadRegister,ReadRow,NULL,SyncPixels};(VOID)Event;(VOID)Context;
 if(mReport==NULL||mReport->BeforeRuns)return;mReport->BeforeRuns=1;
 if(!CaptureEnv(&mReport->LateEnv))mReport->Before.Status=G201_SERVICE_FAILED;
 else G201Observe(&mReport->LateEnv,&io,&mReport->Before,1,1);
 PublishReport();
}
STATIC VOID EFIAPI AtExit(EFI_EVENT Event,VOID *Context)
{
 READ_CONTEXT c={mReport,mReport?&mReport->LateEnv:NULL};
 /* This phase has no write/cache-refresh capability and no service call. */
 G201_IO io={&c,ReadRam,ReadRegister,ReadRow,NULL,NULL};(VOID)Event;(VOID)Context;
 if(mReport==NULL||mReport->ExitRuns)return;mReport->ExitRuns=1;
 if(mReport->Before.Status!=G201_READ_COMPLETE)mReport->Exit.Status=G201_PRIOR_STAGE_FAILED;
 else G201Observe(&mReport->LateEnv,&io,&mReport->Exit,0,0);
 PublishReport();
}
STATIC VOID Put32(UINT8 *p,UINT32 n)
{ for(UINTN i=0;i<4;i++)p[i]=(UINT8)(n>>(8*i)); }
STATIC BOOLEAN OverlapsTargets(UINT64 at,UINT64 n)
{
 CONST UINT64 base[7]={G201_FB_PAGE,0xaf08000,0xaf09000,0xae05000,0xae07000,0xae09000,0xae0b000};
 for(UINTN i=0;i<7;i++)if(at<base[i]+(i?4096:G201_FB_MAP_BYTES)&&base[i]<at+n)return TRUE;return FALSE;
}
EFI_STATUS OpenPrepareCoverHandoff(VOID)
{
 EFI_CPU_ARCH_PROTOCOL *cpu;EFI_STATUS status;
 EFI_PHYSICAL_ADDRESS address=0xffffffffULL;UINTN pages=EFI_SIZE_TO_PAGES(sizeof(G201_REPORT));
 if(mAttempted)return EFI_ALREADY_STARTED;mAttempted=TRUE;
 if(!CacheGeometry(ArmDataCacheLineLength()))return EFI_UNSUPPORTED;
 status=gBS->LocateProtocol(&gEfiCpuArchProtocolGuid,NULL,(VOID **)&cpu);if(EFI_ERROR(status)||!cpu)return EFI_UNSUPPORTED;mCpuPresent=TRUE;
 status=gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid,NULL,(VOID **)&mAcpi);if(EFI_ERROR(status)||!mAcpi)return EFI_UNSUPPORTED;
 status=gBS->AllocatePages(AllocateMaxAddress,EfiACPIMemoryNVS,pages,&address);if(EFI_ERROR(status))return status;
 if(address>0x100000000ULL-EFI_PAGES_TO_SIZE(pages)||OverlapsTargets(address,EFI_PAGES_TO_SIZE(pages))){status=EFI_UNSUPPORTED;goto fail;}
 mReport=(G201_REPORT *)(UINTN)address;ZeroMem(mReport,EFI_PAGES_TO_SIZE(pages));
 mReport->Magic=G201_MAGIC;mReport->Version=G201_VERSION;mReport->Bytes=sizeof(*mReport);mReport->CacheLineBytes=(UINT32)ArmDataCacheLineLength();
 status=gBS->CreateEventEx(EVT_NOTIFY_SIGNAL,TPL_CALLBACK,BeforeExit,NULL,&gEfiEventBeforeExitBootServicesGuid,&mBeforeEvent);if(EFI_ERROR(status))goto fail;
 status=gBS->CreateEventEx(EVT_NOTIFY_SIGNAL,TPL_CALLBACK,AtExit,NULL,&gEfiEventExitBootServicesGuid,&mExitEvent);if(EFI_ERROR(status))goto fail;
 PublishReport();return EFI_SUCCESS;
 fail:
 if(mBeforeEvent){gBS->CloseEvent(mBeforeEvent);mBeforeEvent=NULL;}
 if(mExitEvent){gBS->CloseEvent(mExitEvent);mExitEvent=NULL;}
 gBS->FreePages(address,pages);mReport=NULL;return status;
}
EFI_STATUS OpenPublishCoverHandoffReport(VOID)
{
 UINT8 table[sizeof(G201ReportSsdt)],sum=0;UINTN tableKey=0;EFI_STATUS status;
 if(!mReport||!mAcpi)return EFI_NOT_READY;
 if(mPublishAttempted)return EFI_ALREADY_STARTED;mPublishAttempted=TRUE;
 CopyMem(table,G201ReportSsdt,sizeof(table));Put32(table+G201_REPORT_BASE_OFFSET,(UINT32)(UINTN)mReport);
 Put32(table+G201_REPORT_LENGTH_OFFSET,(UINT32)EFI_PAGES_TO_SIZE(EFI_SIZE_TO_PAGES(sizeof(*mReport))));table[9]=0;
 for(UINTN i=0;i<sizeof(table);i++)sum=(UINT8)(sum+table[i]);table[9]=(UINT8)(0-sum);
 /* Only this immutable resource descriptor is copied by the ACPI protocol.
  * The separately allocated report remains resident for the boot lifetime. */
 status=mAcpi->InstallAcpiTable(mAcpi,table,sizeof(table),&tableKey);
 if(EFI_ERROR(status))return status;
 return CurrentRsdp()?EFI_SUCCESS:EFI_UNSUPPORTED;
}

