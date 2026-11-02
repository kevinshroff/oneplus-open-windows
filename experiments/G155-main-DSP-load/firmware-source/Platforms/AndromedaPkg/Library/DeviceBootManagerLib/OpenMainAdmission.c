/* SPDX-License-Identifier: MIT
 * Fresh finite checks for the original main loader's exact touched pages.
 * The GCD/EFI inventory covers the full declared reservation; CPU translations
 * cover only the fixed original writes. No payload dereference, target write,
 * PAS call, MMIO write, allocation of the carveout or rollback occurs here.
 * These observations do not exclude every DMA master or acquire a power lease.
 * The caller must bind current-boot ownership and successful original MEM_SETUP;
 * the separate payload verifier enforces the exact readable byte extents.
 */
#include <Uefi.h>
#include <PiDxe.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include "OpenDspAdmission.h"
#include "OpenMainAdmission.h"
#include "OpenMainAdmissionPlan.h"

#define PIL_BASE 0x8a800000ULL
#define PIL_BYTES 0x18a80000ULL
#define PAR_ADDRESS 0x000ffffffffff000ULL
STATIC BOOLEAN mInitialized,mBusy;
STATIC OPEN_MAIN_ADMISSION_REPORT mMain;
STATIC CONST UINT64 mMmioPages[]={0xaf08000,0xaf09000,0xae00000,0xae6a000,0xae6b000};
STATIC CONST UINT64 mClockAddress[]={0xaf08000,0xaf0800c,0xaf080a4,0xaf09000,0xaf09004};
_Static_assert(sizeof(OPEN_MAIN_CHECK)==104,"fixed main check ABI");
_Static_assert(sizeof(OPEN_MAIN_ADMISSION_REPORT)==368,"fixed main admission ABI");

STATIC EFI_STATUS Fail(OPEN_MAIN_CHECK *r,UINT32 why,EFI_STATUS status){
 if(!r->Reason){r->Reason=why;r->Status=status;}return r->Status;
}
STATIC BOOLEAN Covers(UINT64 base,UINT64 bytes,UINT64 address,UINT64 length){
 return bytes&&base<=MAX_UINT64-bytes&&address>=base&&address<=base+bytes&&length<=base+bytes-address;
}
STATIC EFI_STATUS ReservedMap(OPEN_MAIN_CHECK *r){
 EFI_GCD_MEMORY_SPACE_DESCRIPTOR d;EFI_STATUS s;UINTN bytes=0,key=0,stride=0;UINT32 version=0;
 EFI_MEMORY_DESCRIPTOR *map=NULL;UINTN capacity,count=0;
 s=gDS->GetMemorySpaceDescriptor(MAIN_BASE,&d);
 if(s!=EFI_SUCCESS||d.BaseAddress!=PIL_BASE||d.Length!=PIL_BYTES||
    d.GcdMemoryType!=EfiGcdMemoryTypeReserved||d.Attributes!=0||
    !(d.Capabilities&EFI_MEMORY_UC)||d.ImageHandle||d.DeviceHandle)
  return Fail(r,MAIN_GCD,EFI_ACCESS_DENIED);
 s=gBS->GetMemoryMap(&bytes,NULL,&key,&stride,&version);
 if(s!=EFI_BUFFER_TOO_SMALL||bytes<sizeof(EFI_MEMORY_DESCRIPTOR)||bytes>0x8000||
    stride<sizeof(EFI_MEMORY_DESCRIPTOR)||stride>256||(stride&7))
  return Fail(r,MAIN_MEMORY_MAP,EFI_COMPROMISED_DATA);
 capacity=bytes+16*stride;
 if(capacity>0x10000)return Fail(r,MAIN_MEMORY_MAP,EFI_BAD_BUFFER_SIZE);
 map=AllocatePool(capacity);if(!map)return Fail(r,MAIN_MEMORY_MAP,EFI_OUT_OF_RESOURCES);
 bytes=capacity;s=gBS->GetMemoryMap(&bytes,map,&key,&stride,&version);
 if(s!=EFI_SUCCESS||!bytes||bytes>capacity||stride<sizeof(*map)||stride>256||
    (stride&7)||bytes%stride||version!=1){s=Fail(r,MAIN_MEMORY_MAP,EFI_COMPROMISED_DATA);goto Done;}
 for(UINTN offset=0;offset<bytes;offset+=stride){
  EFI_MEMORY_DESCRIPTOR *m=(VOID *)((UINT8 *)map+offset);
  if(m->NumberOfPages>MAX_UINT64/4096||m->PhysicalStart>MAX_UINT64-m->NumberOfPages*4096){s=Fail(r,MAIN_MEMORY_MAP,EFI_COMPROMISED_DATA);goto Done;}
  if(m->PhysicalStart<MAIN_BASE+MAIN_BYTES&&MAIN_BASE<m->PhysicalStart+m->NumberOfPages*4096){
   count++;
   if(m->PhysicalStart!=PIL_BASE||m->NumberOfPages!=PIL_BYTES/4096||
      m->Type!=EfiReservedMemoryType||m->Attribute!=EFI_MEMORY_UC){s=Fail(r,MAIN_MEMORY_MAP,EFI_ACCESS_DENIED);goto Done;}
  }
 }
 s=count==1?EFI_SUCCESS:Fail(r,MAIN_MEMORY_MAP,EFI_ACCESS_DENIED);
Done:FreePool(map);return s;
}
STATIC EFI_STATUS CpuMap(OPEN_MAIN_CHECK *r){
 UINT64 el=OpenDspCurrentEl();r->CpuEl=el;
 if(el!=1&&el!=2)return Fail(r,MAIN_CPU,EFI_UNSUPPORTED);
 for(UINTN run=0;run<sizeof(mMainPageRuns)/sizeof(*mMainPageRuns);run++){
  for(UINT64 at=mMainPageRuns[run].Base;at<mMainPageRuns[run].End;at+=4096){
   if(mMain.Fault&OMA_REENTRANT)return Fail(r,MAIN_REENTRY,EFI_ACCESS_DENIED);
   r->ReadPar=OpenDspAt(&el,at,0);r->AtQueries++;r->WritePar=0;
   if(!(r->ReadPar&1)){r->WritePar=OpenDspAt(&el,at,1);r->AtQueries++;}
   if((r->ReadPar&1)||(r->WritePar&1)||
      (r->ReadPar&PAR_ADDRESS)!=at||(r->WritePar&PAR_ADDRESS)!=at||
      (r->ReadPar>>56)!=0x44||(r->WritePar>>56)!=0x44){r->FirstBad=at;return Fail(r,MAIN_CPU,EFI_ACCESS_DENIED);}
   r->CpuPages++;
  }
 }
 if(r->CpuPages!=MAIN_CPU_PAGES)return Fail(r,MAIN_BUDGET,EFI_COMPROMISED_DATA);
 return EFI_SUCCESS;
}
STATIC EFI_STATUS DeviceMap(OPEN_MAIN_CHECK *r){
 CONST UINT64 cache=EFI_MEMORY_UC|EFI_MEMORY_WC|EFI_MEMORY_WT|EFI_MEMORY_WB|EFI_MEMORY_UCE;
 for(UINTN i=0;i<sizeof(mMmioPages)/sizeof(*mMmioPages);i++){
  if(mMain.Fault&OMA_REENTRANT)return Fail(r,MAIN_REENTRY,EFI_ACCESS_DENIED);
  UINT64 at=mMmioPages[i],par;EFI_GCD_MEMORY_SPACE_DESCRIPTOR d;
  EFI_STATUS s=gDS->GetMemorySpaceDescriptor(at,&d);
  if(s!=EFI_SUCCESS||d.GcdMemoryType!=EfiGcdMemoryTypeMemoryMappedIo||
     !Covers(d.BaseAddress,d.Length,at,4096)||!(d.Capabilities&EFI_MEMORY_UC)||
     ((d.Attributes&cache)!=0&&(d.Attributes&cache)!=EFI_MEMORY_UC)||(d.Attributes&EFI_MEMORY_RP)){
   r->FirstBad=at;return Fail(r,MAIN_MMIO_MAP,EFI_ACCESS_DENIED);
  }
  par=OpenDspAt(&r->CpuEl,at,0);r->AtQueries++;
  /* Device-nGnRnE or Device-nGnRE only; never normal-memory aliases. */
  if((par&1)||(par&PAR_ADDRESS)!=at||((par>>56)!=0&&(par>>56)!=4)){
   r->FirstBad=at;r->ReadPar=par;return Fail(r,MAIN_MMIO_MAP,EFI_ACCESS_DENIED);
  }
  r->MmioPages++;
 }
 return EFI_SUCCESS;
}
STATIC BOOLEAN Word(OPEN_MAIN_CHECK *r,UINT64 address,UINT32 *value){
 if(mMain.Fault&OMA_REENTRANT){Fail(r,MAIN_REENTRY,EFI_ACCESS_DENIED);return FALSE;}
 BOOLEAN allowed=address==0xae00000||address==0xae6a604||address==0xae6b604;
 for(UINTN i=0;i<5;i++)if(address==mClockAddress[i])allowed=TRUE;
 if(!allowed||r->MmioReads>=64){Fail(r,allowed?MAIN_BUDGET:MAIN_ARGUMENT,EFI_ACCESS_DENIED);return FALSE;}
 r->MmioReads++;MemoryFence();
#ifndef OPEN_MAIN_ADMISSION_MODEL
 *value=*(volatile CONST UINT32 *)(UINTN)address;
#else
 extern UINT32 OpenMainModelRead(UINT64);
 *value=OpenMainModelRead(address);
#endif
 MemoryFence();return TRUE;
}
STATIC BOOLEAN Gates(OPEN_MAIN_CHECK *r){
 for(UINTN i=0;i<5;i++)if(!Word(r,mClockAddress[i],&r->Clock[i]))return FALSE;
 if((r->Clock[0]&1)||
    (r->Clock[1]&0x80000001u)!=1||(r->Clock[2]&0x80000001u)!=1||
    (r->Clock[3]&0x80000007u)!=0x80000000u||
    (r->Clock[4]&0x18000u)!=0x10000u){Fail(r,MAIN_CLOCK,EFI_ACCESS_DENIED);return FALSE;}
 return TRUE;
}
STATIC EFI_STATUS Display(OPEN_MAIN_CHECK *r){
 if(!Gates(r))return r->Status;
 if(!Gates(r)||!Word(r,0xae00000,&r->HwVersion)||!Gates(r))return r->Status;
 if(r->HwVersion!=0x90000001u)return Fail(r,MAIN_VERSION,EFI_UNSUPPORTED);
 for(UINTN i=0;i<2;i++){
  if(!Gates(r)||!Word(r,i?0xae6b604:0xae6a604,&r->Demura[i])||!Gates(r))return r->Status;
  /* Exact previously observed invalid-fetch-selection word, not an inference
   * from SSPP addresses that may be stale or IOVAs. Unknown bits refuse. */
  if(r->Demura[i]!=0)return Fail(r,MAIN_DEMURA,EFI_ACCESS_DENIED);
 }
 return Gates(r)?EFI_SUCCESS:r->Status;
}
STATIC EFI_STATUS Check(UINTN index,BOOLEAN footprint,OPEN_MAIN_LOG log){
 OPEN_MAIN_CHECK *r=&mMain.Check[index];EFI_STATUS s;
 if(footprint!=TRUE)s=Fail(r,MAIN_SOURCE,EFI_NOT_READY);
 else if((s=ReservedMap(r))==EFI_SUCCESS&&(s=CpuMap(r))==EFI_SUCCESS&&
         (s=DeviceMap(r))==EFI_SUCCESS&&(s=Display(r))==EFI_SUCCESS)r->Complete=1;
 r->Status=s;
 log("G150_main_check index=%u status=%r reason=%x CPU_pages=%lu AT=%lu MMIO=%u Demura=%x/%x complete=%u global_DMA=not_proved\n",
     (UINT32)index,s,r->Reason,r->CpuPages,r->AtQueries,r->MmioReads,r->Demura[0],r->Demura[1],r->Complete);
 /* A callback cannot reenter and leave the outer attempt successful. */
 if(mMain.Fault&OMA_REENTRANT){r->Complete=0;s=Fail(r,MAIN_REENTRY,EFI_ACCESS_DENIED);}
 return s;
}
EFI_STATUS OpenMainAdmissionInit(VOID){
 if(mInitialized)return EFI_ALREADY_STARTED;
 mInitialized=TRUE;ZeroMem(&mMain,sizeof(mMain));mMain.Size=sizeof(mMain);mMain.Version=1;
 mMain.CopyStatus=mMain.RefreshStatus[0]=mMain.RefreshStatus[1]=EFI_NOT_READY;
 for(UINTN i=0;i<3;i++)mMain.Check[i].Status=EFI_NOT_READY;
 return EFI_SUCCESS;
}
CONST OPEN_MAIN_ADMISSION_REPORT *OpenGetMainAdmissionReport(VOID){return mInitialized?&mMain:NULL;}
STATIC EFI_STATUS Enter(OPEN_MAIN_LOG log){
 if(!mInitialized||!log)return EFI_INVALID_PARAMETER;
 if(mBusy){mMain.Fault|=OMA_REENTRANT;return EFI_ACCESS_DENIED;}
 return EFI_SUCCESS;
}
EFI_STATUS OpenMainAuthorizeCopy(BOOLEAN footprint,OPEN_MAIN_LOG log){
 EFI_STATUS s=Enter(log);if(s!=EFI_SUCCESS)return s;
 if(mMain.CopyAttempts||mMain.RefreshAttempts||mMain.Fault)return EFI_ALREADY_STARTED;
 mMain.CopyAttempts=1;mBusy=TRUE;
 mMain.CopyStatus=Check(0,footprint,log);
 if(mMain.CopyStatus==EFI_SUCCESS)mMain.CopyGranted=1;else mMain.Fault|=OMA_CHECK;
 mBusy=FALSE;return mMain.CopyStatus;
}
EFI_STATUS OpenMainRefreshAdmission(BOOLEAN footprint,OPEN_MAIN_LOG log){
 EFI_STATUS s=Enter(log);if(s!=EFI_SUCCESS)return s;
 if(mMain.RefreshAttempts>=2||mMain.Fault)return EFI_ALREADY_STARTED;
 UINT32 attempt=mMain.RefreshAttempts++;
 if(mMain.CopyGranted!=1||mMain.CopyStatus!=EFI_SUCCESS||mMain.AcceptedRefreshes!=attempt){
  mMain.Fault|=OMA_SEQUENCE;return mMain.RefreshStatus[attempt]=EFI_NOT_READY;
 }
 mBusy=TRUE;mMain.RefreshStatus[attempt]=Check(attempt+1,footprint,log);
 if(mMain.RefreshStatus[attempt]==EFI_SUCCESS)mMain.AcceptedRefreshes++;else mMain.Fault|=OMA_CHECK;
 mBusy=FALSE;return mMain.RefreshStatus[attempt];
}
