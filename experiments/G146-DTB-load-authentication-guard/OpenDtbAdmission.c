/* SPDX-License-Identifier: MIT
 * The original PIL writes only CFGL b01's 8376 bytes, in the declared original
 * DTB reservation. This finite experiment adds fresh reserved-map/CPU checks
 * and observes the known Demura conflict before permitting that copy/auth.
 * It does not exclude every unobserved DMA master, remap memory, write MMIO,
 * allocate the carveout, acquire a power lease, or write authenticated data.
 */
#include <Uefi.h>
#include <PiDxe.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include "OpenDspAdmission.h"
#include "OpenDtbAdmission.h"

#define DTB_BASE 0x9e980000ULL
#define DTB_BYTES 8376U
#define DTB_PAGES 3U
#define PIL_BASE 0x8a800000ULL
#define PIL_BYTES 0x18a80000ULL
#define PAR_ADDRESS 0x000ffffffffff000ULL
STATIC BOOLEAN mInitialized;
STATIC OPEN_DTB_ADMISSION_REPORT mDtb;
STATIC CONST UINT64 mMmioPages[]={0xaf08000,0xaf09000,0xae00000,0xae6a000,0xae6b000};
STATIC CONST UINT64 mClockAddress[]={0xaf08000,0xaf0800c,0xaf080a4,0xaf09000,0xaf09004};
STATIC CONST UINT8 mExpectedDigest[32]={
 0xf7,0x18,0x92,0xad,0x4f,0xf2,0xac,0x11,0x00,0xa0,0x7f,0x63,0xb4,0xa5,0xef,0x24,
 0x67,0x49,0xa9,0x59,0x37,0xa7,0x97,0xd5,0x04,0x80,0xe7,0xc7,0x0b,0x1b,0x2f,0x94};
_Static_assert(sizeof(OPEN_DTB_CHECK)==104,"fixed DTB check ABI");
_Static_assert(sizeof(OPEN_DTB_ADMISSION_REPORT)==392,"fixed DTB admission ABI");

STATIC EFI_STATUS Fail(OPEN_DTB_CHECK *r,UINT32 why,EFI_STATUS status){
 if(!r->Reason){r->Reason=why;r->Status=status;}return r->Status;
}
STATIC BOOLEAN Covers(UINT64 base,UINT64 bytes,UINT64 address,UINT64 length){
 return bytes&&base<=MAX_UINT64-bytes&&address>=base&&address<=base+bytes&&length<=base+bytes-address;
}
STATIC EFI_STATUS ReservedMap(OPEN_DTB_CHECK *r){
 EFI_GCD_MEMORY_SPACE_DESCRIPTOR d;EFI_STATUS s;UINTN bytes=0,key=0,stride=0;UINT32 version=0;
 EFI_MEMORY_DESCRIPTOR *map=NULL;UINTN capacity,count=0;
 s=gDS->GetMemorySpaceDescriptor(DTB_BASE,&d);
 if(s!=EFI_SUCCESS||d.BaseAddress!=PIL_BASE||d.Length!=PIL_BYTES||
    d.GcdMemoryType!=EfiGcdMemoryTypeReserved||d.Attributes!=0||
    !(d.Capabilities&EFI_MEMORY_UC)||d.ImageHandle||d.DeviceHandle)
  return Fail(r,DTB_GCD,EFI_ACCESS_DENIED);
 s=gBS->GetMemoryMap(&bytes,NULL,&key,&stride,&version);
 if(s!=EFI_BUFFER_TOO_SMALL||bytes<sizeof(EFI_MEMORY_DESCRIPTOR)||bytes>0x8000||
    stride<sizeof(EFI_MEMORY_DESCRIPTOR)||stride>256||(stride&7))
  return Fail(r,DTB_MEMORY_MAP,EFI_COMPROMISED_DATA);
 capacity=bytes+16*stride;
 if(capacity>0x10000)return Fail(r,DTB_MEMORY_MAP,EFI_BAD_BUFFER_SIZE);
 map=AllocatePool(capacity);if(!map)return Fail(r,DTB_MEMORY_MAP,EFI_OUT_OF_RESOURCES);
 bytes=capacity;s=gBS->GetMemoryMap(&bytes,map,&key,&stride,&version);
 if(s!=EFI_SUCCESS||!bytes||bytes>capacity||stride<sizeof(*map)||stride>256||
    (stride&7)||bytes%stride||version!=1){s=Fail(r,DTB_MEMORY_MAP,EFI_COMPROMISED_DATA);goto Done;}
 for(UINTN offset=0;offset<bytes;offset+=stride){
  EFI_MEMORY_DESCRIPTOR *m=(VOID *)((UINT8 *)map+offset);
  if(m->NumberOfPages>MAX_UINT64/4096||m->PhysicalStart>MAX_UINT64-m->NumberOfPages*4096){s=Fail(r,DTB_MEMORY_MAP,EFI_COMPROMISED_DATA);goto Done;}
  if(m->PhysicalStart<DTB_BASE+0x80000&&DTB_BASE<m->PhysicalStart+m->NumberOfPages*4096){
   count++;
   if(m->PhysicalStart!=PIL_BASE||m->NumberOfPages!=PIL_BYTES/4096||
      m->Type!=EfiReservedMemoryType||m->Attribute!=EFI_MEMORY_UC){s=Fail(r,DTB_MEMORY_MAP,EFI_ACCESS_DENIED);goto Done;}
  }
 }
 s=count==1?EFI_SUCCESS:Fail(r,DTB_MEMORY_MAP,EFI_ACCESS_DENIED);
Done:FreePool(map);return s;
}
STATIC EFI_STATUS CpuMap(OPEN_DTB_CHECK *r){
 UINT64 el=OpenDspCurrentEl();r->CpuEl=el;
 if(el!=1&&el!=2)return Fail(r,DTB_CPU,EFI_UNSUPPORTED);
 for(UINTN i=0;i<DTB_PAGES;i++){
  UINT64 at=DTB_BASE+i*4096;
  r->ReadPar=OpenDspAt(&el,at,0);r->AtQueries++;r->WritePar=0;
  if(!(r->ReadPar&1)){r->WritePar=OpenDspAt(&el,at,1);r->AtQueries++;}
  if((r->ReadPar&1)||(r->WritePar&1)||
     (r->ReadPar&PAR_ADDRESS)!=at||(r->WritePar&PAR_ADDRESS)!=at||
     (r->ReadPar>>56)!=0x44||(r->WritePar>>56)!=0x44){r->FirstBad=at;return Fail(r,DTB_CPU,EFI_ACCESS_DENIED);}
  r->CpuPages++;
 }
 return EFI_SUCCESS;
}
STATIC EFI_STATUS DeviceMap(OPEN_DTB_CHECK *r){
 CONST UINT64 cache=EFI_MEMORY_UC|EFI_MEMORY_WC|EFI_MEMORY_WT|EFI_MEMORY_WB|EFI_MEMORY_UCE;
 for(UINTN i=0;i<sizeof(mMmioPages)/sizeof(*mMmioPages);i++){
  UINT64 at=mMmioPages[i],par;EFI_GCD_MEMORY_SPACE_DESCRIPTOR d;
  EFI_STATUS s=gDS->GetMemorySpaceDescriptor(at,&d);
  if(s!=EFI_SUCCESS||d.GcdMemoryType!=EfiGcdMemoryTypeMemoryMappedIo||
     !Covers(d.BaseAddress,d.Length,at,4096)||!(d.Capabilities&EFI_MEMORY_UC)||
     ((d.Attributes&cache)!=0&&(d.Attributes&cache)!=EFI_MEMORY_UC)||(d.Attributes&EFI_MEMORY_RP)){
   r->FirstBad=at;return Fail(r,DTB_MMIO_MAP,EFI_ACCESS_DENIED);
  }
  par=OpenDspAt(&r->CpuEl,at,0);r->AtQueries++;
  /* Device-nGnRnE or Device-nGnRE only; never normal-memory aliases. */
  if((par&1)||(par&PAR_ADDRESS)!=at||((par>>56)!=0&&(par>>56)!=4)){
   r->FirstBad=at;r->ReadPar=par;return Fail(r,DTB_MMIO_MAP,EFI_ACCESS_DENIED);
  }
  r->MmioPages++;
 }
 return EFI_SUCCESS;
}
STATIC BOOLEAN Word(OPEN_DTB_CHECK *r,UINT64 address,UINT32 *value){
 BOOLEAN allowed=address==0xae00000||address==0xae6a604||address==0xae6b604;
 for(UINTN i=0;i<5;i++)if(address==mClockAddress[i])allowed=TRUE;
 if(!allowed||r->MmioReads>=64){Fail(r,allowed?DTB_BUDGET:DTB_ARGUMENT,EFI_ACCESS_DENIED);return FALSE;}
 r->MmioReads++;MemoryFence();
#ifndef OPEN_DTB_ADMISSION_MODEL
 *value=*(volatile CONST UINT32 *)(UINTN)address;
#else
 extern UINT32 OpenDtbModelRead(UINT64);
 *value=OpenDtbModelRead(address);
#endif
 MemoryFence();return TRUE;
}
STATIC BOOLEAN Gates(OPEN_DTB_CHECK *r){
 for(UINTN i=0;i<5;i++)if(!Word(r,mClockAddress[i],&r->Clock[i]))return FALSE;
 if((r->Clock[0]&1)||
    (r->Clock[1]&0x80000001u)!=1||(r->Clock[2]&0x80000001u)!=1||
    (r->Clock[3]&0x80000007u)!=0x80000000u||
    (r->Clock[4]&0x18000u)!=0x10000u){Fail(r,DTB_CLOCK,EFI_ACCESS_DENIED);return FALSE;}
 return TRUE;
}
STATIC EFI_STATUS Display(OPEN_DTB_CHECK *r){
 if(!Gates(r))return r->Status;
 if(!Gates(r)||!Word(r,0xae00000,&r->HwVersion)||!Gates(r))return r->Status;
 if(r->HwVersion!=0x90000001u)return Fail(r,DTB_VERSION,EFI_UNSUPPORTED);
 for(UINTN i=0;i<2;i++){
  if(!Gates(r)||!Word(r,i?0xae6b604:0xae6a604,&r->Demura[i])||!Gates(r))return r->Status;
  /* Exact previously observed invalid-fetch-selection word, not an inference
   * from SSPP addresses that may be stale or IOVAs. Unknown bits refuse. */
  if(r->Demura[i]!=0)return Fail(r,DTB_DEMURA,EFI_ACCESS_DENIED);
 }
 return Gates(r)?EFI_SUCCESS:r->Status;
}
STATIC EFI_STATUS Check(UINTN index,BOOLEAN footprint,OPEN_DTB_LOG log){
 OPEN_DTB_CHECK *r=&mDtb.Check[index];EFI_STATUS s;
 if(footprint!=TRUE)s=Fail(r,DTB_SOURCE,EFI_NOT_READY);
 else if((s=ReservedMap(r))==EFI_SUCCESS&&(s=CpuMap(r))==EFI_SUCCESS&&
         (s=DeviceMap(r))==EFI_SUCCESS&&(s=Display(r))==EFI_SUCCESS)r->Complete=1;
 r->Status=s;
 log("G146_DTB_check index=%u status=%r reason=%x CPU_pages=%lu AT=%lu MMIO=%u Demura=%x/%x complete=%u global_DMA=not_proved\n",
     (UINT32)index,s,r->Reason,r->CpuPages,r->AtQueries,r->MmioReads,r->Demura[0],r->Demura[1],r->Complete);
 return s;
}
EFI_STATUS OpenDtbAdmissionInit(VOID){
 if(mInitialized)return EFI_ALREADY_STARTED;
 mInitialized=TRUE;ZeroMem(&mDtb,sizeof(mDtb));mDtb.Size=sizeof(mDtb);mDtb.Version=1;
 mDtb.CopyStatus=mDtb.PayloadStatus=EFI_NOT_READY;
 for(UINTN i=0;i<3;i++)mDtb.Check[i].Status=EFI_NOT_READY;
 return EFI_SUCCESS;
}
CONST OPEN_DTB_ADMISSION_REPORT *OpenGetDtbAdmissionReport(VOID){return mInitialized?&mDtb:NULL;}
EFI_STATUS OpenDtbAuthorizeCopy(BOOLEAN footprint,OPEN_DTB_LOG log){
 if(!mInitialized||!log)return EFI_INVALID_PARAMETER;
 if(mDtb.CopyAttempts||mDtb.PayloadAttempts)return EFI_ALREADY_STARTED;
 mDtb.CopyAttempts=1;mDtb.CopyStatus=Check(0,footprint,log);
 if(mDtb.CopyStatus==EFI_SUCCESS)mDtb.CopyGranted=1;
 return mDtb.CopyStatus;
}
EFI_STATUS OpenDtbVerifyPayload(BOOLEAN footprint,OPEN_DTB_LOG log){
 EFI_STATUS s;
 if(!mInitialized||!log)return EFI_INVALID_PARAMETER;
 if(mDtb.PayloadAttempts)return EFI_ALREADY_STARTED;
 mDtb.PayloadAttempts=1;
 if(mDtb.CopyGranted!=1||mDtb.CopyStatus!=EFI_SUCCESS)return mDtb.PayloadStatus=EFI_NOT_READY;
 s=Check(1,footprint,log);if(s!=EFI_SUCCESS)return mDtb.PayloadStatus=s;
 if(!Sha256HashAll((CONST VOID *)(UINTN)DTB_BASE,DTB_BYTES,mDtb.Digest)){
  mDtb.HashOutcome=1;return mDtb.PayloadStatus=EFI_DEVICE_ERROR;
 }
 mDtb.PayloadHashed=1;
 if(CompareMem(mDtb.Digest,mExpectedDigest,sizeof(mExpectedDigest))){
  mDtb.HashOutcome=2;return mDtb.PayloadStatus=EFI_SECURITY_VIOLATION;
 }
 mDtb.PayloadMatched=1;mDtb.HashOutcome=3;
 /* Recheck the finite observations after hashing, before secure forwarding.
  * No target read or rollback write is performed after authentication. */
 mDtb.PayloadStatus=Check(2,footprint,log);return mDtb.PayloadStatus;
}
