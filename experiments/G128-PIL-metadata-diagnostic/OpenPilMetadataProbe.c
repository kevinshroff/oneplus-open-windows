/** @file G128 fixed original-loader metadata diagnostic. No PAS request.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Uefi.h>
#include <IndustryStandard/Acpi.h>
#include <Protocol/AcpiTable.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/MemoryAttribute.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include "OpenSha256.h"
#include "OpenPilMetadataProbe.h"
#include "OpenPilMetadataBindings.h"

STATIC EFI_GUID mPil = {0x1f4f1da3,0x4d8d,0x4894,{0xba,0x2a,0x13,0xd3,0x20,0x7f,0x97,0x39}};
STATIC EFI_GUID mScm = {0x77ed108d,0x8524,0x4b8b,{0x9d,0x2e,0x34,0x98,0x7a,0xec,0xb9,0xc1}};
STATIC BOOLEAN mRan;
STATIC G128_REPORT mReport;

typedef UINT64(EFIAPI *GET_CFG)(CHAR16 *,VOID *);
typedef UINT64(EFIAPI *LOAD_META)(UINT64 *);
typedef UINT64(EFIAPI *CHECK_HEADER)(UINT64 *,VOID *);
typedef VOID(EFIAPI *UNCACHED_FREE)(VOID *);
STATIC UINT64 Q(CONST VOID *P){UINT64 V;CopyMem(&V,P,8);return V;}
STATIC VOID SetQ(VOID *P,UINT64 V){CopyMem(P,&V,8);}

#ifndef OPEN_G128_TEST_CALLS
STATIC UINT64 GetCfg(UINTN F,CHAR16 *Name,VOID *Out){return ((GET_CFG)F)(Name,Out);}
STATIC UINT64 LoadMeta(UINTN F,UINT64 *Ctx){return ((LOAD_META)F)(Ctx);}
STATIC UINT64 Header(UINTN F,UINT64 *Ctx,VOID *Data){return ((CHECK_HEADER)F)(Ctx,Data);}
STATIC VOID Release(UINTN F,VOID *P){((UNCACHED_FREE)F)(P);}
#else
UINT64 GetCfg(UINTN,CHAR16 *,VOID *);
UINT64 LoadMeta(UINTN,UINT64 *);
UINT64 Header(UINTN,UINT64 *,VOID *);
VOID Release(UINTN,VOID *);
#endif

STATIC EFI_STATUS
BindImage(VOID *Protocol,CONST G128_IMAGE *Spec,UINT64 *Base,UINT32 *Variant)
{
 EFI_HANDLE *Handles=NULL;EFI_LOADED_IMAGE_PROTOCOL *Loaded;
 EFI_STATUS S;UINTN Count=0,I,J,Found=0;UINT64 B=0,V;
 UINT8 *Copy=NULL,Hash[32];
 S=gBS->LocateHandleBuffer(ByProtocol,&gEfiLoadedImageProtocolGuid,NULL,&Count,&Handles);
 if(S!=EFI_SUCCESS)return S;
 if(Count>256){S=EFI_COMPROMISED_DATA;goto Done;}
 for(I=0;I<Count;I++){
  S=gBS->HandleProtocol(Handles[I],&gEfiLoadedImageProtocolGuid,(VOID **)&Loaded);
  if(S!=EFI_SUCCESS||Loaded==NULL||Loaded->ImageBase==NULL||Loaded->ImageSize!=Spec->ImageBytes)continue;
  B=(UINTN)Loaded->ImageBase;
  if(B>MAX_UINT64-Spec->ImageBytes)continue;
  for(J=0;J<Spec->ProtocolCount;J++)if((UINTN)Protocol==B+Spec->ProtocolRva[J]){
   Found++;*Base=B;*Variant=(UINT32)J;
  }
 }
 if(Found!=1){S=Found?EFI_NO_MAPPING:EFI_NOT_FOUND;goto Done;}
 B=*Base;
 if(Spec->TextRva>Spec->ImageBytes||Spec->TextBytes>Spec->ImageBytes-Spec->TextRva){S=EFI_COMPROMISED_DATA;goto Done;}
 Copy=AllocatePool(Spec->TextBytes);if(Copy==NULL){S=EFI_OUT_OF_RESOURCES;goto Done;}
 CopyMem(Copy,(VOID *)(UINTN)(B+Spec->TextRva),Spec->TextBytes);
 for(I=0;I<Spec->RelocCount;I++){
  J=Spec->Reloc[I];
  if(J>Spec->TextBytes||8>Spec->TextBytes-J){S=EFI_COMPROMISED_DATA;goto Done;}
  V=Q(Copy+J);if(V<B){S=EFI_COMPROMISED_DATA;goto Done;}SetQ(Copy+J,V-B);
 }
 OpenShaAll(Copy,Spec->TextBytes,Hash);
 S=CompareMem(Hash,Spec->TextHash,32)?EFI_COMPROMISED_DATA:EFI_SUCCESS;
Done:
 if(Copy!=NULL)FreePool(Copy);if(Handles!=NULL)FreePool(Handles);
 if(S!=EFI_SUCCESS)*Base=0;
 return S;
}

STATIC EFI_STATUS
ProbeOne(UINTN Index,UINT64 Base)
{
 UINT64 State[23],Ctx[2],V,Before,After;
 EFI_STATUS Cleanup=EFI_SUCCESS,S;
 UINTN I;UINT8 Digest[32];BOOLEAN Good=FALSE;
 ZeroMem(State,sizeof(State));Ctx[0]=(UINTN)mReport.Config[Index];Ctx[1]=(UINTN)State;
 mReport.ImagesAttempted++;
 mReport.Status[9+Index]=LoadMeta((UINTN)Base+0x3144,Ctx);
 if(mReport.Status[9+Index]!=0)goto Done;
 mReport.CachedAddress[Index]=State[6];mReport.UncachedAddress[Index]=State[7];
 if(State[6]==0||State[7]==0)goto Done;
 OpenShaAll((VOID *)(UINTN)State[6],mMetadata[Index].Bytes,Digest);CopyMem(mReport.CachedDigest[Index],Digest,32);
 if(CompareMem(Digest,mMetadata[Index].Hash,32)!=0)goto Done;
 OpenShaAll((VOID *)(UINTN)State[7],mMetadata[Index].Bytes,Digest);CopyMem(mReport.UncachedDigest[Index],Digest,32);
 if(CompareMem(Digest,mMetadata[Index].Hash,32)!=0)goto Done;
 mReport.Flags|=1U<<(5+Index);
 mReport.Status[11+Index]=Header((UINTN)Base+0x2200,Ctx,(VOID *)(UINTN)State[6]);
 if(mReport.Status[11+Index]==0){mReport.Flags|=1U<<(7+Index);Good=TRUE;}
Done:
 /* The table's3bcc method is PAS shutdown, not memory cleanup. Never call it.
  * The three cached pointers come from EFI AllocatePool; uncached memory is
  * returned to PIL's arena with its own fixed free primitive. */
 if(State[7]){
  Before=Q((VOID *)(UINTN)(Base+0x1b228));
  Release((UINTN)Base+0xfcd4,(VOID *)(UINTN)State[7]);
  After=Q((VOID *)(UINTN)(Base+0x1b228));
  if(After>Before && After-Before>=((mMetadata[Index].Bytes+4095)&~4095ULL) &&
     ((After-Before)&4095)==0)mReport.UncachedReleaseBytes[Index]=After-Before;
  else Cleanup=EFI_DEVICE_ERROR;
 }
 for(I=0;I<3;I++){
  V=State[I==0?3:I==1?4:6];if(V==0)continue;
  S=gBS->FreePool((VOID *)(UINTN)V);if(S!=EFI_SUCCESS)Cleanup=S;
 }
 mReport.Status[13+Index]=Cleanup;
 if(Cleanup==EFI_SUCCESS)mReport.Flags|=1U<<(9+Index);
 return Good&&Cleanup==EFI_SUCCESS?EFI_SUCCESS:EFI_DEVICE_ERROR;
}

STATIC EFI_STATUS
Publish(VOID)
{
 EFI_ACPI_TABLE_PROTOCOL *Acpi;EFI_ACPI_DESCRIPTION_HEADER *H;
 EFI_STATUS S;UINTN Key,N=sizeof(*H)+sizeof(mReport),I;UINT8 Sum=0;
 S=gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid,NULL,(VOID **)&Acpi);if(S!=EFI_SUCCESS)return S;
 H=AllocateZeroPool(N);if(H==NULL)return EFI_OUT_OF_RESOURCES;
 H->Signature=SIGNATURE_32('O','P','A','S');H->Length=(UINT32)N;H->Revision=1;
 CopyMem(H->OemId,"OPEN  ",6);CopyMem(&H->OemTableId,"G128META",8);H->OemRevision=128;
 H->CreatorId=SIGNATURE_32('O','P','E','N');H->CreatorRevision=1;CopyMem(H+1,&mReport,sizeof(mReport));
 for(I=0;I<N;I++)Sum=(UINT8)(Sum+((UINT8 *)H)[I]);H->Checksum=(UINT8)(0-Sum);
 S=Acpi->InstallAcpiTable(Acpi,H,N,&Key);FreePool(H);return S;
}

EFI_STATUS
OpenRunPilMetadataProbe(BOOLEAN PreflightReady)
{
 VOID *Pil=NULL,*Scm=NULL;EFI_MEMORY_ATTRIBUTE_PROTOCOL *Memory=NULL;
 EFI_STATUS S;UINT32 Variant=0;UINTN I;UINT64 Fn,Attr=0;BOOLEAN Ready;
 if(mRan)return EFI_ALREADY_STARTED;mRan=TRUE;
 ZeroMem(&mReport,sizeof(mReport));mReport.Size=sizeof(mReport);mReport.Version=1;mReport.Magic=G128_MAGIC;
 for(I=0;I<16;I++)mReport.Status[I]=EFI_NOT_READY;
 for(I=9;I<=12;I++)mReport.Status[I]=MAX_UINT64;
 CopyMem(mReport.InputDigest,mInputDigest,32);mReport.Status[1]=PreflightReady?EFI_SUCCESS:EFI_NOT_READY;
 if(PreflightReady)mReport.Flags|=1U<<4;
 mReport.Status[2]=gBS->LocateProtocol(&mPil,NULL,&Pil);
 mReport.Status[3]=gBS->LocateProtocol(&mScm,NULL,&Scm);
 if(mReport.Status[2]==EFI_SUCCESS&&Pil!=NULL){
  mReport.Status[4]=BindImage(Pil,&mPilImage,&mReport.ImageBase[0],&Variant);
  if(mReport.Status[4]==EFI_SUCCESS){
   if(Q(Pil)!=0x10004||Q((UINT8 *)Pil+8)!=mReport.ImageBase[0]+0x1708||Q((UINT8 *)Pil+48)!=mReport.ImageBase[0]+0x17e8)mReport.Status[4]=EFI_COMPROMISED_DATA;
   else mReport.Flags|=1U;
  }
 }
 if(mReport.Status[3]==EFI_SUCCESS&&Scm!=NULL){
  mReport.Status[5]=BindImage(Scm,&mScmImage,&mReport.ImageBase[1],&Variant);
  if(mReport.Status[5]==EFI_SUCCESS){
   Fn=Q((UINT8 *)Scm+56);mReport.ScmTableRva=mScmImage.ProtocolRva[Variant];
   mReport.ScmFunctionRva=Variant?0x3f94:0x185c;mReport.ScmABI=Variant?2:1;
   if(Q(Scm)!=0x40001||Fn!=mReport.ImageBase[1]+mReport.ScmFunctionRva)mReport.Status[5]=EFI_COMPROMISED_DATA;
   else{
    mReport.Flags|=2U;
    mReport.Status[15]=gBS->LocateProtocol(&gEfiMemoryAttributeProtocolGuid,NULL,(VOID **)&Memory);
    if(mReport.Status[15]==EFI_SUCCESS&&Memory!=NULL){
     mReport.Status[8]=Memory->GetMemoryAttributes(Memory,((UINTN)Scm+56)&~0xfffULL,4096,&Attr);
     if(mReport.Status[8]==EFI_SUCCESS){mReport.SlotAttributes=Attr;mReport.Flags|=1U<<11;}
    }
   }
  }
 }
 if(mReport.Flags&1U)for(I=0;I<2;I++){
  mReport.Status[6+I]=GetCfg((UINTN)mReport.ImageBase[0]+0x17e8,(CHAR16 *)mMetadata[I].Name,mReport.Config[I]);
  if(mReport.Status[6+I]!=0)continue;
  OpenShaAll(mReport.Config[I],G128_CFG_BYTES,mReport.ConfigDigest[I]);
  if(!CompareMem(mReport.ConfigDigest[I],mMetadata[I].ConfigHash,32))mReport.Flags|=1U<<(2+I);
 }
 Ready=PreflightReady&&(mReport.Flags&13U)==13U;
 if(Ready)for(I=0;I<2;I++){
  if(ProbeOne(I,mReport.ImageBase[0])!=EFI_SUCCESS)Ready=FALSE;
  if(mReport.Status[13+I]!=EFI_SUCCESS)break;
 }
 mReport.Status[0]=Ready?EFI_SUCCESS:EFI_NOT_READY;
 /* Source-level requested PAS count stays0; this is not global DSP state. */
 mReport.RequestedPasStages=0;
 S=Publish();return S;
}
