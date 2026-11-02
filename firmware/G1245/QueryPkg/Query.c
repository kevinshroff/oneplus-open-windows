/* Availability-only pre-EBS observer. No aperture setter, PAS, MMIO or OS callback. */
#include <Uefi.h>
#include <IndustryStandard/Acpi.h>
#include <Protocol/AcpiTable.h>
#include <Protocol/AcpiSystemDescriptionTable.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/DevicePath.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include "OpenSha256.h"
#include "ScmIdentity.h"
extern EFI_GUID gOpenG1245ScmProtocolGuid;
STATIC EFI_GUID ScmFileGuid = {0x16e48f1f,0x7944,0x4baa,{0xbc,0xa5,0x2d,0x0c,0xb7,0x88,0xa9,0x04}};
typedef struct SCM_PROTOCOL SCM_PROTOCOL;
typedef EFI_STATUS (EFIAPI *SCM_SIP)(SCM_PROTOCOL *,UINT32,UINT32,UINT64 *,UINT64 *);
struct SCM_PROTOCOL {UINT64 Revision;VOID *Reserved[6];SCM_SIP Sip;};
STATIC_ASSERT(OFFSET_OF(SCM_PROTOCOL,Sip)==0x38,"Original Sip protocol slot");
STATIC_ASSERT(sizeof(SCM_PROTOCOL)==0x40,"Original protocol layout");
#define QUERY_SIGNATURE SIGNATURE_32('O','A','S','Q')
#define F_LOCATE_ATTEMPT 1u
#define F_LOCATE_OK 2u
#define F_IDENTITY_OK 4u
#define F_CALL_ATTEMPT 8u
#define F_CALL_RETURNED 16u
#define F_COMPLETION_OK 32u
#define F_AVAILABLE 64u
#pragma pack(push,1)
typedef struct {
 EFI_ACPI_DESCRIPTION_HEADER Header;
 UINT32 Version,Flags;
 UINT64 LocateStatus,IdentityStatus,CallStatus,ProtocolRevision;
 UINT32 MethodRva,ImageBytes,ImageCodeType,ImageDataType,SmcId,ParamId;
 UINT64 Arguments[10],Results[4];
 UINT8 NormalizedTextSha256[32];
} REPORT;
#pragma pack(pop)
STATIC_ASSERT(sizeof(REPORT)==244,"OASQ v1 packed report");
STATIC BOOLEAN Attempted;
STATIC UINT8 Sum(CONST VOID *P,UINTN N){CONST UINT8 *B=P;UINT8 S=0;for(UINTN I=0;I<N;I++)S=(UINT8)(S+B[I]);return S;}
STATIC UINT32 U32(CONST VOID *P){UINT32 V;CopyMem(&V,P,sizeof(V));return V;}
STATIC UINT64 U64(CONST VOID *P){UINT64 V;CopyMem(&V,P,sizeof(V));return V;}
STATIC BOOLEAN ScmFilePath(EFI_DEVICE_PATH_PROTOCOL *Path){
 if(!Path)return FALSE;UINTN Offset=0,Found=0;
 while(Offset+4<=512){
  EFI_DEVICE_PATH_PROTOCOL *D=(VOID *)((UINT8 *)Path+Offset);
  UINTN N=(UINTN)D->Length[0]|((UINTN)D->Length[1]<<8);
  if(N<4||N>512-Offset)return FALSE;
  if(D->Type==END_DEVICE_PATH_TYPE)return Found==1&&D->SubType==END_ENTIRE_DEVICE_PATH_SUBTYPE&&N==4;
  if(D->Type==MEDIA_DEVICE_PATH&&D->SubType==MEDIA_PIWG_FW_FILE_DP){
   if(N!=20||CompareMem((UINT8 *)D+4,&ScmFileGuid,16))return FALSE;Found++;
  }
  Offset+=N;
 }
 return FALSE;
}
STATIC EFI_STATUS Qualify(SCM_PROTOCOL *Scm,REPORT *R){
 EFI_HANDLE *Handles=NULL;UINTN Count=0,Matches=0;VOID *Text=NULL;EFI_STATUS St;
 if(!Scm||Scm->Revision!=0x40001||!Scm->Sip)return EFI_UNSUPPORTED;
 R->ProtocolRevision=Scm->Revision;
 St=gBS->LocateHandleBuffer(ByProtocol,&gEfiLoadedImageProtocolGuid,NULL,&Count,&Handles);
 if(EFI_ERROR(St))return St;
 if(Count>256){gBS->FreePool(Handles);return EFI_COMPROMISED_DATA;}
 St=gBS->AllocatePool(EfiBootServicesData,SCM_TEXT_BYTES,&Text);
 if(EFI_ERROR(St)){gBS->FreePool(Handles);return St;}
 for(UINTN I=0;I<Count;I++){
  EFI_LOADED_IMAGE_PROTOCOL *L=NULL;
  if(EFI_ERROR(gBS->HandleProtocol(Handles[I],&gEfiLoadedImageProtocolGuid,(VOID **)&L))||!L||!L->ImageBase||L->ImageSize!=SCM_IMAGE_BYTES||!ScmFilePath(L->FilePath))continue;
  UINT8 *B=L->ImageBase;UINTN Base=(UINTN)B,This=(UINTN)Scm,Fn=(UINTN)Scm->Sip;
  if(!((This==Base+0xe0e8&&Fn==Base+0x185c)||(This==Base+0xe140&&Fn==Base+0x3f94)))continue;
  R->MethodRva=(UINT32)(Fn-Base);R->ImageBytes=(UINT32)L->ImageSize;
  R->ImageCodeType=(UINT32)L->ImageCodeType;R->ImageDataType=(UINT32)L->ImageDataType;
  if(L->ImageCodeType!=EfiBootServicesCode||L->ImageDataType!=EfiBootServicesData||B[0]!='M'||B[1]!='Z')continue;
  UINT32 Pe=U32(B+0x3c);if(Pe>0x400||U32(B+Pe)!=0x00004550||B[Pe+4]!=0x64||B[Pe+5]!=0xaa)continue;
  if(B[Pe+24]!=0x0b||B[Pe+25]!=2||U32(B+Pe+24+16)!=0x1000||U32(B+Pe+24+56)!=SCM_IMAGE_BYTES||B[Pe+24+68]!=11||B[Pe+24+69]!=0)continue;
  CopyMem(Text,B+SCM_TEXT_RVA,SCM_TEXT_BYTES);
  for(UINTN J=0;J<sizeof(ScmTextRelocations)/sizeof(ScmTextRelocations[0]);J++){
   UINT32 Off=ScmTextRelocations[J];UINT64 V=U64((UINT8 *)Text+Off)-(UINT64)Base;
   CopyMem((UINT8 *)Text+Off,&V,sizeof(V));
  }
  OpenShaAll(Text,SCM_TEXT_BYTES,R->NormalizedTextSha256);
  if(CompareMem(R->NormalizedTextSha256,ScmTextHash,32)||U64(B+0xe5a8)!=(UINT64)(UINTN)gBS)continue;
  Matches++;
 }
 gBS->FreePool(Text);gBS->FreePool(Handles);
 return Matches==1?EFI_SUCCESS:EFI_UNSUPPORTED;
}
EFI_STATUS EFIAPI QueryEntry(EFI_HANDLE Image,EFI_SYSTEM_TABLE *System){
 (VOID)Image;(VOID)System;
 if(Attempted)return EFI_ALREADY_STARTED;Attempted=TRUE;
 EFI_ACPI_TABLE_PROTOCOL *Acpi=NULL;EFI_ACPI_SDT_PROTOCOL *Sdt=NULL;SCM_PROTOCOL *Scm=NULL;
 EFI_STATUS St;UINTN Key=0;REPORT R;UINT64 Args[10],Results[4];
 ZeroMem(&R,sizeof(R));ZeroMem(Args,sizeof(Args));ZeroMem(Results,sizeof(Results));
 St=gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid,NULL,(VOID **)&Acpi);if(EFI_ERROR(St))return St;
 St=gBS->LocateProtocol(&gEfiAcpiSdtProtocolGuid,NULL,(VOID **)&Sdt);if(EFI_ERROR(St))return St;
 BOOLEAN Ended=FALSE;
 for(UINTN I=0;I<256;I++){
  EFI_ACPI_SDT_HEADER *T=NULL;EFI_ACPI_TABLE_VERSION V;UINTN K;
  St=Sdt->GetAcpiTable(I,&T,&V,&K);
  if(St==EFI_NOT_FOUND){Ended=TRUE;break;}
  if(EFI_ERROR(St)||!T)return EFI_COMPROMISED_DATA;
  if(T->Signature==QUERY_SIGNATURE)return EFI_ALREADY_STARTED;
 }
 if(!Ended)return EFI_COMPROMISED_DATA;
 R.Header.Signature=QUERY_SIGNATURE;R.Header.Length=sizeof(R);R.Header.Revision=1;
 CopyMem(R.Header.OemId,"OPEN  ",6);CopyMem(&R.Header.OemTableId,"SCMQUERY",8);
 R.Header.OemRevision=1245;R.Header.CreatorId=SIGNATURE_32('O','P','E','N');R.Header.CreatorRevision=1;
 R.Version=1;R.IdentityStatus=(UINT64)EFI_NOT_STARTED;R.CallStatus=(UINT64)EFI_NOT_STARTED;
 R.SmcId=0x02000601;R.ParamId=1;Args[0]=0x02000c1b;CopyMem(R.Arguments,Args,sizeof(Args));
 R.Flags|=F_LOCATE_ATTEMPT;
 St=gBS->LocateProtocol(&gOpenG1245ScmProtocolGuid,NULL,(VOID **)&Scm);R.LocateStatus=(UINT64)St;
 if(!EFI_ERROR(St)&&Scm){
  R.Flags|=F_LOCATE_OK;St=Qualify(Scm,&R);R.IdentityStatus=(UINT64)St;
  if(!EFI_ERROR(St)){
   R.Flags|=F_IDENTITY_OK|F_CALL_ATTEMPT;
   /* Call selected original method/This exactly once; no direct SMC or retry. */
   St=Scm->Sip(Scm,R.SmcId,R.ParamId,Args,Results);CopyMem(R.Results,Results,sizeof(Results));
   R.CallStatus=(UINT64)St;R.Flags|=F_CALL_RETURNED;
   if(St==EFI_SUCCESS&&R.Results[0]==1){R.Flags|=F_COMPLETION_OK;if(R.Results[1]!=0)R.Flags|=F_AVAILABLE;}
  }
 }
 /* Publication success is not availability or a successful secure call. */
 R.Header.Checksum=(UINT8)(0-Sum(&R,sizeof(R)));
 return Acpi->InstallAcpiTable(Acpi,&R,sizeof(R),&Key);
}
