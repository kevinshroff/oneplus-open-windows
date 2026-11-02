/* SPDX-License-Identifier: MIT
 * Paired ACPI transaction before Windows consumes tables. PCI root LAST.
 * No raw XSDT edits, duplicate MCFG or runtime services. Reset-only prototype.
 */
#include <Uefi.h>
#include <Protocol/AcpiTable.h>
#include <Protocol/AcpiSystemDescriptionTable.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include "G401Publish.h"
#include "G401ExpectedMcfg.h"
#include "WIFI401Aml.h"
typedef struct{UINT8*Old;UINTN OldN,OldKey;UINT8*New;UINTN NewN,NewKey;} ITEM;
static ITEM mT[3]; /* APIC, IORT, MCFG */
static EFI_ACPI_TABLE_PROTOCOL*mTables;
static BOOLEAN mStarted;
static void FreeItems(void){for(UINTN I=0;I<3;I++){if(mT[I].Old)FreePool(mT[I].Old);if(mT[I].New)FreePool(mT[I].New);ZeroMem(&mT[I],sizeof(mT[I]));}}
EFI_STATUS G401PreparePublication(G401_PUBLICATION_REPORT*R){
 if(!R||mStarted)return EFI_NOT_READY;mStarted=TRUE;R->Stage=1;
 EFI_ACPI_SDT_PROTOCOL*Sdt=0;
 EFI_STATUS E=gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid,0,(VOID**)&mTables);if(EFI_ERROR(E))goto Bad;
 E=gBS->LocateProtocol(&gEfiAcpiSdtProtocolGuid,0,(VOID**)&Sdt);if(EFI_ERROR(E))goto Bad;
 UINTN Found[3]={0};BOOLEAN End=FALSE;
 for(UINTN I=0;I<256;I++){
  EFI_ACPI_SDT_HEADER*T=0;EFI_ACPI_TABLE_VERSION V=0;UINTN Key=0;
  E=Sdt->GetAcpiTable(I,&T,&V,&Key);
  if(E==EFI_NOT_FOUND){End=TRUE;break;}if(EFI_ERROR(E))goto Bad;
  if(!T)continue;UINTN At=3;
  if(T->Signature==SIGNATURE_32('A','P','I','C'))At=0;
  if(T->Signature==SIGNATURE_32('I','O','R','T'))At=1;
  if(T->Signature==SIGNATURE_32('M','C','F','G'))At=2;
  if(At==3)continue;
  if(++Found[At]!=1||T->Length<36||T->Length>4096){E=EFI_UNSUPPORTED;goto Bad;}
  mT[At].OldN=T->Length;mT[At].OldKey=Key;mT[At].Old=AllocateCopyPool(T->Length,T);
  if(!mT[At].Old){E=EFI_OUT_OF_RESOURCES;goto Bad;}
 }
 if(!End||Found[0]!=1||Found[1]!=1||Found[2]!=1){E=EFI_UNSUPPORTED;goto Bad;}
 if(mT[2].OldN!=sizeof(G401ExpectedMcfg)||CompareMem(mT[2].Old,G401ExpectedMcfg,sizeof(G401ExpectedMcfg))){E=EFI_UNSUPPORTED;goto Bad;}
 mT[0].NewN=G403_APIC_BYTES;mT[1].NewN=G403_IORT_BYTES;mT[2].NewN=mT[2].OldN;
 for(UINTN I=0;I<3;I++){mT[I].New=AllocatePool(mT[I].NewN);if(!mT[I].New){E=EFI_OUT_OF_RESOURCES;goto Bad;}}
 if(G403BuildTables(mT[0].Old,mT[0].OldN,mT[1].Old,mT[1].OldN,
  mT[0].New,mT[0].NewN,mT[1].New,mT[1].NewN)){E=EFI_UNSUPPORTED;goto Bad;}
 R->Prepared=1;R->Stage=2;R->Status=EFI_SUCCESS;return EFI_SUCCESS;
Bad:R->Status=E;FreeItems();return E;
}
EFI_STATUS G401PublishRoot(const G401_REPORT*T,BOOLEAN AllowAwakePrototype,
 G403_GATE Gate,void*Context,G401_PUBLICATION_REPORT*R){
 if(!T||!R||!Gate||!AllowAwakePrototype||!R->Prepared||R->Attempted||!mTables||
    T->Stage!=6||T->FirstError||!T->SeparationValid||!T->MemValid||!T->RootForwardingValid||(T->CommandAfter&4))return EFI_NOT_READY;
 if(G401BuildMcfg(T,mT[2].Old,mT[2].OldN,mT[2].New,mT[2].NewN))return EFI_UNSUPPORTED;
 if(Gate(Context))return EFI_NOT_READY;
 R->Attempted=1;R->Stage=3;EFI_STATUS E=EFI_SUCCESS;
 for(UINTN I=0;I<3;I++){
  E=mTables->UninstallAcpiTable(mTables,mT[I].OldKey);if(EFI_ERROR(E))goto Rollback;
  R->RemovedMask|=1U<<I;
  E=mTables->InstallAcpiTable(mTables,mT[I].New,mT[I].NewN,&mT[I].NewKey);if(EFI_ERROR(E))goto Rollback;
  R->InstalledMask|=1U<<I;
 }
 R->Stage=4;UINTN Key=0;
 E=mTables->InstallAcpiTable(mTables,(VOID*)G401Ssdt,sizeof(G401Ssdt),&Key);
 if(EFI_ERROR(E))goto Rollback;
 R->RootPublished=1;R->Stage=5;R->Status=EFI_SUCCESS;FreeItems();return EFI_SUCCESS;
Rollback:
 R->Status=E;R->RollbackAttempted=1;
 for(UINTN N=3;N;N--){UINTN I=N-1;EFI_STATUS X;
  if(R->InstalledMask&(1U<<I)){
   X=mTables->UninstallAcpiTable(mTables,mT[I].NewKey);
   if(EFI_ERROR(X)){R->RollbackFailed|=1U<<I;R->RollbackStatus=X;continue;}
   R->InstalledMask&=~(1U<<I);
  }
  if(R->RemovedMask&(1U<<I)){
   UINTN Restore=0;X=mTables->InstallAcpiTable(mTables,mT[I].Old,mT[I].OldN,&Restore);
   if(EFI_ERROR(X)){R->RollbackFailed|=1U<<I;R->RollbackStatus=X;}
   else R->RemovedMask&=~(1U<<I);
  }
 }
 FreeItems();return R->RollbackFailed?EFI_COMPROMISED_DATA:E;
}
