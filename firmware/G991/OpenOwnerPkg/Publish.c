/* ACPI publication only; exact G182 source baseline, no prior GPU/MMU1 publisher.
 * No MMIO, clocks, rail, SMC, driver, tables/root activation or DMA calls. */
#include <Uefi.h>
#include <IndustryStandard/Acpi.h>
#include <Protocol/AcpiTable.h>
#include <Protocol/AcpiSystemDescriptionTable.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include "Mmu1.h"
#include "Gpu0.h"
#include "IortOriginal.h"
#include "IortLevel.h"
#pragma pack(push,1)
typedef struct{EFI_ACPI_DESCRIPTION_HEADER Header;UINT32 Version,Stage;UINT64 Status;UINT32 AttemptedMask,InstalledMask,Committed,RollbackFailed;UINT64 Key[3],OriginalKey;UINT32 GpuMemory,MmuMemory,MmuIrq,Ready,Hardware,Translation;}REPORT;
#pragma pack(pop)
STATIC_ASSERT(sizeof(REPORT)==124,"OGBT source ABI");
STATIC BOOLEAN Attempted;
STATIC UINT8 Sum(CONST VOID*p,UINTN n){CONST UINT8*b=p;UINT8 s=0;for(UINTN i=0;i<n;i++)s=(UINT8)(s+b[i]);return s;}
EFI_STATUS EFIAPI PublishEntry(EFI_HANDLE image,EFI_SYSTEM_TABLE*system){
 (VOID)image;(VOID)system;if(Attempted)return EFI_ALREADY_STARTED;Attempted=TRUE;
 EFI_ACPI_TABLE_PROTOCOL*a=NULL;EFI_ACPI_SDT_PROTOCOL*s=NULL;EFI_STATUS st;UINTN reportKey=0;REPORT r;ZeroMem(&r,sizeof(r));r.Header.Signature=SIGNATURE_32('O','G','B','T');r.Header.Length=sizeof(r);r.Header.Revision=1;CopyMem(r.Header.OemId,"OPEN  ",6);CopyMem(&r.Header.OemTableId,"OWNERTBL",8);r.Header.OemRevision=1;r.Header.CreatorId=SIGNATURE_32('O','P','E','N');r.Header.CreatorRevision=1;r.Version=1;r.Stage=1;r.GpuMemory=5;r.MmuMemory=6;r.MmuIrq=3;
 st=gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid,NULL,(VOID**)&a);if(EFI_ERROR(st))return st;st=gBS->LocateProtocol(&gEfiAcpiSdtProtocolGuid,NULL,(VOID**)&s);if(EFI_ERROR(st))goto report;
 if(sizeof(mIortOriginal)!=3835||sizeof(mIortLevel)!=3835||Sum(mIortOriginal,sizeof(mIortOriginal))||Sum(mIortLevel,sizeof(mIortLevel))||Sum(mMmu1,sizeof(mMmu1))||Sum(mGpu0,sizeof(mGpu0))){st=EFI_COMPROMISED_DATA;goto report;}
 UINTN original=0,matches=0;BOOLEAN ended=FALSE;
 for(UINTN i=0;i<256;i++){EFI_ACPI_SDT_HEADER*t=NULL;EFI_ACPI_TABLE_VERSION version;UINTN key=0;st=s->GetAcpiTable(i,&t,&version,&key);if(st==EFI_NOT_FOUND){ended=TRUE;break;}if(EFI_ERROR(st)||!t){st=EFI_COMPROMISED_DATA;goto report;}
  if(t->Signature==SIGNATURE_32('I','O','R','T')){if(t->Length!=sizeof(mIortOriginal)||CompareMem(t,mIortOriginal,sizeof(mIortOriginal))){st=EFI_UNSUPPORTED;goto report;}original=key;matches++;}
  if(t->Signature==SIGNATURE_32('S','S','D','T')&&(!CompareMem(&t->OemTableId,"OMMUGMU ",8)||!CompareMem(&t->OemTableId,"GPUSPLIT",8))){st=EFI_ALREADY_STARTED;goto report;}
 }
 if(!ended||matches!=1){st=EFI_NOT_FOUND;goto report;}r.OriginalKey=original;r.Stage=2;
 CONST UINT8*data[3]={mIortLevel,mMmu1,mGpu0};CONST UINTN bytes[3]={sizeof(mIortLevel),sizeof(mMmu1),sizeof(mGpu0)};
 /* Keep the exact original table published until all replacements exist.
  * OS has not booted. The old key is removed only at complete commit. */
 for(UINTN i=0;i<3;i++){UINTN key=0;r.AttemptedMask|=1u<<i;st=a->InstallAcpiTable(a,(VOID*)data[i],bytes[i],&key);if(EFI_ERROR(st))goto rollback;r.Key[i]=key;r.InstalledMask|=1u<<i;}
 st=a->UninstallAcpiTable(a,original);if(EFI_ERROR(st))goto rollback;r.Committed=1;r.Stage=3;goto report;
rollback:
 /* Revert only known new table keys. Preserve original on any failed commit;
  * a failed uninstall is reported and never called coherent/ready. */
 for(UINTN j=3;j>0;j--)if(r.InstalledMask&(1u<<(j-1))){EFI_STATUS x=a->UninstallAcpiTable(a,(UINTN)r.Key[j-1]);if(EFI_ERROR(x))r.RollbackFailed|=1u<<(j-1);else r.InstalledMask&=~(1u<<(j-1));}
report:
 r.Status=(UINT64)st;r.Header.Checksum=(UINT8)(0-Sum(&r,sizeof(r)));return a->InstallAcpiTable(a,&r,sizeof(r),&reportKey);
}
