/** @file
  G139 fixed in-window memory inventory. No PIL API, disk IO, target data
  access, mapping change or DSP request. The existing mode16 path publishes
  one OEM ACPI report and returns to the normal Windows boot path.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Uefi.h>
#include <IndustryStandard/Acpi.h>
#include <Protocol/AcpiTable.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include "OpenPilFootprint.h"
#include "OpenPilCpuInventory.h"
#define REPORT_BYTES (32U*1024U)
#define TRAILER_BYTES 256U
STATIC CHAR8 *mText;
STATIC UINTN mTextUsed;
STATIC BOOLEAN mTruncated,mRan;

STATIC VOID Report(CONST CHAR8 *Format,...)
{
 VA_LIST Args;UINTN N,Room;
 if(mText==NULL || mTruncated)return;
 Room=REPORT_BYTES-TRAILER_BYTES-mTextUsed;
 if(Room<2){mTruncated=TRUE;return;}
 VA_START(Args,Format);
 N=AsciiVSPrint(mText+mTextUsed,Room,Format,Args);
 VA_END(Args);
 mTextUsed+=N;
 if(N>=Room-1)mTruncated=TRUE;
}

STATIC EFI_STATUS PublishReport(VOID)
{
 EFI_ACPI_TABLE_PROTOCOL *Acpi=NULL;
 EFI_ACPI_DESCRIPTION_HEADER *Header;
 EFI_STATUS Status;UINTN Key=0,Bytes,I;UINT8 Sum=0;
 Status=gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid,NULL,(VOID **)&Acpi);
 if(Status!=EFI_SUCCESS || Acpi==NULL)return Status==EFI_SUCCESS?EFI_NOT_FOUND:Status;
 Bytes=sizeof(*Header)+mTextUsed;Header=AllocateZeroPool(Bytes);
 if(Header==NULL)return EFI_OUT_OF_RESOURCES;
 Header->Signature=SIGNATURE_32('O','P','I','L');Header->Length=(UINT32)Bytes;Header->Revision=1;
 CopyMem(Header->OemId,"OPEN  ",6);CopyMem(&Header->OemTableId,"G139PIL1",8);
 Header->OemRevision=139;Header->CreatorId=SIGNATURE_32('O','P','E','N');Header->CreatorRevision=1;
 CopyMem(Header+1,mText,mTextUsed);
 for(I=0;I<Bytes;I++)Sum=(UINT8)(Sum+((UINT8 *)Header)[I]);Header->Checksum=(UINT8)(0-Sum);
 Status=Acpi->InstallAcpiTable(Acpi,Header,Bytes,&Key);
 FreePool(Header);return Status;
}

EFI_STATUS OpenRunPilInventory(VOID)
{
 P139_CPU_INVENTORY *Cpu;P139_U64 El;EFI_STATUS Status;UINTN N;
 if(mRan)return EFI_ALREADY_STARTED;
 mRan=TRUE;mText=AllocateZeroPool(REPORT_BYTES);
 if(mText==NULL)return EFI_OUT_OF_RESOURCES;
 Report("OPEN-PIL-INVENTORY G139 version=1\npolicy_start=8A800000 policy_end=A3280000 source=G138-shipped-devcfg\n");
 OpenAppendPilFootprint(Report);
 Cpu=AllocateZeroPool(sizeof(*Cpu));
 if(Cpu==NULL)Report("P139_cpu allocation_failed=1 queries=0\n");
 else{
  El=OpenDspCurrentEl();OpenCollectPilCpu(Cpu,OpenDspAt,&El,El);
  Report("P139_cpu el=%lu complete=%u refusal=%u pages=%lu queries=%lu\n",Cpu->El,Cpu->Complete,Cpu->Refusal,Cpu->Pages,Cpu->Queries);
  Report("P139_cpu_faults reads=%lu writes=%lu read_aliases=%lu write_aliases=%lu tag_differences=%lu\n",Cpu->ReadFaults,Cpu->WriteFaults,Cpu->ReadAliases,Cpu->WriteAliases,Cpu->TagDifferences);
  Report("P139_cpu_first_fault address=%lx read_par=%lx write_par=%lx\n",Cpu->FirstFault,Cpu->FaultReadPar,Cpu->FaultWritePar);
  Report("P139_cpu_first_alias address=%lx read_par=%lx write_par=%lx\n",Cpu->FirstAlias,Cpu->AliasReadPar,Cpu->AliasWritePar);
  Report("P139_cpu_first_tag_difference address=%lx read_par=%lx write_par=%lx\n",Cpu->FirstTagDifference,Cpu->TagReadPar,Cpu->TagWritePar);
  for(N=0;N<256;N++)if(Cpu->ReadTags[N]||Cpu->WriteTags[N])
   Report("P139_cpu_tag value=%02x reads=%lu writes=%lu\n",(UINT32)N,Cpu->ReadTags[N],Cpu->WriteTags[N]);
  FreePool(Cpu);
 }
 /* Keep a trailer budget even when the observation text was clipped. */
 mTextUsed+=AsciiSPrint(mText+mTextUsed,REPORT_BYTES-mTextUsed,
   "\nG139_FINAL truncated=%u PAS_requests=0 target_data_accesses=0 mappings_changed=0 ownership=not_proved\n",mTruncated);
 Status=PublishReport();FreePool(mText);mText=NULL;return Status;
}
