/** @file
  G80 exact-sector guarded userdata-type change and independent undo image.
  Only four fixed GPT sectors may be written. No partition/filesystem resizing.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include "OpenG80GptTypeMigration.h"
#include "OpenG80GoldenData.h"
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>

STATIC BOOLEAN mGptTypeBootAllowed = FALSE;

BOOLEAN OpenG80GptTypeAllowsBoot (VOID) { return mGptTypeBootAllowed; }

STATIC EFI_STATUS
ReadStable (IN EFI_BLOCK_IO_PROTOCOL *Io, IN UINT32 MediaId, IN EFI_LBA Lba,
            IN UINT8 *Dma, OUT UINT8 *Dest)
{
  EFI_STATUS Status;
  SetMem (Dma, 4096, 0xa5);
  Status = Io->ReadBlocks (Io, MediaId, Lba, 4096, Dma);
  if (EFI_ERROR (Status)) { return Status; }
  CopyMem (Dest, Dma, 4096);
  SetMem (Dma, 4096, 0x5a);
  Status = Io->ReadBlocks (Io, MediaId, Lba, 4096, Dma);
  if (EFI_ERROR (Status)) { return Status; }
  return (CompareMem (Dest, Dma, 4096) == 0) ? EFI_SUCCESS : EFI_CRC_ERROR;
}

EFI_STATUS
OpenG80MakeCorrected (OUT UINT8 After[5][4096])
{
  STATIC CONST UINT8 EspType[16] = {
    0x28,0x73,0x2a,0xc1,0x1f,0xf8,0xd2,0x11,0xba,0x4b,0x00,0xa0,0xc9,0x3e,0xc9,0x3b
  };
  UINTN I;
  UINT32 Crc, HeaderCrc;
  EFI_STATUS Status;
  CopyMem (After, mGoldenGpt, sizeof (mGoldenGpt));
  CopyMem (After[2] + 1664, EspType, 16);
  CopyMem (After[4] + 1664, EspType, 16);
  Status = gBS->CalculateCrc32 (After[2], 4096, &Crc);
  if (EFI_ERROR (Status)) { return Status; }
  if (Crc != OPEN_GPT_AFTER_ARRAY_CRC) { return EFI_CRC_ERROR; }
  for (I = 1; I <= 3; I += 2) {
    CopyMem (After[I] + 88, &Crc, 4);
    ZeroMem (After[I] + 16, 4);
    Status = gBS->CalculateCrc32 (After[I], 92, &HeaderCrc);
    if (EFI_ERROR (Status)) { return Status; }
    if (HeaderCrc != ((I == 1) ? OPEN_GPT_AFTER_PRIMARY_CRC : OPEN_GPT_AFTER_BACKUP_CRC)) {
      return EFI_CRC_ERROR;
    }
    CopyMem (After[I] + 16, &HeaderCrc, 4);
  }
  return EFI_SUCCESS;
}

VOID
OpenRunG80GptTypeMigration (IN EFI_BLOCK_IO_PROTOCOL *Io,
  IN EFI_PARTITION_INFO_PROTOCOL *Info, IN UINT32 Mode,
  IN OPEN_GPT_TYPE_LOG WriteLog, OUT OPEN_GPT_TYPE_RESULT *R)
{
  UINTN Order[4] = { 4, 3, 2, 1 }; // Prefer backup first when primary is complete.
  EFI_STATUS Status;
  EFI_PHYSICAL_ADDRESS Allocation;
  UINTN Alignment, Pages, I, K;
  UINT32 MediaId;
  UINT8 *Dma, *Check;
  UINT8 (*Current)[4096], (*After)[4096];
  CONST UINT8 (*Desired)[4096];
  BOOLEAN Allocated, AllDesired;
  ZeroMem (R, sizeof (*R)); CopyMem (R->Magic, "OPG80TX", 8);
  R->Mode = Mode; R->State = 1; R->Status = EFI_INVALID_PARAMETER;
  mGptTypeBootAllowed = FALSE;
  Current = NULL; After = NULL; Check = NULL; Allocated = FALSE;
  Pages = 0; Allocation = 0;
  if (((Mode != 13) && (Mode != 14)) || (Io == NULL) || (Io->Media == NULL) ||
      !Io->Media->MediaPresent || Io->Media->LogicalPartition || Io->Media->ReadOnly ||
      (Io->Media->BlockSize != 4096) || (Io->Media->LastBlock != 0x7613bff) ||
      (Io->ReadBlocks == NULL) || (Io->WriteBlocks == NULL) || (Io->FlushBlocks == NULL) ||
      (Info == NULL) || (Info->Type != PARTITION_TYPE_GPT) ||
      (Info->Info.Gpt.StartingLBA != 0x2208) || (Info->Info.Gpt.EndingLBA != 0x442207) ||
      (CompareMem (&Info->Info.Gpt.UniquePartitionGUID, mGoldenGpt[2] + 656, 16) != 0)) {
    goto Done;
  }
  MediaId = Io->Media->MediaId;
  Alignment = MAX ((UINTN)Io->Media->IoAlign, EFI_PAGE_SIZE);
  if ((Alignment > 65536) || ((Alignment & (Alignment - 1)) != 0)) { goto Done; }
  Pages = EFI_SIZE_TO_PAGES (4096 + Alignment - 1);
  Allocation = MAX_UINT32;
  Status = gBS->AllocatePages (AllocateMaxAddress, EfiBootServicesData, Pages, &Allocation);
  R->Status = Status;
  if (EFI_ERROR (Status)) { goto Done; }
  Allocated = TRUE;
  Dma = (VOID *)(UINTN)ALIGN_VALUE (Allocation, Alignment);
  Current = AllocatePool (sizeof (mGoldenGpt));
  After = AllocatePool (sizeof (mGoldenGpt));
  Check = AllocatePool (4096);
  if ((Current == NULL) || (After == NULL) || (Check == NULL)) {
    R->Status = EFI_OUT_OF_RESOURCES; goto Done;
  }
  Status = OpenG80MakeCorrected (After);
  R->Status = Status;
  if (EFI_ERROR (Status)) { goto Done; }
  Desired = (Mode == 13) ? (CONST UINT8 (*)[4096])After : mGoldenGpt;
  AllDesired = TRUE;
  for (I = 0; I < 5; I++) {
    Status = ReadStable (Io, MediaId, mGoldenGptLba[I], Dma, Current[I]);
    R->Status = Status;
    if (EFI_ERROR (Status)) { goto Done; }
    if (CompareMem (Current[I], mGoldenGpt[I], 4096) == 0) { R->InitialPattern[I] = 1; }
    else if (CompareMem (Current[I], After[I], 4096) == 0) { R->InitialPattern[I] = 2; }
    else { R->Status = EFI_COMPROMISED_DATA; goto Done; }
    if (CompareMem (Current[I], Desired[I], 4096) != 0) { AllDesired = FALSE; }
  }
  // At least one header must match its array before any write is allowed.
  // An interrupted earlier pass may leave only the backup complete. Finish
  // the primary first in that case, preserving the complete backup throughout.
  if (R->InitialPattern[1] != R->InitialPattern[2]) {
    if (R->InitialPattern[3] != R->InitialPattern[4]) {
      R->Status = EFI_COMPROMISED_DATA; goto Done;
    }
    Order[0] = 2; Order[1] = 1; Order[2] = 4; Order[3] = 3;
  }
  if (AllDesired) { R->State = 2; R->Status = EFI_SUCCESS; goto Done; }
  for (I = 0; I < 4; I++) {
    K = Order[I];
    if (CompareMem (Current[K], Desired[K], 4096) == 0) { continue; }
    // Reject an intervening change before touching this exact sector.
    Status = ReadStable (Io, MediaId, mGoldenGptLba[K], Dma, Check);
    if (!EFI_ERROR (Status) && (CompareMem (Check, Current[K], 4096) != 0)) {
      Status = EFI_COMPROMISED_DATA;
    }
    R->Status = Status;
    if (EFI_ERROR (Status)) { goto Done; }
    CopyMem (Dma, Desired[K], 4096);
    R->WriteLba[I] = mGoldenGptLba[K]; R->WritesAttempted++;
    Status = Io->WriteBlocks (Io, MediaId, mGoldenGptLba[K], 4096, Dma);
    R->WriteStatus[I] = Status; R->Status = Status;
    if (EFI_ERROR (Status)) { goto Done; }
    Status = Io->FlushBlocks (Io);
    R->FlushStatus[I] = Status; R->Status = Status;
    if (EFI_ERROR (Status)) { goto Done; }
    Status = ReadStable (Io, MediaId, mGoldenGptLba[K], Dma, Check);
    if (!EFI_ERROR (Status) && (CompareMem (Check, Desired[K], 4096) != 0)) {
      Status = EFI_CRC_ERROR;
    }
    R->ReadbackStatus[I] = Status; R->Status = Status;
    if (EFI_ERROR (Status)) { goto Done; }
    R->WritesVerified++; CopyMem (Current[K], Desired[K], 4096);
  }
  for (I = 0; I < 5; I++) {
    Status = ReadStable (Io, MediaId, mGoldenGptLba[I], Dma, Check);
    if (!EFI_ERROR (Status) && (CompareMem (Check, Desired[I], 4096) != 0)) {
      Status = EFI_CRC_ERROR;
    }
    R->Status = Status;
    if (EFI_ERROR (Status)) { goto Done; }
  }
  R->State = 3; R->Status = EFI_SUCCESS;
Done:
  if (EFI_ERROR (R->Status) && (R->WritesAttempted != 0)) { R->State = 4; }
  mGptTypeBootAllowed = (R->State == 2) || (R->State == 3);
  WriteLog ("G80 GPT mode=%u state=%u status=%lx written=%u verified=%u\n",
            Mode, R->State, R->Status, R->WritesAttempted, R->WritesVerified);
  WriteLog ("GPT: exact-sector guards; complete-copy-safe order; flush and double readback.\n");
  WriteLog ("Only userdata type + CRCs; MBR/extents/IDs/names/other entries preserved.\n");
  if (!mGptTypeBootAllowed) { WriteLog ("GPT guard/failure: Windows held; use bootloader recovery.\n"); }
  if (Current != NULL) { FreePool (Current); }
  if (After != NULL) { FreePool (After); }
  if (Check != NULL) { FreePool (Check); }
  if (Allocated) { gBS->FreePages (Allocation, Pages); }
}
