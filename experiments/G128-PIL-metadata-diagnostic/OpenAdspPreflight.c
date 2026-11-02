/** @file
  G119 finite ADSP file/reservation preflight. No PIL request, SCM call or MMIO.
  The source is selected by GPT identity and parent GPT hashes. File access uses
  a separate read-only BlockIO facade. The result is copied to an OEM ACPI table
  so Windows can retrieve it without a disk log or a physical recording.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Uefi.h>
#include <PiDxe.h>
#include <IndustryStandard/Acpi.h>
#include <Protocol/AcpiTable.h>
#include <Protocol/BlockIo.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/FileInfo.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DevicePathLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PlatformMemoryMapLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include "ReadOnlyBlockIo.h"
#include "OpenSha256.h"
#include "OpenPilMetadataProbe.h"
#ifndef OPEN_ADSP_BINDINGS
#define OPEN_ADSP_BINDINGS "OpenAdspInputs.h"
#endif
#include OPEN_ADSP_BINDINGS

#define SOURCE_BYTES 314572800ULL
#define SOURCE_DISK_BYTES 4043309056ULL
#define SOURCE_START 4614ULL
#define SOURCE_END 81413ULL
#define BUFFER_BYTES 65536U
#define READ_LIMIT (128ULL * 1024 * 1024)
#define REPORT_BYTES (24 * 1024)
#define ADSP_START 0x9E980000ULL // Include the 512 KiB DTB preimage.
#define ADSP_END 0xA3280000ULL

STATIC EFI_GUID mRecordGuid = {0xfe2555be,0xd716,0x4686,{0xb9,0xd0,0x79,0xdb,0x59,0x21,0xb7,0x0d}};
STATIC EFI_GUID mTypeGuid = {0x6848de61,0xeb61,0x4def,{0x9a,0x8e,0x38,0x17,0xcb,0xeb,0x8f,0x1c}};
STATIC EFI_GUID mFacadeGuid = {0xba92c6b8,0x88ca,0x4cea,{0x97,0xe1,0x57,0xe8,0x3b,0x7b,0x5b,0x19}};
STATIC EFI_GUID mPilGuid = {0x1f4f1da3,0x4d8d,0x4894,{0xba,0x2a,0x13,0xd3,0x20,0x7f,0x97,0x39}};

typedef struct {
  OPEN_RO_VOLUME Ro; // First: ReadOnlyBlockIo casts its interface to this prefix.
  EFI_BLOCK_READ ForwardRead;
  UINT64 RequestedBytes;
  UINT8 Record[128];
  EFI_GUID Type;
  EFI_DEVICE_PATH_PROTOCOL *Path;
  EFI_HANDLE Handle;
} OPEN_ADSP_VOLUME;

STATIC CHAR8 *mText;
STATIC UINTN mTextUsed;
STATIC BOOLEAN mTextTruncated;
STATIC BOOLEAN mRan;

STATIC VOID
Report (CONST CHAR8 *Format, ...)
{
  VA_LIST Args;
  UINTN N;
  if (mText == NULL || mTextUsed >= REPORT_BYTES - 2) { mTextTruncated = TRUE; return; }
  VA_START (Args, Format);
  N = AsciiVSPrint (mText + mTextUsed, REPORT_BYTES - mTextUsed, Format, Args);
  VA_END (Args);
  mTextUsed += N;
  if (mTextUsed >= REPORT_BYTES - 2) { mTextTruncated = TRUE; }
}

STATIC UINT64 Read64 (CONST VOID *P) { UINT64 V; CopyMem (&V, P, 8); return V; }
STATIC UINT32 Read32 (CONST VOID *P) { UINT32 V; CopyMem (&V, P, 4); return V; }

STATIC BOOLEAN
LabelIs (CONST UINT8 *Record, CONST CHAR8 *Name)
{
  UINTN I;
  UINT16 C;
  for (I = 0; I < 36; I++) {
    CopyMem (&C, Record + 56 + I * 2, 2);
    if (C >= 'A' && C <= 'Z') { C += 'a' - 'A'; }
    if (C != (UINT8)Name[I]) { return FALSE; }
    if (C == 0) { return TRUE; }
  }
  return FALSE;
}

STATIC EFI_STATUS EFIAPI
BudgetRead (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId, EFI_LBA Lba, UINTN Size, VOID *Buffer)
{
  OPEN_ADSP_VOLUME *V = (VOID *)This;
  if (Size > READ_LIMIT - V->RequestedBytes) { return EFI_ABORTED; }
  V->RequestedBytes += Size;
  return V->ForwardRead (This, MediaId, Lba, Size, Buffer);
}

STATIC EFI_STATUS
RawRead (EFI_BLOCK_IO_PROTOCOL *Io, UINT64 Offset, UINTN Bytes, VOID *Scratch, VOID *Out)
{
  UINT64 First, End, Capacity;
  EFI_STATUS Status;
  EFI_BLOCK_IO_MEDIA *M = Io->Media;
  if (M == NULL || !M->MediaPresent || M->BlockSize != 4096 || M->LastBlock >= MAX_UINT64/4096) {
    return EFI_UNSUPPORTED;
  }
  Capacity = (M->LastBlock + 1) * 4096;
  if (Bytes == 0 || Offset > Capacity || Bytes > Capacity - Offset) { return EFI_INVALID_PARAMETER; }
  First = Offset & ~4095ULL;
  End = (Offset + Bytes + 4095) & ~4095ULL;
  if (End - First > BUFFER_BYTES) { return EFI_BAD_BUFFER_SIZE; }
  Status = Io->ReadBlocks (Io, M->MediaId, First/4096, (UINTN)(End-First), Scratch);
  if (!EFI_ERROR (Status)) { CopyMem (Out, (UINT8 *)Scratch + (UINTN)(Offset-First), Bytes); }
  return Status;
}

STATIC EFI_STATUS
CheckParent (EFI_BLOCK_IO_PROTOCOL *Io, VOID *Scratch, VOID *Check)
{
  EFI_STATUS Status;
  UINT8 Hash[32];
  UINT64 ArrayLba, Bytes;
  UINT32 Count, Stride;
  UINTN Pass;
  for (Pass = 0; Pass < 2; Pass++) {
    Status = RawRead (Io, 4096, 4096, Scratch, Check);
    if (EFI_ERROR (Status)) { return Status; }
    OpenShaAll (Check, 4096, Hash);
    if (CompareMem (Hash, mSourceHeaderHash, 32) != 0) { return EFI_COMPROMISED_DATA; }
    ArrayLba = Read64 ((UINT8 *)Check + 72);
    Count = Read32 ((UINT8 *)Check + 80);
    Stride = Read32 ((UINT8 *)Check + 84);
    Bytes = (UINT64)Count * Stride;
    if (Count == 0 || Stride < 128 || Bytes > BUFFER_BYTES || ArrayLba > MAX_UINT64/4096) {
      return EFI_COMPROMISED_DATA;
    }
    Status = RawRead (Io, ArrayLba*4096, (UINTN)Bytes, Scratch, Check);
    if (EFI_ERROR (Status)) { return Status; }
    OpenShaAll (Check, (UINTN)Bytes, Hash);
    if (CompareMem (Hash, mSourceArrayHash, 32) != 0) { return EFI_COMPROMISED_DATA; }
  }
  return EFI_SUCCESS;
}

STATIC BOOLEAN
IsParentPath (EFI_HANDLE Parent, EFI_HANDLE Child)
{
  EFI_DEVICE_PATH_PROTOCOL *P, *C;
  UINTN PN, CN;
  P = DevicePathFromHandle (Parent);
  C = DevicePathFromHandle (Child);
  if (P == NULL || C == NULL) { return FALSE; }
  PN = GetDevicePathSize (P);
  CN = GetDevicePathSize (C);
  return PN > END_DEVICE_PATH_LENGTH && PN <= 4096 && CN > PN && CN <= 4096 &&
         CompareMem (P, C, PN - END_DEVICE_PATH_LENGTH) == 0;
}

STATIC EFI_STATUS
SelectSource (EFI_HANDLE *Selected, EFI_BLOCK_IO_PROTOCOL **Source, VOID *Scratch, VOID *Check)
{
  EFI_HANDLE *Handles, Parent = NULL;
  EFI_BLOCK_IO_PROTOCOL *Io;
  UINT8 *Record;
  EFI_GUID *Type;
  UINTN Count, I, Roots = 0, Names = 0, Basic = 0;
  EFI_STATUS Status;
  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiBlockIoProtocolGuid, NULL, &Count, &Handles);
  if (EFI_ERROR (Status)) { return Status; }
  *Selected = NULL;
  *Source = NULL;
  for (I = 0; I < Count; I++) {
    Status = gBS->HandleProtocol (Handles[I], &gEfiBlockIoProtocolGuid, (VOID **)&Io);
    if (EFI_ERROR (Status) || Io == NULL || Io->Media == NULL) { continue; }
    if (!EFI_ERROR (gBS->HandleProtocol (Handles[I], &mTypeGuid, (VOID **)&Type)) &&
        Type != NULL && CompareGuid (Type, &mBasicDataGuid)) { Basic++; }
    if (!Io->Media->LogicalPartition && Io->Media->MediaPresent && Io->Media->BlockSize == 4096 &&
        Io->Media->LastBlock == SOURCE_DISK_BYTES/4096-1 && Io->ReadBlocks != NULL &&
        Io->Media->IoAlign <= BUFFER_BYTES &&
        (Io->Media->IoAlign <= 1 || (Io->Media->IoAlign & (Io->Media->IoAlign-1)) == 0)) {
      Status = CheckParent (Io, Scratch, Check);
      if (!EFI_ERROR (Status)) { Parent = Handles[I]; Roots++; }
    }
    Status = gBS->HandleProtocol (Handles[I], &mRecordGuid, (VOID **)&Record);
    if (EFI_ERROR (Status) || Record == NULL || !LabelIs (Record, "modem_a")) { continue; }
    Names++;
    if (CompareMem (Record, &mBasicDataGuid, 16) != 0 ||
        CompareMem (Record+16, &mSourcePartitionGuid, 16) != 0 ||
        Read64 (Record+32) != SOURCE_START || Read64 (Record+40) != SOURCE_END ||
        !Io->Media->LogicalPartition || !Io->Media->MediaPresent ||
        Io->Media->BlockSize != 4096 || Io->Media->LastBlock != SOURCE_BYTES/4096-1 ||
        Io->ReadBlocks == NULL || Io->Media->IoAlign > BUFFER_BYTES ||
        (Io->Media->IoAlign > 1 && (Io->Media->IoAlign & (Io->Media->IoAlign-1)) != 0)) { continue; }
    *Selected = Handles[I];
    *Source = Io;
  }
  Report ("inventory BlockIO=%u BasicData=%u modem_names=%u pinned_roots=%u\n", Count, Basic, Names, Roots);
  FreePool (Handles);
  if (Names != 1 || Roots != 1 || *Selected == NULL || !IsParentPath (Parent, *Selected)) {
    *Selected = NULL; *Source = NULL; return EFI_NOT_FOUND;
  }
  return EFI_SUCCESS;
}

STATIC EFI_STATUS
CheckMetadata (OPEN_ADSP_VOLUME *V, VOID *Scratch, VOID *Check)
{
  UINTN I;
  UINT8 Hash[32];
  EFI_STATUS Status;
  for (I = 0; I < ARRAY_SIZE (mAdspMetadata); I++) {
    Status = RawRead (&V->Ro.Io, mAdspMetadata[I].Offset, mAdspMetadata[I].Bytes, Scratch, Check);
    if (EFI_ERROR (Status)) { return Status; }
    OpenShaAll (Check, mAdspMetadata[I].Bytes, Hash);
    if (CompareMem (Hash, mAdspMetadata[I].Hash, 32) != 0) { return EFI_COMPROMISED_DATA; }
  }
  return EFI_SUCCESS;
}

STATIC EFI_STATUS
CheckFiles (EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs, VOID *Buffer)
{
  EFI_FILE_PROTOCOL *Root = NULL, *File = NULL;
  EFI_STATUS Status, CloseStatus;
  UINTN I, J, N, InfoSize;
  UINT64 Done;
  CHAR16 Path[64];
  union { UINT64 Alignment; UINT8 Data[512]; } InfoBuffer;
  UINT8 Hash[32];
  EFI_FILE_INFO *Info = (VOID *)InfoBuffer.Data;
  OPEN_SHA256 Sha;
  Status = Fs->OpenVolume (Fs, &Root);
  if (EFI_ERROR (Status) || Root == NULL) { return EFI_ERROR (Status) ? Status : EFI_COMPROMISED_DATA; }
  for (I = 0; I < ARRAY_SIZE (mAdspFiles); I++) {
    CopyMem (Path, L"\\image\\", 7 * sizeof (CHAR16));
    for (J = 0; J < 55 && mAdspFiles[I].Name[J] != 0; J++) { Path[7+J] = (UINT8)mAdspFiles[I].Name[J]; }
    if (J == 55) { Status = EFI_BAD_BUFFER_SIZE; break; }
    Path[7+J] = 0;
    Status = Root->Open (Root, &File, Path, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR (Status) || File == NULL) { Status = EFI_ERROR (Status) ? Status : EFI_COMPROMISED_DATA; break; }
    InfoSize = sizeof (InfoBuffer);
    Status = File->GetInfo (File, &gEfiFileInfoGuid, &InfoSize, Info);
    if (!EFI_ERROR (Status) && (InfoSize < SIZE_OF_EFI_FILE_INFO || InfoSize > sizeof (InfoBuffer) ||
        Info->Size < SIZE_OF_EFI_FILE_INFO || Info->Size > InfoSize ||
        Info->FileSize != mAdspFiles[I].Bytes || (Info->Attribute & EFI_FILE_DIRECTORY) != 0)) { Status = EFI_COMPROMISED_DATA; }
    OpenShaInit (&Sha);
    Done = 0;
    while (!EFI_ERROR (Status) && Done < mAdspFiles[I].Bytes) {
      N = (UINTN)MIN ((UINT64)BUFFER_BYTES, mAdspFiles[I].Bytes-Done);
      InfoSize = N;
      Status = File->Read (File, &N, Buffer);
      if (!EFI_ERROR (Status) && N != InfoSize) { Status = EFI_COMPROMISED_DATA; }
      if (!EFI_ERROR (Status)) { OpenShaUpdate (&Sha, Buffer, N); Done += N; }
    }
    if (!EFI_ERROR (Status)) {
      N = 1;
      Status = File->Read (File, &N, Buffer);
      if (!EFI_ERROR (Status) && N != 0) { Status = EFI_COMPROMISED_DATA; }
    }
    if (!EFI_ERROR (Status)) {
      OpenShaFinal (&Sha, Hash);
      if (CompareMem (Hash, mAdspFiles[I].Hash, 32) != 0) { Status = EFI_COMPROMISED_DATA; }
    }
    Report ("file %u %a bytes=%lu read=%lu status=%r\n", I, mAdspFiles[I].Name, mAdspFiles[I].Bytes, Done, Status);
    CloseStatus = File->Close (File); File = NULL;
    if (!EFI_ERROR (Status)) { Status = CloseStatus; }
    if (EFI_ERROR (Status)) { break; }
  }
  if (File != NULL) { File->Close (File); }
  CloseStatus = Root->Close (Root);
  if (!EFI_ERROR (Status)) { Status = CloseStatus; }
  Report ("files_completed=%u total=%u status=%r\n", I, ARRAY_SIZE (mAdspFiles), Status);
  return Status;
}

STATIC EFI_STATUS
CheckReservation (VOID)
{
  ARM_MEMORY_REGION_DESCRIPTOR_EX *Map;
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR *Gcd;
  EFI_MEMORY_DESCRIPTOR *Mem, *D;
  EFI_STATUS Status, Result = EFI_SUCCESS;
  UINTN I, Count, Found = 0, Size = 65536, Key, Stride;
  UINT32 Version;
  UINT64 Cursor, End;
  Map = GetPlatformMemoryMap ();
  for (I = 0; I < MAX_ARM_MEMORY_REGION_DESCRIPTOR_COUNT && Map[I].Length != 0; I++) {
    if (AsciiStrCmp (Map[I].Name, "PIL Reserved") == 0) {
      if (Map[I].Address != 0x8A800000ULL || Map[I].Length != 0x18A80000ULL ||
          Map[I].ResourceType != EFI_RESOURCE_MEMORY_RESERVED || Map[I].MemoryType != EfiReservedMemoryType ||
          Map[I].ResourceAttribute != EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE ||
          Map[I].ArmAttributes != ARM_MEMORY_REGION_ATTRIBUTE_UNCACHED_UNBUFFERED) { Result = EFI_COMPROMISED_DATA; }
      Found++;
    }
    if (AsciiStrCmp (Map[I].Name, "Display Demura") == 0) {
      if (Map[I].Address != ADSP_END || Map[I].Length != 0x02300000ULL || Map[I].MemoryType != EfiReservedMemoryType) { Result = EFI_COMPROMISED_DATA; }
      Found++;
    }
  }
  if (Found != 2) { Result = EFI_COMPROMISED_DATA; }
  Report ("compiled_reservation entries=%u status=%r\n", Found, Result);
  Status = gDS->GetMemorySpaceMap (&Count, &Gcd);
  if (EFI_ERROR (Status)) { return Status; }
  Cursor = ADSP_START;
  for (I = 0; I < Count; I++) {
    if (Gcd[I].BaseAddress > MAX_UINT64 - Gcd[I].Length) { Result = EFI_COMPROMISED_DATA; continue; }
    End = Gcd[I].BaseAddress + Gcd[I].Length;
    if (End <= ADSP_START || Gcd[I].BaseAddress >= ADSP_END) { continue; }
    Report ("gcd base=%lx bytes=%lx type=%u caps=%lx attr=%lx\n", Gcd[I].BaseAddress, Gcd[I].Length, Gcd[I].GcdMemoryType, Gcd[I].Capabilities, Gcd[I].Attributes);
    if (Gcd[I].BaseAddress > Cursor || Gcd[I].GcdMemoryType != EfiGcdMemoryTypeReserved) { Result = EFI_COMPROMISED_DATA; }
    if (End > Cursor) { Cursor = End; }
  }
  FreePool (Gcd);
  if (Cursor < ADSP_END) { Result = EFI_NOT_FOUND; }
  Mem = AllocatePool (Size);
  if (Mem == NULL) { return EFI_OUT_OF_RESOURCES; }
  Status = gBS->GetMemoryMap (&Size, Mem, &Key, &Stride, &Version);
  if (!EFI_ERROR (Status) && (Stride < sizeof (*Mem) || Size % Stride != 0)) { Status = EFI_COMPROMISED_DATA; }
  Cursor = ADSP_START;
  if (!EFI_ERROR (Status)) {
    for (I = 0; I < Size; I += Stride) {
      D = (VOID *)((UINT8 *)Mem + I);
      if (D->NumberOfPages > (MAX_UINT64-D->PhysicalStart)/4096) { Result = EFI_COMPROMISED_DATA; continue; }
      End = D->PhysicalStart + D->NumberOfPages * 4096;
      if (End <= ADSP_START || D->PhysicalStart >= ADSP_END) { continue; }
      Report ("efi base=%lx pages=%lx type=%u attr=%lx\n", D->PhysicalStart, D->NumberOfPages, D->Type, D->Attribute);
      if (D->PhysicalStart > Cursor || D->Type != EfiReservedMemoryType) { Result = EFI_COMPROMISED_DATA; }
      if (End > Cursor) { Cursor = End; }
    }
    if (Cursor < ADSP_END) { Result = EFI_NOT_FOUND; }
  } else { Result = Status; }
  FreePool (Mem);
  Report ("reservation status=%r hardware_display_ownership=not_tested\n", Result);
  return Result;
}

STATIC EFI_STATUS
PublishReport (VOID)
{
  EFI_ACPI_TABLE_PROTOCOL *Acpi;
  EFI_ACPI_DESCRIPTION_HEADER *Header;
  EFI_STATUS Status;
  UINTN Key, Bytes, I;
  UINT8 Sum = 0;
  Status = gBS->LocateProtocol (&gEfiAcpiTableProtocolGuid, NULL, (VOID **)&Acpi);
  if (EFI_ERROR (Status)) { return Status; }
  Bytes = sizeof (*Header) + mTextUsed;
  Header = AllocateZeroPool (Bytes);
  if (Header == NULL) { return EFI_OUT_OF_RESOURCES; }
  Header->Signature = SIGNATURE_32 ('O','A','P','F');
  Header->Length = (UINT32)Bytes;
  Header->Revision = 1;
  CopyMem (Header->OemId, "OPEN  ", 6);
  CopyMem (&Header->OemTableId, "G119PFLT", 8);
  Header->OemRevision = 119;
  Header->CreatorId = SIGNATURE_32 ('O','P','E','N');
  Header->CreatorRevision = 1;
  CopyMem (Header+1, mText, mTextUsed);
  for (I = 0; I < Bytes; I++) { Sum = (UINT8)(Sum + ((UINT8 *)Header)[I]); }
  Header->Checksum = (UINT8)(0-Sum);
  Status = Acpi->InstallAcpiTable (Acpi, Header, Bytes, &Key);
  FreePool (Header); // InstallAcpiTable owns its copy, not this allocation.
  return Status;
}

EFI_STATUS
OpenRunAdspPreflight (VOID)
{
  EFI_STATUS Status, FilesStatus = EFI_NOT_READY, MemoryStatus, Cleanup = EFI_SUCCESS;
  EFI_BLOCK_IO_PROTOCOL *Source;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
  EFI_HANDLE SourceHandle;
  OPEN_ADSP_VOLUME *V = NULL;
  VENDOR_DEVICE_PATH Node;
  VOID *Scratch = NULL, *Dma = NULL, *Check = NULL, *Pil = NULL;
  BOOLEAN Installed = FALSE, Connected = FALSE, Keep = FALSE, ProbeCalled = FALSE;
  UINTN I;
  if (mRan) { return EFI_ALREADY_STARTED; }
  mRan = TRUE;
  mText = AllocateZeroPool (REPORT_BYTES);
  if (mText == NULL) { return EFI_OUT_OF_RESOURCES; }
  Report ("OPEN-ADSP-PREFLIGHT G119 version=1\ninput_sha256=%a\nDSP_start=not_armed source_writes=blocked\n", OPEN_ADSP_INPUT_SHA256);
  MemoryStatus = CheckReservation ();
  Status = gBS->LocateProtocol (&mPilGuid, NULL, &Pil);
  Report ("PIL_protocol status=%r present=%u request_count=0\n", Status, Pil != NULL);
  Scratch = AllocateAlignedPages (EFI_SIZE_TO_PAGES (BUFFER_BYTES), BUFFER_BYTES);
  Dma = AllocateAlignedPages (EFI_SIZE_TO_PAGES (BUFFER_BYTES), BUFFER_BYTES);
  Check = AllocatePool (BUFFER_BYTES);
  V = AllocateZeroPool (sizeof (*V));
  if (Scratch == NULL || Dma == NULL || Check == NULL || V == NULL) { Status = EFI_OUT_OF_RESOURCES; goto Done; }
  Status = SelectSource (&SourceHandle, &Source, Scratch, Check);
  Report ("source_selection status=%r\n", Status);
  if (EFI_ERROR (Status)) { goto Done; }
  Status = OpenInitReadOnlyVolume (&V->Ro, Source, Dma, SOURCE_BYTES/4096);
  if (EFI_ERROR (Status)) { goto Done; }
  V->Ro.Media.LogicalPartition = TRUE;
  V->ForwardRead = V->Ro.Io.ReadBlocks;
  V->Ro.Io.ReadBlocks = BudgetRead;
  Status = CheckMetadata (V, Scratch, Check);
  Report ("metadata_before status=%r\n", Status);
  if (EFI_ERROR (Status)) { goto Done; }
  V->Type = mBasicDataGuid;
  CopyMem (V->Record, &V->Type, 16);
  CopyMem (V->Record+16, &mFacadeGuid, 16);
  { UINT64 Last = SOURCE_BYTES/4096-1, Attributes = LShiftU64 (1,60);
    CopyMem (V->Record+40, &Last, 8); CopyMem (V->Record+48, &Attributes, 8); }
  for (I = 0; I < 7; I++) { ((CHAR16 *)(VOID *)(V->Record+56))[I] = L"adsp_ro"[I]; }
  ZeroMem (&Node, sizeof (Node));
  Node.Header.Type = MEDIA_DEVICE_PATH;
  Node.Header.SubType = MEDIA_VENDOR_DP;
  SetDevicePathNodeLength (&Node.Header, sizeof (Node));
  Node.Guid = mFacadeGuid;
  V->Path = AppendDevicePathNode (DevicePathFromHandle (SourceHandle), &Node.Header);
  if (V->Path == NULL) { Status = EFI_OUT_OF_RESOURCES; goto Done; }
  Status = gBS->InstallMultipleProtocolInterfaces (&V->Handle,
    &gEfiDevicePathProtocolGuid, V->Path, &gEfiBlockIoProtocolGuid, &V->Ro.Io,
    &mTypeGuid, &V->Type, &mRecordGuid, V->Record, NULL);
  if (EFI_ERROR (Status)) { Keep = V->Handle != NULL; goto Done; }
  Installed = TRUE;
  Status = gBS->ConnectController (V->Handle, NULL, NULL, TRUE);
  Connected = TRUE; // A failed connect can still have attached child drivers.
  Report ("read_only_connect status=%r\n", Status);
  Status = gBS->HandleProtocol (V->Handle, &gEfiSimpleFileSystemProtocolGuid, (VOID **)&Fs);
  Report ("read_only_filesystem status=%r present=%u\n", Status, !EFI_ERROR (Status));
  if (!EFI_ERROR (Status)) { FilesStatus = CheckFiles (Fs, Check); }
  if (!EFI_ERROR (Status)) { Status = FilesStatus; }
  // The original metadata helper resolves adsp_ro synchronously. Keep the
  // verified read-only facade connected through this call and its cleanup.
  { EFI_STATUS ProbeStatus = OpenRunPilMetadataProbe (
      MemoryStatus == EFI_SUCCESS && Status == EFI_SUCCESS && FilesStatus == EFI_SUCCESS &&
      V->Ro.DeniedWrites == 0 && V->Ro.Failures == 0 &&
      V->RequestedBytes <= READ_LIMIT - 1024*1024);
    ProbeCalled = TRUE;
    Report ("G128_metadata_publication status=%r\n", ProbeStatus); }
  Cleanup = CheckMetadata (V, Scratch, Check);
  Report ("metadata_after status=%r\n", Cleanup);
  if (!EFI_ERROR (Status)) { Status = Cleanup; }
Done:
  if (!ProbeCalled) {
    EFI_STATUS ProbeStatus = OpenRunPilMetadataProbe (FALSE);
    Report ("G128_inspection_publication status=%r\n", ProbeStatus);
  }
  if (Connected) {
    Cleanup = gBS->DisconnectController (V->Handle, NULL, NULL);
    Report ("disconnect status=%r\n", Cleanup);
    if (EFI_ERROR (Cleanup)) { Keep = TRUE; }
  }
  if (Installed && !Keep) {
    Cleanup = gBS->UninstallMultipleProtocolInterfaces (V->Handle,
      &gEfiDevicePathProtocolGuid, V->Path, &gEfiBlockIoProtocolGuid, &V->Ro.Io,
      &mTypeGuid, &V->Type, &mRecordGuid, V->Record, NULL);
    Report ("uninstall status=%r\n", Cleanup);
    if (EFI_ERROR (Cleanup)) { Keep = TRUE; }
  }
  if (!EFI_ERROR (Status) && EFI_ERROR (Cleanup)) { Status = Cleanup; }
  if (V != NULL) {
    Report ("read_calls=%lu read_bytes=%lu requested_bytes=%lu denied_writes=%lu failures=%lu kept_facade=%u\n",
      V->Ro.ReadCalls, V->Ro.ReadBytes, V->RequestedBytes, V->Ro.DeniedWrites, V->Ro.Failures, Keep);
    if (V->Ro.DeniedWrites != 0 && !EFI_ERROR (Status)) { Status = EFI_WRITE_PROTECTED; }
    if (!Keep) { if (V->Path != NULL) { FreePool (V->Path); } FreePool (V); }
  }
  // If disconnect/uninstall could not remove all users, retain the facade and
  // its DMA buffer through ExitBootServices. Never free a live protocol context.
  if (!Keep && Dma != NULL) { FreeAlignedPages (Dma, EFI_SIZE_TO_PAGES (BUFFER_BYTES)); }
  if (Scratch != NULL) { FreeAlignedPages (Scratch, EFI_SIZE_TO_PAGES (BUFFER_BYTES)); }
  if (Check != NULL) { FreePool (Check); }
  Report ("FINAL file_status=%r memory_status=%r cleanup_status=%r truncated=%u\nDSP_start=not_armed request_count=0\n",
    Status, MemoryStatus, Cleanup, mTextTruncated);
  Status = PublishReport ();
  FreePool (mText); mText = NULL;
  return Status;
}
