/** G79: export only two bounded, read-only BlockIo facades over USB.
    This function never returns to Windows or the GPT migration path. */
#include <Uefi.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/PartitionInfo.h>
#include <Protocol/UsbFunctionIo.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include "ReadOnlyBlockIo.h"
#include "OpenScsiWriteProtect.h"
#include "OpenPinnedBlockIo.h"
#include "OpenG80GptTypeMigration.h"
#include "OpenG80GoldenData.h"
#include "OpenPinnedPlanIdentity.h"
#include <Library/DxeServicesLib.h>
#include <Library/PcdLib.h>
#include <Pi/PiFirmwareFile.h>

typedef struct _OPEN_MSD OPEN_MSD;
struct _OPEN_MSD {
  UINT32 Revision;
  EFI_STATUS (EFIAPI *Assign)(OPEN_MSD *, EFI_BLOCK_IO_PROTOCOL *, UINT32);
  EFI_STATUS (EFIAPI *MaxLun)(OPEN_MSD *, UINT8 *);
  EFI_STATUS (EFIAPI *Event)(OPEN_MSD *);
  EFI_STATUS (EFIAPI *Start)(OPEN_MSD *);
  EFI_STATUS (EFIAPI *Stop)(OPEN_MSD *);
  VOID *Speed, *Unmount, *Mount, *FindPartitions;
};
STATIC_ASSERT (OFFSET_OF (OPEN_MSD, Assign) == 8, "MSD ABI assign");
STATIC_ASSERT (OFFSET_OF (OPEN_MSD, Start) == 32, "MSD ABI start");
STATIC_ASSERT (sizeof (OPEN_MSD) == 80, "MSD ABI size");

STATIC EFI_GUID mMsdGuid = {0xc8591faf,0xdbcc,0x479e,{0x9e,0xf2,0xfd,0x08,0x5b,0xc3,0x7b,0xc7}};
STATIC EFI_GUID mMsdFile = {0x5af77f10,0x90df,0x4e7e,{0x83,0x25,0xa1,0x7e,0xc0,0x9d,0x54,0x43}};
STATIC EFI_GUID mUsbFile = {0x94f8a6a7,0xdc34,0x4101,{0x88,0xc1,0x99,0x17,0x9c,0xce,0xae,0x83}};
STATIC EFI_GUID mSuperGuid = {0x1c68511e,0x28af,0xa8c9,{0xdd,0x6f,0xe3,0x30,0x3d,0x56,0x8c,0x04}};
STATIC EFI_GUID mUserGuid = {0x5982c0bf,0xb83f,0x025d,{0x43,0x54,0x68,0x00,0x9b,0xa0,0xa5,0xd1}};
STATIC OPEN_RO_VOLUME mVolumes[2];
STATIC OPEN_PIN_VOLUME mPinned;
STATIC EFI_HANDLE mUserHandle;
STATIC EFI_PARTITION_INFO_PROTOCOL mSuperInfo;
STATIC EFI_BLOCK_IO_PROTOCOL *mRawDisk;
STATIC UINT8 *mPlan;
STATIC BOOLEAN mUndo, mCommitPending, mFinalActive, mSeenCommit, mUndoComplete;
STATIC UINT32 mCommitTag;
STATIC UINTN mCommitDelay, mFinalIndex;
STATIC OPEN_SHA256 mFinalSha;
STATIC EFI_BLOCK_IO_PROTOCOL *ExportedIo (UINTN I) { return I == 0 ? &mVolumes[0].Io : &mPinned.Ro.Io; }
STATIC BOOLEAN IsCommitRead (CONST UINT8 *C) {
 return C != NULL && CompareMem(C,"USBC",4)==0 && C[8]==0 && C[9]==0x10 && C[10]==0 && C[11]==0 &&
 C[12]==0x80 && C[13]==1 && C[14]==10 && C[15]==0x28 && C[16]==0 &&
 C[17]==0 && C[18]==0 && C[19]==0 && C[20]==0 && C[21]==31 && C[22]==0 && C[23]==1 && C[24]==0;
}

STATIC VOID
Halt (CONST CHAR16 *Reason, EFI_STATUS Status)
{
  Print (L"\nG80 STOP: %s: %r\nStorage updates held. No Windows boot follows.\n", Reason, Status);
  DEBUG ((DEBUG_ERROR, "G80 STOP %s %r\n", Reason, Status));
  for (;;) { gBS->Stall (100000); }
}

STATIC UINTN
FindDriverImage (CONST EFI_GUID *File, UINTN MinimumSize)
{
  EFI_HANDLE *Handles;
  EFI_LOADED_IMAGE_PROTOCOL *Image;
  EFI_DEVICE_PATH_PROTOCOL *Node;
  UINTN Count, I, Base = 0, Matches = 0;
  EFI_STATUS Status;
  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiLoadedImageProtocolGuid, NULL, &Count, &Handles);
  if (EFI_ERROR (Status)) { return 0; }
  for (I = 0; I < Count; I++) {
    Status = gBS->HandleProtocol (Handles[I], &gEfiLoadedImageProtocolGuid, (VOID **)&Image);
    if (EFI_ERROR (Status) || Image == NULL || Image->FilePath == NULL ||
        !IsDevicePathValid (Image->FilePath, 4096)) { continue; }
    for (Node = Image->FilePath; !IsDevicePathEnd (Node); Node = NextDevicePathNode (Node)) {
      if ((DevicePathType (Node) == MEDIA_DEVICE_PATH) &&
          (DevicePathSubType (Node) == MEDIA_PIWG_FW_FILE_DP) &&
          (DevicePathNodeLength (Node) == sizeof (MEDIA_FW_VOL_FILEPATH_DEVICE_PATH)) &&
          CompareGuid (&((MEDIA_FW_VOL_FILEPATH_DEVICE_PATH *)Node)->FvFileName, File)) {
        if (Image->ImageBase == NULL || Image->ImageSize < MinimumSize) { continue; }
        Base = (UINTN)Image->ImageBase; Matches++;
      }
    }
  }
  FreePool (Handles);
  return Matches == 1 ? Base : 0;
}

typedef EFI_STATUS (EFIAPI *OPEN_CONFIGURE_EX)(EFI_USBFN_IO_PROTOCOL *, VOID *, VOID *);
STATIC EFI_USBFN_IO_PROTOCOL *mRecoveryUsb;
STATIC UINTN mUsb2Configurations;
STATIC EFI_USBFN_IO_TRANSFER mOriginalTransfer;
STATIC UINT8 *mMsdInstance;
STATIC UINTN mProtectedSense[2];

STATIC EFI_STATUS EFIAPI
RecoveryTransfer (EFI_USBFN_IO_PROTOCOL *This, UINT8 EndpointIndex,
  EFI_USBFN_ENDPOINT_DIRECTION Direction, UINTN *Size, VOID *Buffer)
{
  UINT8 *Cbw;
  UINTN Capacity;
  INTN Protected;
  if (This != mRecoveryUsb || mOriginalTransfer == NULL || mMsdInstance == NULL) {
    return EFI_ACCESS_DENIED;
  }
  // REA: IssueXfer 0x3a84 forwards this buffer directly. The SCSI dispatcher
  // 0x3c20 uses CBW at instance+0x688 and data-IN buffer at +0x660. Restrict
  // edits to its exact four-byte MODE SENSE(6) header; all other USB traffic
  // passes unchanged. Underlying BlockIo writes still always refuse.
  if (EndpointIndex == 1 && Direction == EfiUsbEndpointDirectionDeviceTx &&
      Size != NULL && *Size == 4 && Buffer != NULL &&
      Buffer == *(VOID **)(mMsdInstance + 0x660)) {
    Cbw = *(UINT8 **)(mMsdInstance + 0x688);
    Capacity = *(UINTN *)(mMsdInstance + 0x690);
    if (Cbw == NULL || Capacity < 31 || Capacity > 65536) {
      Halt (L"SCSI command buffer bounds", EFI_COMPROMISED_DATA);
    }
    Protected = OpenProtectModeSense6 (Cbw, 31, Buffer, *Size);
    if (Protected < 0) { Halt (L"unexpected MODE SENSE response", EFI_COMPROMISED_DATA); }
    if (Protected == 1 && mProtectedSense[Cbw[13]]++ == 0) {
      Print (L"G79 SCSI write protection advertised: LUN %u\n", Cbw[13]);
    }
  }
  if (EndpointIndex == 1 && Direction == EfiUsbEndpointDirectionDeviceTx && Size != NULL && *Size == 4096 &&
      Buffer == *(VOID **)(mMsdInstance + 0x660) && !mUndoComplete) {
    UINT32 Tag;
    Cbw = *(UINT8 **)(mMsdInstance + 0x688);
    if (IsCommitRead(Cbw)) {
      CopyMem(&Tag,Cbw+4,4);
      if (!mSeenCommit || Tag != mCommitTag) { mCommitTag=Tag;mSeenCommit=TRUE;mCommitPending=TRUE;mCommitDelay=30000; }
    }
  }
  return mOriginalTransfer (This, EndpointIndex, Direction, Size, Buffer);
}

// REA on the exact UsbfnDwc3Dxe SHA256 6184f6e3...526c8d62 established:
// 0x2438 is legacy ConfigureEnableEndpoints; 0x2554 is Configure...Ex;
// instance+0xdd8 controls automatic SuperSpeed descriptor conversion. With
// that byte zero, the legacy method stores no SuperSpeed descriptor. Core
// initialization at 0x37e8 then selects DCFG speed 0 (USB High Speed).
// Only this temporary instance's RAM changes; no UEFI variable is written.
STATIC EFI_STATUS EFIAPI
ConfigureUsb2Only (EFI_USBFN_IO_PROTOCOL *This, VOID *DeviceInfo, VOID *IgnoredSsInfo)
{
  EFI_STATUS Status;
  UINT8 *Instance;
  if (This != mRecoveryUsb || DeviceInfo == NULL || IgnoredSsInfo == NULL ||
      mUsb2Configurations != 0) { return EFI_ACCESS_DENIED; }
  Instance = (UINT8 *)This - 8;
  if (*(UINT64 *)Instance != 0x66627375 || Instance[0xdd8] > 1) { return EFI_COMPROMISED_DATA; }
  Instance[0xdd8] = 0;
  Status = This->ConfigureEnableEndpoints (This, (EFI_USB_DEVICE_INFO *)DeviceInfo);
  if (EFI_ERROR (Status)) { return Status; }
  if (*(VOID **)(Instance + 0x1a8) != DeviceInfo ||
      *(VOID **)(Instance + 0x1b0) != NULL || Instance[0xdd8] != 0) {
    return EFI_COMPROMISED_DATA;
  }
  mUsb2Configurations++;
  return EFI_SUCCESS;
}

STATIC BOOLEAN
UsbAbiMatches (EFI_USBFN_IO_PROTOCOL *Usb, UINTN Base)
{
  if (Usb == NULL || Base == 0 || Usb->Revision != 0x10003 ||
      *(UINT64 *)((UINT8 *)Usb - 8) != 0x66627375) { return FALSE; }
  return (UINTN)Usb->ConfigureEnableEndpoints == Base + 0x2438 &&
    (UINTN)Usb->EventHandler == Base + 0x2e40 &&
    (UINTN)Usb->Transfer == Base + 0x3080 &&
    (UINTN)Usb->StartController == Base + 0x32c4 &&
    (UINTN)Usb->StopController == Base + 0x32cc &&
    *(UINTN *)((UINT8 *)Usb + 0x90) == Base + 0x2554;
}

STATIC BOOLEAN
MsdAbiMatches (OPEN_MSD *Msd, UINTN Base)
{
  UINTN I;
  STATIC CONST UINTN Offsets[9] = {0x1788,0x1740,0x18fc,0x1aa0,0x1bf8,0x1cf0,0x1d9c,0x1e04,0x1e6c};
  UINTN *Methods;
  if (Msd == NULL || Base == 0 || Msd->Revision != 0x10003) { return FALSE; }
  Methods = (UINTN *)((UINT8 *)Msd + 8);
  for (I = 0; I < ARRAY_SIZE (Offsets); I++) {
    if (Methods[I] != Base + Offsets[I]) { return FALSE; }
  }
  // These private offsets are reconstructed from this exact shipped binary.
  // Refuse a preconfigured instance rather than removing any existing LUNs.
  if (*(UINT64 *)((UINT8 *)Msd - 8) != 0x6d627375 ||
      *(UINT64 *)((UINT8 *)Msd + 0x50) != 0) { return FALSE; }
  for (I = 0; I < 16 * 24; I++) {
    if (*((UINT8 *)Msd + 0x58 + I) != 0) { return FALSE; }
  }
  return TRUE;
}

STATIC VOID
SelectVolumes (VOID)
{
  EFI_HANDLE *Handles;
  EFI_PARTITION_INFO_PROTOCOL *Info;
  EFI_BLOCK_IO_PROTOCOL *Io, *Selected[2] = {NULL, NULL};
  EFI_STATUS Status;
  EFI_PHYSICAL_ADDRESS Allocation;
  UINTN Count, I, J, Which, Align, Pages;
  UINT64 Blocks[2] = {0x440000, 0x40000}; // 17 GiB super; first 1 GiB userdata.
  UINT32 Crc[2];
  CHAR16 Name[37];
  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiPartitionInfoProtocolGuid, NULL, &Count, &Handles);
  if (EFI_ERROR (Status)) { Halt (L"partition inventory", Status); }
  for (I = 0; I < Count; I++) {
    Status = gBS->HandleProtocol (Handles[I], &gEfiPartitionInfoProtocolGuid, (VOID **)&Info);
    if (EFI_ERROR (Status) || Info->Type != PARTITION_TYPE_GPT) { continue; }
    CopyMem (Name, Info->Info.Gpt.PartitionName, 72); Name[36] = 0;
    if (CompareGuid (&Info->Info.Gpt.UniquePartitionGUID, &mSuperGuid) && StrCmp (Name, L"super") == 0 &&
        Info->Info.Gpt.StartingLBA == 0x2208 && Info->Info.Gpt.EndingLBA == 0x442207) { Which = 0; }
    else if (CompareGuid (&Info->Info.Gpt.UniquePartitionGUID, &mUserGuid) && StrCmp (Name, L"userdata") == 0 &&
        Info->Info.Gpt.StartingLBA == 0x4582ec && Info->Info.Gpt.EndingLBA == 0x7613bfa) { Which = 1; }
    else { continue; }
    if (Selected[Which] != NULL) { Halt (L"duplicate partition identity", EFI_COMPROMISED_DATA); }
    Status = gBS->HandleProtocol (Handles[I], &gEfiBlockIoProtocolGuid, (VOID **)&Io);
    if (EFI_ERROR (Status) || Io == NULL || Io->Media == NULL ||
        Io->Media->LastBlock != Info->Info.Gpt.EndingLBA - Info->Info.Gpt.StartingLBA) {
      Halt (L"partition BlockIo extent", EFI_COMPROMISED_DATA);
    }
    Selected[Which] = Io;
    if (Which == 1) { mUserHandle=Handles[I]; } else { mSuperInfo=*Info; }
  }
  FreePool (Handles);
  for (I = 0; I < 2; I++) {
    if (Selected[I] == NULL) { Halt (L"required partition not found", EFI_NOT_FOUND); }
    Io = Selected[I];
    Align = MAX ((UINTN)Io->Media->IoAlign, EFI_PAGE_SIZE);
    if (Align > OPEN_RO_CHUNK || (Align & (Align - 1)) != 0) { Halt (L"DMA alignment", EFI_UNSUPPORTED); }
    Pages = EFI_SIZE_TO_PAGES (OPEN_RO_CHUNK + Align - 1);
    Allocation = MAX_UINT32;
    Status = gBS->AllocatePages (AllocateMaxAddress, EfiBootServicesData, Pages, &Allocation);
    if (EFI_ERROR (Status)) { Halt (L"low DMA buffer", Status); }
    Status = OpenInitReadOnlyVolume (&mVolumes[I], Io, (VOID *)(UINTN)ALIGN_VALUE (Allocation, Align), Blocks[I]);
    if (EFI_ERROR (Status)) { Halt (L"read-only facade", Status); }
    for (J = 0; J < 2; J++) {
      Status = mVolumes[I].Io.ReadBlocks (&mVolumes[I].Io, mVolumes[I].Media.MediaId, 0, 4096, mVolumes[I].Bounce);
      if (EFI_ERROR (Status)) { Halt (L"first-sector read", Status); }
      gBS->CalculateCrc32 (mVolumes[I].Bounce, 4096, &Crc[J]);
    }
    if (Crc[0] != Crc[1]) { Halt (L"unstable first sector", EFI_CRC_ERROR); }
    if (I == 0 && CompareMem ((UINT8 *)mVolumes[I].Bounce + 3, "NTFS    ", 8) != 0) {
      Halt (L"super is not NTFS", EFI_COMPROMISED_DATA);
    }
    Print (L"LUN %u: %s, %lu bytes, READ ONLY, sector CRC32=%08x\n", I,
      I == 0 ? L"super" : L"userdata prefix", Blocks[I] * 4096, Crc[0]);
  }
}

STATIC UINT8 *LowBuffer (VOID) {
 EFI_PHYSICAL_ADDRESS A=MAX_UINT32;EFI_STATUS S;
 S=gBS->AllocatePages(AllocateMaxAddress,EfiBootServicesData,16,&A);
 if(EFI_ERROR(S)){Halt(L"64KiB low buffer",S);}return (VOID *)(UINTN)A;
}
STATIC VOID LoadPinnedPlan (VOID) {
 EFI_GUID Guid={0x2e037fd2,0x644f,0x4b03,{0xb7,0x7a,0xbf,0xb9,0x33,0x0d,0x70,0xd8}};
 UINTN N=0;VOID *B=NULL;UINT8 H[32];EFI_STATUS S;
 S=GetSectionFromAnyFv(&Guid,EFI_SECTION_RAW,0,&B,&N);
 if(EFI_ERROR(S)||B==NULL||N!=256+OPEN_PIN_COUNT*64){Halt(L"pinned plan section",EFI_COMPROMISED_DATA);}
 OpenShaAll(B,N,H);if(CompareMem(H,mPinnedPlanHash,32)!=0){Halt(L"pinned plan SHA256",EFI_CRC_ERROR);}
 mPlan=B;
 if(CompareMem(mPlan,"OP80P01",8)!=0 || *(UINT32 *)(mPlan+8)!=1 || *(UINT32 *)(mPlan+12)!=4096 ||
 *(UINT32 *)(mPlan+16)!=65536 || *(UINT32 *)(mPlan+20)!=16384 || *(UINT64 *)(mPlan+24)!=(1ULL<<30) || *(UINT64 *)(mPlan+32)!=64){Halt(L"pinned plan geometry",EFI_COMPROMISED_DATA);}
 mUndo=FixedPcdGet32(PcdOpenBringupMode)==14;
 if(!mUndo && FixedPcdGet32(PcdOpenBringupMode)!=13){Halt(L"repair mode",EFI_ACCESS_DENIED);}
}
STATIC VOID InitializePinnedVolume (VOID) {
 EFI_STATUS S=OpenInitPinnedVolume(&mPinned,mVolumes[1].Source,mVolumes[1].Bounce,LowBuffer(),mPlan+256,mUndo);
 if(EFI_ERROR(S)){Halt(L"pinned facade",S);}
}
STATIC VOID FindPinnedPhysicalDisk (VOID) {
 EFI_HANDLE *Handles;UINTN Count,I,J,Matches=0;EFI_BLOCK_IO_PROTOCOL *Io;EFI_STATUS S;
 UINT8 (*After)[4096]=AllocatePool(5*4096);UINT8 *Check=AllocatePool(4096);UINT8 Pattern[5];
 if(After==NULL||Check==NULL){Halt(L"GPT check memory",EFI_OUT_OF_RESOURCES);}
 S=OpenG80MakeCorrected(After);if(EFI_ERROR(S)){Halt(L"GPT candidate CRC",S);}
 S=gBS->LocateHandleBuffer(ByProtocol,&gEfiBlockIoProtocolGuid,NULL,&Count,&Handles);if(EFI_ERROR(S)){Halt(L"physical block inventory",S);}
 for(I=0;I<Count;I++){
  S=gBS->HandleProtocol(Handles[I],&gEfiBlockIoProtocolGuid,(VOID **)&Io);
  if(EFI_ERROR(S)||Io==NULL||Io->Media==NULL||!Io->Media->MediaPresent||Io->Media->LogicalPartition||Io->Media->ReadOnly||Io->Media->BlockSize!=4096||Io->Media->LastBlock!=0x7613bff||Io->ReadBlocks==NULL||Io->WriteBlocks==NULL||Io->FlushBlocks==NULL||Io->Media->IoAlign>65536){continue;}
  ZeroMem(Pattern,sizeof(Pattern));
  for(J=0;J<5;J++){
   S=Io->ReadBlocks(Io,Io->Media->MediaId,mGoldenGptLba[J],4096,mPinned.Ro.Bounce);if(EFI_ERROR(S)){break;}
   CopyMem(Check,mPinned.Ro.Bounce,4096);
   S=Io->ReadBlocks(Io,Io->Media->MediaId,mGoldenGptLba[J],4096,mPinned.Ro.Bounce);
   if(EFI_ERROR(S)||CompareMem(Check,mPinned.Ro.Bounce,4096)!=0||
    (CompareMem(Check,mGoldenGpt[J],4096)!=0&&CompareMem(Check,After[J],4096)!=0)){break;}
   Pattern[J]=(CompareMem(Check,mGoldenGpt[J],4096)==0)?1:2;
  }
  if(J==5 && (Pattern[1]==Pattern[2] || Pattern[3]==Pattern[4])){mRawDisk=Io;Matches++;}
 }
 FreePool(Handles);FreePool(After);FreePool(Check);
 if(Matches!=1){Halt(L"exact GPT physical identity/preimage",EFI_COMPROMISED_DATA);}
 Print(L"G80 both GPT copies match pinned before/after sectors. No GPT write yet.\n");
}
STATIC VOID ScanInitialPrefix (VOID) {
 UINTN I,Old=0,New=0;UINT8 H[32];OPEN_SHA256 Whole;EFI_STATUS S;
 OpenShaInit(&Whole);
 for(I=0;I<OPEN_PIN_COUNT;I++){
  S=mPinned.Ro.Io.ReadBlocks(&mPinned.Ro.Io,mPinned.Ro.Media.MediaId,I*16,65536,mPinned.Check);if(EFI_ERROR(S)){Halt(L"prefix qualification read",S);}
  OpenShaAll(mPinned.Check,65536,H);OpenShaUpdate(&Whole,mPinned.Check,65536);
  if(CompareMem(H,mPinned.Hashes+I*64,32)==0){Old++;}else if(CompareMem(H,mPinned.Hashes+I*64+32,32)==0){New++;}
  else{Print(L"Unknown prefix chunk %u; storage remains held.\n",I);Halt(L"prefix preimage",EFI_COMPROMISED_DATA);}
  if((I&1023)==1023){Print(L"G80 prefix qualification: %u / 1024 MiB\n",(I+1)/16);}
 }
 OpenShaFinal(&Whole,H);Print(L"G80 all prefix chunks qualified; before=%u after=%u.\n",Old,New);
 // A fully before/after image must also agree with its whole-prefix identity.
 if((Old==OPEN_PIN_COUNT && CompareMem(H,mPlan+48,32)!=0)||(New==OPEN_PIN_COUNT && CompareMem(H,mPlan+80,32)!=0)){Halt(L"whole prefix identity",EFI_CRC_ERROR);}
}
STATIC VOID GptLog (CONST CHAR8 *Format,...) { (VOID)Format; }
STATIC BOOLEAN ScanFinalChunk (OPEN_MSD *Msd, EFI_USBFN_IO_PROTOCOL *Usb) {
 EFI_STATUS S;UINT8 H[32];OPEN_GPT_TYPE_RESULT Result;UINTN Offset=mUndo?0:32;
 S=mPinned.Ro.Io.ReadBlocks(&mPinned.Ro.Io,mPinned.Ro.Media.MediaId,mFinalIndex*16,65536,mPinned.Check);
 if(EFI_ERROR(S)){Halt(L"final prefix read",S);}
 OpenShaAll(mPinned.Check,65536,H);
 if(CompareMem(H,mPinned.Hashes+mFinalIndex*64+Offset,32)!=0){
  Print(L"G80 commit held: prefix chunk %u is incomplete. Updates remain available.\n",mFinalIndex);
  mFinalActive=FALSE;mPinned.Frozen=FALSE;return FALSE;
 }
 OpenShaUpdate(&mFinalSha,mPinned.Check,65536);mFinalIndex++;
 if((mFinalIndex&1023)==0){Print(L"G80 final validation: %u / 1024 MiB\n",mFinalIndex/16);}
 if(mFinalIndex!=OPEN_PIN_COUNT){return FALSE;}
 OpenShaFinal(&mFinalSha,H);if(CompareMem(H,mPlan+(mUndo?48:80),32)!=0){Halt(L"final complete prefix SHA256",EFI_CRC_ERROR);}
 // Prefix is now frozen and independently matches the whole prepared image.
 OpenRunG80GptTypeMigration(mRawDisk,&mSuperInfo,mUndo?14:13,GptLog,&Result);
 Print(L"G80 GPT state=%u status=%r writes=%u verified=%u\n",Result.State,Result.Status,Result.WritesAttempted,Result.WritesVerified);
 if(!OpenG80GptTypeAllowsBoot()){Halt(L"GPT exact transaction",Result.Status);}
 mFinalActive=FALSE;mCommitPending=FALSE;
 if(mUndo){mUndoComplete=TRUE;Print(L"G80 inverse verified. Original prefix/GPT restored; recovery stays read only.\n");return FALSE;}
 // The control read's CSW completed before final scanning began; USB requests
 // were serviced between each 64KiB check. Stop MSD, restore the exact callback,
 // then reconnect the same filesystem controller to discard its old FAT cache.
 Usb->Transfer=mOriginalTransfer;
 S=Msd->Stop(Msd);if(EFI_ERROR(S)){Halt(L"MSD stop before boot",S);}
 S=gBS->DisconnectController(mUserHandle,NULL,NULL);
 if(EFI_ERROR(S)&&S!=EFI_NOT_FOUND){Halt(L"old boot filesystem disconnect",S);}
 S=gBS->ConnectController(mUserHandle,NULL,NULL,TRUE);
 if(EFI_ERROR(S)&&S!=EFI_ALREADY_STARTED){Halt(L"new boot filesystem connect",S);}
 Print(L"G80 prefix/GPT verified. Booting inert maintenance WinPE.\n");return TRUE;
}

VOID
OpenRunBootRepairUsb (VOID)
{
  OPEN_MSD *Msd = NULL;
  EFI_USBFN_IO_PROTOCOL *Usb = NULL;
  EFI_STATUS Status;
  UINTN I, Polls = 0;
  UINT32 LastSpeed = MAX_UINT32, Speed;
  OPEN_CONFIGURE_EX OriginalConfigure;
  UINT8 MaxLun = 0;
  Print (L"\nG80 guarded boot repair. Installed Windows is preserved.\n");
  gBS->SetWatchdogTimer (0, 0, 0, NULL);
  Status = gBS->LocateProtocol (&mMsdGuid, NULL, (VOID **)&Msd);
  if (EFI_ERROR (Status) || !MsdAbiMatches (Msd, FindDriverImage (&mMsdFile, 0x11200))) { Halt (L"MSD binary/ABI guard", EFI_UNSUPPORTED); }
  Status = Msd->MaxLun (Msd, &MaxLun);
  if (EFI_ERROR (Status) || MaxLun != 16) { Halt (L"MSD LUN capacity", EFI_UNSUPPORTED); }
  LoadPinnedPlan ();
  SelectVolumes ();
  InitializePinnedVolume ();
  FindPinnedPhysicalDisk ();
  ScanInitialPrefix ();
  for (I = 0; I < 2; I++) {
    Status = Msd->Assign (Msd, ExportedIo(I), (UINT32)I);
    if (EFI_ERROR (Status)) { Halt (L"MSD facade assignment", Status); }
  }
  if (*(UINT64 *)((UINT8 *)Msd + 0x50) != 2) { Halt (L"MSD configured LUN count", EFI_COMPROMISED_DATA); }
  for (I = 0; I < 16; I++) {
    VOID *Assigned = *(VOID **)((UINT8 *)Msd + 0x58 + I * 24);
    if (Assigned != (I < 2 ? ExportedIo(I) : NULL)) { Halt (L"MSD LUN isolation", EFI_COMPROMISED_DATA); }
  }
  Status = gBS->LocateProtocol (&gEfiUsbFunctionIoProtocolGuid, NULL, (VOID **)&Usb);
  if (EFI_ERROR (Status) || !UsbAbiMatches (Usb, FindDriverImage (&mUsbFile, 0x16500))) {
    Halt (L"USB function interface", EFI_UNSUPPORTED);
  }
  Status = Usb->StartController (Usb);
  Print (L"USB function start: %r\n", Status);
  if (EFI_ERROR (Status) && Status != EFI_ALREADY_STARTED) { Halt (L"USB function start", Status); }
  // Msd->Start invokes the vendor Configure...Ex slot once. Route that one
  // call to the verified USB2 configuration and immediately restore the slot.
  mRecoveryUsb = Usb;
  mMsdInstance = (UINT8 *)Msd - 8;
  mOriginalTransfer = Usb->Transfer;
  Usb->Transfer = RecoveryTransfer;
  OriginalConfigure = *(OPEN_CONFIGURE_EX *)((UINT8 *)Usb + 0x90);
  *(OPEN_CONFIGURE_EX *)((UINT8 *)Usb + 0x90) = ConfigureUsb2Only;
  Status = Msd->Start (Msd);
  *(OPEN_CONFIGURE_EX *)((UINT8 *)Usb + 0x90) = OriginalConfigure;
  Print (L"USB mass storage start: %r\n", Status);
  if (EFI_ERROR (Status)) { Halt (L"USB mass storage start", Status); }
  if (mUsb2Configurations != 1) { Halt (L"USB2 configuration count", EFI_COMPROMISED_DATA); }
  Print (L"G79 USB2 only: legacy descriptors, no SuperSpeed conversion.\n");
  Print (L"G79 SCSI MODE SENSE write protection enabled.\n");
  Print (L"Only pinned 64 KiB boot-prefix updates are admitted. System volume is read only.\n");
  for (;;) {
    Status = Msd->Event (Msd);
    if (EFI_ERROR(mPinned.Fault)) { Halt(L"pinned prefix write failed; preserve evidence",mPinned.Fault); }
    if (mCommitPending && !mFinalActive && --mCommitDelay==0) {
      mCommitPending=FALSE;mFinalActive=TRUE;mFinalIndex=0;mPinned.Frozen=TRUE;OpenShaInit(&mFinalSha);
      Print(L"G80 validating complete prefix before GPT/boot handoff...\n");
    }
    if (mFinalActive && ScanFinalChunk(Msd,Usb)) { return; }
    Speed = *(UINT32 *)((UINT8 *)Usb - 8 + 0x184);
    if (Speed != LastSpeed) {
      Print (L"G79 USB negotiated speed=%u; core maximum=%u (0=High Speed)\n",
        Speed, *((UINT8 *)Usb - 8 + 0x188));
      LastSpeed = Speed;
    }
    // EFI_NOT_READY is the observed driver's detached event status.
    if (EFI_ERROR (Status) && Status != EFI_NOT_READY) {
      Print (L"MSD event status: %r\n", Status);
      gBS->Stall (100000);
    }
    if (++Polls == 100000) {
      Print (L"Read bytes: super=%lu userdata=%lu; denied writes=%lu/%lu; read errors=%lu/%lu\n",
        mVolumes[0].ReadBytes,mPinned.Ro.ReadBytes,mVolumes[0].DeniedWrites,mPinned.Ro.DeniedWrites,
        mVolumes[0].Failures,mPinned.Ro.Failures);
      Print (L"SCSI protected MODE SENSE responses: %lu/%lu\n",mProtectedSense[0],mProtectedSense[1]);
      Polls = 0;
    }
    gBS->Stall (100);
  }
}
