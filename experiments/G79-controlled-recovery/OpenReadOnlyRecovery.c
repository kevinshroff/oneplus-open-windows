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

STATIC VOID
Halt (CONST CHAR16 *Reason, EFI_STATUS Status)
{
  Print (L"\nG79 STOP: %s: %r\nStorage is not exported. No Windows boot follows.\n", Reason, Status);
  DEBUG ((DEBUG_ERROR, "G79 STOP %s %r\n", Reason, Status));
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

VOID
OpenRunReadOnlyUsbRecovery (VOID)
{
  OPEN_MSD *Msd = NULL;
  EFI_USBFN_IO_PROTOCOL *Usb = NULL;
  EFI_STATUS Status;
  UINTN I, Polls = 0;
  UINT32 LastSpeed = MAX_UINT32, Speed;
  OPEN_CONFIGURE_EX OriginalConfigure;
  UINT8 MaxLun = 0;
  Print (L"\nG79 read-only USB recovery. No OS deployment runs.\n");
  gBS->SetWatchdogTimer (0, 0, 0, NULL);
  Status = gBS->LocateProtocol (&mMsdGuid, NULL, (VOID **)&Msd);
  if (EFI_ERROR (Status) || !MsdAbiMatches (Msd, FindDriverImage (&mMsdFile, 0x11200))) { Halt (L"MSD binary/ABI guard", EFI_UNSUPPORTED); }
  Status = Msd->MaxLun (Msd, &MaxLun);
  if (EFI_ERROR (Status) || MaxLun != 16) { Halt (L"MSD LUN capacity", EFI_UNSUPPORTED); }
  SelectVolumes ();
  for (I = 0; I < 2; I++) {
    Status = Msd->Assign (Msd, &mVolumes[I].Io, (UINT32)I);
    if (EFI_ERROR (Status)) { Halt (L"MSD facade assignment", Status); }
  }
  if (*(UINT64 *)((UINT8 *)Msd + 0x50) != 2) { Halt (L"MSD configured LUN count", EFI_COMPROMISED_DATA); }
  for (I = 0; I < 16; I++) {
    VOID *Assigned = *(VOID **)((UINT8 *)Msd + 0x58 + I * 24);
    if (Assigned != (I < 2 ? &mVolumes[I].Io : NULL)) { Halt (L"MSD LUN isolation", EFI_COMPROMISED_DATA); }
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
  Print (L"Laptop may now read the two volumes. Every write callback refuses.\n");
  for (;;) {
    Status = Msd->Event (Msd);
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
        mVolumes[0].ReadBytes,mVolumes[1].ReadBytes,mVolumes[0].DeniedWrites,mVolumes[1].DeniedWrites,
        mVolumes[0].Failures,mVolumes[1].Failures);
      Print (L"SCSI protected MODE SENSE responses: %lu/%lu\n",mProtectedSense[0],mProtectedSense[1]);
      Polls = 0;
    }
    gBS->Stall (100);
  }
}
