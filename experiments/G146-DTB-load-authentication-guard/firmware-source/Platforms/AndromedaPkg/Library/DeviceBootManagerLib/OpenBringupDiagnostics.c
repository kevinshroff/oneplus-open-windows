/** @file
  Automatic, storage-read-only OnePlus Open bring-up inspection.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Uefi.h>
#include <PiDxe.h>
#include <Guid/Acpi.h>
#include <Guid/MemoryAttributesTable.h>
#include <IndustryStandard/Acpi.h>
#include <Protocol/AcpiSystemDescriptionTable.h>
#include <Protocol/BlockIo.h>
#include <Protocol/PartitionInfo.h>
#include <Protocol/UsbFunctionIo.h>
#include <Protocol/Usb2HostController.h>
#include <Protocol/UsbIo.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/EFIPlatformInfo.h>
#include <Protocol/EFIChipInfo.h>
#include <Protocol/EFIRamPartition.h>
#include <Library/ArmLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/DxeServicesLib.h>
#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/PrintLib.h>
#include <Library/PlatformMemoryMapLib.h>
#include <Library/FrameBufferSerialPortLib.h>
#include <Library/UefiBootServicesTableLib.h>

#define OPEN_USB_LABEL_PRE_G16 ((FixedPcdGet32 (PcdOpenBringupMode) == 9) ? "G15" : \
                        ((FixedPcdGet32 (PcdOpenBringupMode) == 8) ? "G13" : \
                        ((FixedPcdGet32 (PcdOpenBringupMode) == 7) ? "G11" : "G08")))

VOID OpenRunBootRepairUsb (VOID);
EFI_STATUS OpenRunAdspPreflight (VOID);
VOID OpenRunReadOnlyUsbRecovery (VOID);
VOID OpenCollectBootStorageEvidence (IN VOID (*WriteLog)(IN CONST CHAR8 *Format, ...));
VOID OpenCollectRawStorageEvidence (IN VOID (*WriteLog)(IN CONST CHAR8 *Format, ...));
#define OPEN_USB_LABEL ((FixedPcdGet32 (PcdOpenBringupMode) == 10) ? "G16" : ((FixedPcdGet32 (PcdOpenBringupMode) == 11) ? "G16-UNDO" : OPEN_USB_LABEL_PRE_G16))
BOOLEAN OpenGptTypeAllowsBoot (VOID);
VOID OpenCollectGptSnapshot (IN VOID (*WriteLog)(IN CONST CHAR8 *Format, ...));

#define OPEN_REPORT_SIZE  (128 * 1024)
#define OPEN_PAGE_LINES   32
#define OPEN_ACPI_RAW_LIMIT  1024

STATIC CHAR8                  *mReport;
STATIC UINTN                  mUsed;
STATIC EFI_MEMORY_DESCRIPTOR  *mMap;
STATIC UINTN                  mMapSize;
STATIC UINTN                  mDescriptorSize;
STATIC BOOLEAN                mTruncated;
STATIC UINTN                  mUsbInitBase;
STATIC UINT64                 mUsbInitSize;
STATIC UINTN                  mUsbInitMatches;
STATIC BOOLEAN                mUsbPeripheralStarted;

STATIC BOOLEAN
ResetDiagnosticPage (VOID)
{
  ARM_MEMORY_REGION_DESCRIPTOR_EX *Map;
  UINTN I;
  UINT64 Bytes;
  PFBCON_POSITION Position;
  Map = GetPlatformMemoryMap ();
  Bytes = (UINT64)FixedPcdGet32 (PcdMipiFrameBufferWidth) *
          FixedPcdGet32 (PcdMipiFrameBufferHeight) *
          (FixedPcdGet32 (PcdMipiFrameBufferPixelBpp) / 8);
  for (I = 0; (I < MAX_ARM_MEMORY_REGION_DESCRIPTOR_COUNT) && (Map[I].Length != 0); I++) {
    if (AsciiStrCmp (Map[I].Name, "Display Reserved") != 0) { continue; }
    if ((Bytes == 0) || (Map[I].Length < sizeof (*Position)) ||
        (Bytes > Map[I].Length - sizeof (*Position))) { return FALSE; }
    // This is the same shared cursor location used by FrameBufferSerialPortLib
    // and initialized in ArmPlatformLib/InitializationUtils.c. Reset both the
    // pixels and cursor so a page never crosses the logger's clear-on-wrap.
    SetMem ((VOID *)(UINTN)Map[I].Address, (UINTN)Bytes, 0);
    Position = (VOID *)(UINTN)(Map[I].Address + Bytes);
    Position->x = 0;
    Position->y = 0;
    // The first subsequent debug line flushes the framebuffer via its logger.
    return TRUE;
  }
  return FALSE;
}

STATIC VOID
Log (IN CONST CHAR8 *Format, ...)
{
  VA_LIST Args;
  UINTN   Written;
  if ((mReport == NULL) || (mUsed >= OPEN_REPORT_SIZE - 2)) {
    mTruncated = TRUE;
    return;
  }
  VA_START (Args, Format);
  Written = AsciiVSPrint (mReport + mUsed, OPEN_REPORT_SIZE - mUsed, Format, Args);
  VA_END (Args);
  mUsed += Written;
  if (mUsed >= OPEN_REPORT_SIZE - 2) {
    mTruncated = TRUE;
  }
}

STATIC EFI_STATUS
SnapshotMap (VOID)
{
  EFI_STATUS Status;
  UINTN      Size;
  UINTN      Key;
  UINT32     Version;
  // An intentionally generous buffer avoids allocating while printing the map.
  if (mMap == NULL) {
    mMap = AllocatePool (64 * 1024);
    if (mMap == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
  }
  Size = 64 * 1024;
  Status = gBS->GetMemoryMap (&Size, mMap, &Key, &mDescriptorSize, &Version);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  if ((mDescriptorSize < sizeof (*mMap)) || ((Size % mDescriptorSize) != 0)) {
    return EFI_COMPROMISED_DATA;
  }
  mMapSize = Size;
  return EFI_SUCCESS;
}

STATIC BOOLEAN
Readable (IN UINT64 Address, IN UINT64 Length)
{
  UINTN                 Offset;
  EFI_MEMORY_DESCRIPTOR *D;
  UINT64                Size;
  if ((Length == 0) || (Address > MAX_UINT64 - Length) || (mMap == NULL)) {
    return FALSE;
  }
  for (Offset = 0; Offset < mMapSize; Offset += mDescriptorSize) {
    D = (VOID *)((UINT8 *)mMap + Offset);
    if ((D->Type == EfiMemoryMappedIO) || (D->Type == EfiMemoryMappedIOPortSpace) ||
        (D->Type == EfiUnusableMemory) || (D->NumberOfPages > (MAX_UINT64 >> EFI_PAGE_SHIFT))) {
      continue;
    }
    Size = D->NumberOfPages << EFI_PAGE_SHIFT;
    if ((Address >= D->PhysicalStart) && (Address - D->PhysicalStart <= Size) &&
        (Length <= Size - (Address - D->PhysicalStart))) {
      return TRUE;
    }
  }
  return FALSE;
}

STATIC VOID
Registers (VOID)
{
  UINT64 El, Mmfr, Tcr, Ttbr, Mair, Sctlr;
  __asm__ __volatile__ ("mrs %0, CurrentEL" : "=r" (El));
  __asm__ __volatile__ ("mrs %0, id_aa64mmfr0_el1" : "=r" (Mmfr));
  if (El == 8) {
    __asm__ __volatile__ ("mrs %0, tcr_el2" : "=r" (Tcr));
    __asm__ __volatile__ ("mrs %0, ttbr0_el2" : "=r" (Ttbr));
    __asm__ __volatile__ ("mrs %0, mair_el2" : "=r" (Mair));
    __asm__ __volatile__ ("mrs %0, sctlr_el2" : "=r" (Sctlr));
  } else if (El == 4) {
    __asm__ __volatile__ ("mrs %0, tcr_el1" : "=r" (Tcr));
    __asm__ __volatile__ ("mrs %0, ttbr0_el1" : "=r" (Ttbr));
    __asm__ __volatile__ ("mrs %0, mair_el1" : "=r" (Mair));
    __asm__ __volatile__ ("mrs %0, sctlr_el1" : "=r" (Sctlr));
  } else {
    Log ("Unexpected CurrentEL=%lx; other registers skipped\n", El);
    return;
  }
  Log ("CPU EL=%lu PA-bits=%u MMFR0=%016lx\n", El >> 2, ArmGetPhysicalAddressBits (), Mmfr);
  Log ("TCR=%016lx TTBR0=%016lx\n", Tcr, Ttbr);
  Log ("MAIR=%016lx SCTLR=%016lx\n", Mair, Sctlr);
}

STATIC VOID
Usb (VOID)
{
  EFI_HANDLE            *Handles;
  UINTN                 Count, I;
  EFI_STATUS            Status;
  EFI_USBFN_IO_PROTOCOL *UsbFn;
  Count = 0;
  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiUsbFunctionIoProtocolGuid, NULL, &Count, &Handles);
  Log ("USB FUNCTION handles=%u status=%r\n", Count, Status);
  if (!EFI_ERROR (Status)) {
    for (I = 0; I < Count; I++) {
      Status = gBS->HandleProtocol (Handles[I], &gEfiUsbFunctionIoProtocolGuid, (VOID **)&UsbFn);
      if (!EFI_ERROR (Status) && (UsbFn != NULL)) {
        Log ("USBFN[%u] ptr=%p revision=%08x\n", I, UsbFn, UsbFn->Revision);
        Log (" alloc=%p free=%p event=%p xfer=%p\n", UsbFn->AllocateTransferBuffer,
             UsbFn->FreeTransferBuffer, UsbFn->EventHandler, UsbFn->Transfer);
      }
    }
    FreePool (Handles);
  }
  Count = 0;
  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiUsb2HcProtocolGuid, NULL, &Count, &Handles);
  Log ("USB HOST handles=%u status=%r\n", Count, Status);
  if (!EFI_ERROR (Status)) { FreePool (Handles); }
  Count = 0;
  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiUsbIoProtocolGuid, NULL, &Count, &Handles);
  Log ("USB IO handles=%u status=%r\n", Count, Status);
  if (!EFI_ERROR (Status)) { FreePool (Handles); }
  Log ("USB enumeration only; no descriptors configured or USB transfers.\n");
}

STATIC BOOLEAN
UsbPrerequisites (VOID)
{
  STATIC struct {
    CONST CHAR8 *Name;
    EFI_GUID Guid;
  } Probes[] = {
    { "ChipInfo",     { 0xb0760469, 0x970c, 0x487a, { 0xa4, 0xb5, 0x28, 0xdb, 0x7b, 0x45, 0xce, 0xf1 } } },
    { "SPMI",         { 0xfa5f306b, 0xf47d, 0x4ac4, { 0xa4, 0x7d, 0x88, 0x2f, 0x82, 0x04, 0xec, 0x30 } } },
    { "SMEM",         { 0xf4e5c7d0, 0xd239, 0x47cb, { 0xaa, 0xcd, 0x7f, 0x66, 0xef, 0x76, 0x32, 0x38 } } },
    { "PlatformInfo", { 0x157a5c45, 0x21b2, 0x43c5, { 0xba, 0x7c, 0x82, 0x2f, 0xee, 0x5f, 0xe5, 0x99 } } },
    { "AcpiSdt",      { 0xeb97088e, 0xcfdf, 0x49c6, { 0xbe, 0x4b, 0xd9, 0x06, 0xa5, 0xb2, 0x0e, 0x86 } } },
    { "USB_CONFIG",   { 0xe722b03f, 0xb250, 0x42ce, { 0x8e, 0xbd, 0x5b, 0xd5, 0x18, 0x12, 0xd0, 0x37 } } },
  };
  UINTN I;
  VOID *Interface;
  EFI_STATUS Status;
  BOOLEAN Ready;
  Ready = TRUE;
  Log ("UsbConfig binary requires ALL first five protocols:\n");
  for (I = 0; I < ARRAY_SIZE (Probes); I++) {
    Interface = NULL;
    Status = gBS->LocateProtocol (&Probes[I].Guid, NULL, &Interface);
    Log ("PROTOCOL %a: %r ptr=%p\n", Probes[I].Name, Status, Interface);
    if ((I < 5) && (EFI_ERROR (Status) || (Interface == NULL))) { Ready = FALSE; }
  }
  Log ("\n");
  return Ready;
}

STATIC UINTN
UsbResidentImages (IN BOOLEAN Print)
{
  STATIC struct {
    CONST CHAR8 *Name;
    EFI_GUID Guid;
    UINTN Count;
  } Images[] = {
    { "UsbConfig",    { 0xcd823a4d, 0x7dec, 0x4531, { 0xae, 0x5d, 0x41, 0x34, 0xfa, 0x41, 0x27, 0xb8 } }, 0 },
    { "UsbInit",      { 0x0a134f0e, 0x075e, 0x40b3, { 0x9c, 0x63, 0x3b, 0x39, 0x06, 0x80, 0x46, 0x63 } }, 0 },
    { "UsbfnDwc3",    { 0x94f8a6a7, 0xdc34, 0x4101, { 0x88, 0xc1, 0x99, 0x17, 0x9c, 0xce, 0xae, 0x83 } }, 0 },
    { "UsbPwrCtrl",   { 0x11faed4c, 0xb21f, 0x4d88, { 0x8e, 0x48, 0xc4, 0xc2, 0x8a, 0x1e, 0x50, 0xdf } }, 0 },
    { "SPMI",         { 0x2a7b4bef, 0x80cd, 0x49e1, { 0xb4, 0x73, 0x37, 0x4b, 0xa4, 0xd6, 0x73, 0xfc } }, 0 },
    { "ChipInfo",     { 0x10e193df, 0x9966, 0x44e7, { 0xb1, 0x7c, 0x59, 0xdd, 0x83, 0x1e, 0x20, 0xfc } }, 0 },
    { "PlatformInfo", { 0xb105211b, 0xbbbd, 0x4add, { 0xa3, 0xb0, 0xd1, 0xcf, 0x4a, 0x52, 0x15, 0x4c } }, 0 },
    { "PmicGlink",    { 0x6d4a9cf7, 0xcc0c, 0x42b0, { 0xaa, 0x89, 0xf6, 0xa6, 0xa8, 0xd9, 0x92, 0x73 } }, 0 },
  };
  EFI_HANDLE *Handles;
  EFI_LOADED_IMAGE_PROTOCOL *Image;
  EFI_DEVICE_PATH_PROTOCOL *Node;
  EFI_GUID *FileGuid;
  EFI_STATUS Status;
  UINTN Count, I, J;
  for (J = 0; J < ARRAY_SIZE (Images); J++) { Images[J].Count = 0; }
  mUsbInitBase = 0; mUsbInitSize = 0; mUsbInitMatches = 0;
  Count = 0;
  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiLoadedImageProtocolGuid, NULL, &Count, &Handles);
  if (Print) { Log ("Resident image scan: %r handles=%u\n", Status, Count); }
  if (EFI_ERROR (Status)) { return MAX_UINTN; }
  for (I = 0; I < Count; I++) {
    Status = gBS->HandleProtocol (Handles[I], &gEfiLoadedImageProtocolGuid, (VOID **)&Image);
    if (EFI_ERROR (Status) || (Image == NULL) || (Image->FilePath == NULL) ||
        !IsDevicePathValid (Image->FilePath, 4096)) { continue; }
    for (Node = Image->FilePath; !IsDevicePathEnd (Node); Node = NextDevicePathNode (Node)) {
      if ((DevicePathType (Node) != MEDIA_DEVICE_PATH) ||
          (DevicePathSubType (Node) != MEDIA_PIWG_FW_FILE_DP) ||
          (DevicePathNodeLength (Node) != sizeof (MEDIA_FW_VOL_FILEPATH_DEVICE_PATH))) { continue; }
      FileGuid = &((MEDIA_FW_VOL_FILEPATH_DEVICE_PATH *)Node)->FvFileName;
      for (J = 0; J < ARRAY_SIZE (Images); J++) {
        if (CompareGuid (FileGuid, &Images[J].Guid)) {
          Images[J].Count++;
          if (J == 1) {
            mUsbInitBase = (UINTN)Image->ImageBase;
            mUsbInitSize = Image->ImageSize;
            mUsbInitMatches++;
          }
        }
      }
    }
  }
  FreePool (Handles);
  if (Print) {
    for (J = 0; J < ARRAY_SIZE (Images); J++) {
      Log ("IMAGE %a: resident matches=%u\n", Images[J].Name, Images[J].Count);
    }
    Log ("Zero matches can mean not dispatched, failed, or another path.\n");
    Log ("Resident image alone does not prove successful initialization.\n");
  }
  return Images[0].Count;
}

STATIC BOOLEAN
UsbEntryInputs (VOID)
{
  STATIC EFI_GUID ChipGuid = { 0xb0760469, 0x970c, 0x487a, { 0xa4, 0xb5, 0x28, 0xdb, 0x7b, 0x45, 0xce, 0xf1 } };
  EFI_PLATFORMINFO_PROTOCOL *Platform;
  EFI_PLATFORMINFO_PLATFORM_INFO_TYPE Info;
  EFI_CHIPINFO_PROTOCOL *Chip;
  EFIChipInfoVersionType Version;
  EFI_STATUS Status;
  BOOLEAN Ready;
  Ready = FALSE;
  Platform = NULL;
  Status = gBS->LocateProtocol (&gEfiPlatformInfoProtocolGuid, NULL, (VOID **)&Platform);
  if (EFI_ERROR (Status) || (Platform == NULL) || (Platform->GetPlatformInfo == NULL)) {
    Log ("Platform entry getter unavailable: %r\n", Status);
    return FALSE;
  }
  ZeroMem (&Info, sizeof (Info));
  Status = Platform->GetPlatformInfo (Platform, &Info);
  Log ("GetPlatformInfo: %r type=%x ver=%x sub=%x\n", Status, Info.platform, Info.version, Info.subtype);
  if (EFI_ERROR (Status)) { return FALSE; }
  Chip = NULL;
  Status = gBS->LocateProtocol (&ChipGuid, NULL, (VOID **)&Chip);
  if (EFI_ERROR (Status) || (Chip == NULL) || (Chip->GetChipVersion == NULL)) {
    Log ("Chip entry getter unavailable: %r\n", Status);
    return FALSE;
  }
  Version = 0;
  Status = Chip->GetChipVersion (Chip, &Version);
  Log ("GetChipVersion: %r revision=%lx value=%x\n", Status, Chip->Revision, Version);
  Ready = (BOOLEAN)!EFI_ERROR (Status);
  return Ready;
}

// E06 explicitly retries one existing driver at application TPL. It does not
// relax its dependency expression, change its bytes, or write OS partitions.
STATIC VOID
UsbConfigRetry (IN BOOLEAN PrerequisitesReady)
{
  STATIC EFI_GUID ConfigGuid = { 0xe722b03f, 0xb250, 0x42ce, { 0x8e, 0xbd, 0x5b, 0xd5, 0x18, 0x12, 0xd0, 0x37 } };
  STATIC EFI_GUID FileGuid = { 0xcd823a4d, 0x7dec, 0x4531, { 0xae, 0x5d, 0x41, 0x34, 0xfa, 0x41, 0x27, 0xb8 } };
  EFI_STATUS Status;
  EFI_TPL Tpl;
  EFI_HANDLE Image;
  EFI_DEVICE_PATH_PROTOCOL *Path;
  VOID *Buffer, *Interface;
  UINTN Size, Resident, ExitDataSize;
  UINT32 Crc;
  CHAR16 *ExitData;

  Tpl = gBS->RaiseTPL (TPL_HIGH_LEVEL);
  gBS->RestoreTPL (Tpl);
  Log ("RETRY current TPL=%u (requires 4)\n", Tpl);
  if ((Tpl != TPL_APPLICATION) || !PrerequisitesReady) {
    Log ("RETRY skipped: TPL or prerequisite guard\n"); return;
  }
  Interface = NULL;
  Status = gBS->LocateProtocol (&ConfigGuid, NULL, &Interface);
  if ((Status != EFI_NOT_FOUND) || (Interface != NULL)) {
    Log ("RETRY skipped: USB_CONFIG status=%r ptr=%p\n", Status, Interface); return;
  }
  Resident = UsbResidentImages (FALSE);
  Log ("RETRY existing UsbConfig image matches=%lu\n", Resident);
  if (Resident != 0) { Log ("RETRY skipped: image present or scan failed\n"); return; }
  if (!UsbEntryInputs ()) { Log ("RETRY skipped: entry getter failure\n"); return; }
  Buffer = NULL; Size = 0;
  Status = GetSectionFromAnyFv (&FileGuid, EFI_SECTION_PE32, 0, &Buffer, &Size);
  Log ("RETRY FV PE32: %r bytes=%lu\n", Status, Size);
  if (EFI_ERROR (Status)) { if (Buffer != NULL) { FreePool (Buffer); } return; }
  Crc = 0;
  Status = gBS->CalculateCrc32 (Buffer, Size, &Crc);
  Log ("RETRY source CRC=%08x status=%r\n", Crc, Status);
  if (EFI_ERROR (Status) || (Size != 94208) || (Crc != 0xBFF3D402)) {
    Log ("RETRY stopped: expected packaged driver bytes do not match\n");
    FreePool (Buffer); return;
  }
  Path = NULL;
  Status = GetFileDevicePathFromAnyFv (&FileGuid, EFI_SECTION_PE32, 0, &Path);
  Log ("RETRY FV path: %r\n", Status);
  if (EFI_ERROR (Status) || (Path == NULL)) {
    if (Path != NULL) { FreePool (Path); }
    FreePool (Buffer); return;
  }
  Image = NULL;
  ResetDiagnosticPage ();
  DEBUG ((DEBUG_ERROR, "\n        OPEN-USB %a: calling LoadImage for UsbConfig\n",
          (FixedPcdGet32 (PcdOpenBringupMode) >= 6) ? OPEN_USB_LABEL :
          ((FixedPcdGet32 (PcdOpenBringupMode) == 5) ? "F07" : "E06")));
  gBS->Stall (2000000);
  Status = gBS->LoadImage (FALSE, gImageHandle, Path, Buffer, Size, &Image);
  FreePool (Path); FreePool (Buffer);
  Log ("RETRY LoadImage: %r raw=%016lx handle=%p\n", Status, Status, Image);
  if (EFI_ERROR (Status)) {
    // A security violation can leave a loaded but unstarted handle. Never
    // start it; unload only that returned handle, then stop this attempt.
    if (Image != NULL) {
      Status = gBS->UnloadImage (Image);
      Log ("RETRY rejected-image cleanup: %r\n", Status);
    }
    return;
  }
  if (Image == NULL) { Log ("RETRY stopped: successful load returned NULL handle\n"); return; }
  ResetDiagnosticPage ();
  DEBUG ((DEBUG_ERROR, "\n        OPEN-USB %a: calling StartImage for UsbConfig\n",
          (FixedPcdGet32 (PcdOpenBringupMode) >= 6) ? OPEN_USB_LABEL :
          ((FixedPcdGet32 (PcdOpenBringupMode) == 5) ? "F07" : "E06")));
  DEBUG ((DEBUG_ERROR, "        If this stops here, keep this phase visible in the recording.\n"));
  gBS->Stall (3000000);
  ExitData = NULL; ExitDataSize = 0;
  Status = gBS->StartImage (Image, &ExitDataSize, &ExitData);
  Log ("RETRY StartImage: %r raw=%016lx exit-bytes=%lu\n", Status, Status, ExitDataSize);
  // StartImage/CoreExit owns unloading a failed driver. Do not reuse its
  // handle after an error; keep a successfully started driver resident.
  if (ExitData != NULL) { FreePool (ExitData); }
  Interface = NULL;
  Status = gBS->LocateProtocol (&ConfigGuid, NULL, &Interface);
  Log ("AFTER RETRY USB_CONFIG: %r ptr=%p\n", Status, Interface);
  if (FixedPcdGet32 (PcdOpenBringupMode) == 4) {
    Log ("Only UsbConfig was retried; UsbInit was not restarted.\n");
  }
}

// Reconstructed from the exact UsbInitDxe PE32, with each method's argument
// registers and memory writes checked in REA assembly. Runtime calls require
// the matching resident image, revision, instance signature and method RVAs.
typedef struct {
  UINT8 Core;
  UINT8 Reserved[3];
  UINT32 SupportedModes;
} OPEN_USB_CORE_INFO;
typedef struct _OPEN_USB_INIT OPEN_USB_INIT;
struct _OPEN_USB_INIT {
  UINT64 Revision;
  EFI_STATUS (EFIAPI *QueryCoreCount)(OPEN_USB_INIT *This, UINT8 *Count);
  EFI_STATUS (EFIAPI *QueryCoreInfo)(OPEN_USB_INIT *This, UINT8 *Core, OPEN_USB_CORE_INFO *Info);
  EFI_STATUS (EFIAPI *StartController)(OPEN_USB_INIT *This, UINT8 Core, UINT32 Modes);
  EFI_STATUS (EFIAPI *StopController)(OPEN_USB_INIT *This, UINT8 Core, UINT32 Modes);
};
STATIC_ASSERT (sizeof (OPEN_USB_CORE_INFO) == 8, "UsbInit core info ABI");
STATIC_ASSERT (sizeof (OPEN_USB_INIT) == 40, "UsbInit interface ABI");

STATIC BOOLEAN
UsbInitInterfaceMatches (IN OPEN_USB_INIT *Init, IN UINT64 Signature)
{
  return (BOOLEAN)((Init != NULL) && (Signature == 0x69627375) &&
    (mUsbInitMatches == 1) && (mUsbInitBase != 0) &&
    (mUsbInitSize >= 0x18B4) && (mUsbInitSize <= MAX_UINTN - mUsbInitBase) &&
    (Init->Revision == 0x10000) &&
    ((UINTN)Init->QueryCoreCount == mUsbInitBase + 0x1444) &&
    ((UINTN)Init->QueryCoreInfo == mUsbInitBase + 0x14DC) &&
    ((UINTN)Init->StartController == mUsbInitBase + 0x15B8) &&
    ((UINTN)Init->StopController == mUsbInitBase + 0x1684));
}

STATIC VOID
UsbInitRunPeripheral (IN OPEN_USB_INIT *Init)
{
  struct { UINT8 Count; UINT8 Canary[7]; } Count;
  struct { OPEN_USB_CORE_INFO Info; UINT8 Canary[8]; } Core;
  EFI_STATUS Status;
  UINT8 Number;
  UINTN I;
  SetMem (&Count, sizeof (Count), 0xA5); Count.Count = 0;
  Status = Init->QueryCoreCount (Init, &Count.Count);
  Log ("INIT QueryCoreCount: %r count=%u\n", Status, Count.Count);
  if (EFI_ERROR (Status)) { return; }
  for (I = 0; I < sizeof (Count.Canary); I++) {
    if (Count.Canary[I] != 0xA5) { Log ("INIT count ABI canary changed; stopped\n"); return; }
  }
  if ((Count.Count == 0) || (Count.Count > 16)) { Log ("INIT invalid core count; stopped\n"); return; }
  SetMem (&Core, sizeof (Core), 0xA5); ZeroMem (&Core.Info, sizeof (Core.Info));
  Number = 0;
  Status = Init->QueryCoreInfo (Init, &Number, &Core.Info);
  Log ("INIT QueryCoreInfo: %r core=%u modes=%x\n", Status, Core.Info.Core, Core.Info.SupportedModes);
  if (EFI_ERROR (Status)) { return; }
  for (I = 0; I < sizeof (Core.Canary); I++) {
    if (Core.Canary[I] != 0xA5) { Log ("INIT info ABI canary changed; stopped\n"); return; }
  }
  if ((Number != 0) || (Core.Info.Core != 0) || ((Core.Info.SupportedModes & 2) == 0) ||
      ((Core.Info.SupportedModes & ~7U) != 0)) {
    Log ("INIT core 0 peripheral support guard failed; stopped\n"); return;
  }
  ResetDiagnosticPage ();
  DEBUG ((DEBUG_ERROR, "\n        OPEN-USB %a: StartController core 0, peripheral mode 2\n",
          (FixedPcdGet32 (PcdOpenBringupMode) >= 6) ? OPEN_USB_LABEL : "F07"));
  DEBUG ((DEBUG_ERROR, "        Keep this phase visible if progress stops.\n"));
  gBS->Stall (3000000);
  Status = Init->StartController (Init, 0, 2);
  Log ("INIT StartController(0,2): %r raw=%016lx\n", Status, Status);
  if (!EFI_ERROR (Status)) {
    mUsbPeripheralStarted = TRUE;
    gBS->Stall (2000000);
  }
}

STATIC EFI_STATUS
UsbInitLoad (IN VOID *Buffer, IN UINTN Size)
{
  STATIC EFI_GUID FileGuid = { 0x0a134f0e, 0x075e, 0x40b3, { 0x9c, 0x63, 0x3b, 0x39, 0x06, 0x80, 0x46, 0x63 } };
  EFI_STATUS Status;
  EFI_DEVICE_PATH_PROTOCOL *Path;
  EFI_HANDLE Image;
  UINTN ExitSize;
  CHAR16 *ExitData;
  Path = NULL;
  Status = GetFileDevicePathFromAnyFv (&FileGuid, EFI_SECTION_PE32, 0, &Path);
  Log ("INIT FV path: %r\n", Status);
  if (EFI_ERROR (Status) || (Path == NULL)) {
    if (Path != NULL) { FreePool (Path); }
    return EFI_ERROR (Status) ? Status : EFI_NOT_FOUND;
  }
  Image = NULL;
  ResetDiagnosticPage ();
  DEBUG ((DEBUG_ERROR, "\n        OPEN-USB %a: calling LoadImage for UsbInit\n",
          (FixedPcdGet32 (PcdOpenBringupMode) >= 6) ? OPEN_USB_LABEL : "F07"));
  gBS->Stall (2000000);
  Status = gBS->LoadImage (FALSE, gImageHandle, Path, Buffer, Size, &Image);
  FreePool (Path);
  Log ("INIT LoadImage: %r raw=%016lx handle=%p\n", Status, Status, Image);
  if (EFI_ERROR (Status)) {
    if (Image != NULL) { Log ("INIT rejected-image cleanup: %r\n", gBS->UnloadImage (Image)); }
    return Status;
  }
  if (Image == NULL) { return EFI_COMPROMISED_DATA; }
  ResetDiagnosticPage ();
  DEBUG ((DEBUG_ERROR, "\n        OPEN-USB %a: calling StartImage for UsbInit\n",
          (FixedPcdGet32 (PcdOpenBringupMode) >= 6) ? OPEN_USB_LABEL : "F07"));
  gBS->Stall (3000000);
  ExitSize = 0; ExitData = NULL;
  Status = gBS->StartImage (Image, &ExitSize, &ExitData);
  Log ("INIT StartImage: %r raw=%016lx exit-bytes=%lu\n", Status, Status, ExitSize);
  if (ExitData != NULL) { FreePool (ExitData); }
  return Status;
}

// A published pointer alone is insufficient after a failed driver entry.
// Require a resident configuration image before the UsbInit methods can use it.
STATIC BOOLEAN
UsbConfigProviderLive (VOID)
{
  STATIC EFI_GUID ConfigGuid = { 0xe722b03f, 0xb250, 0x42ce, { 0x8e, 0xbd, 0x5b, 0xd5, 0x18, 0x12, 0xd0, 0x37 } };
  EFI_STATUS Status;
  VOID *Config;
  UINTN Count;
  Config = NULL;
  Status = gBS->LocateProtocol (&ConfigGuid, NULL, &Config);
  Log ("INIT prerequisite USB_CONFIG: %r ptr=%p\n", Status, Config);
  if (EFI_ERROR (Status) || (Config == NULL)) { return FALSE; }
  Count = UsbResidentImages (FALSE);
  Log ("INIT prerequisite resident UsbConfig images=%lu\n", Count);
  return (BOOLEAN)(Count == 1);
}

STATIC VOID
UsbInitBringUp (VOID)
{
  STATIC EFI_GUID InitGuid = { 0x2da15ac7, 0x4909, 0x4c4c, { 0xb8, 0xc3, 0xa7, 0x42, 0x19, 0x5e, 0xa4, 0x6e } };
  STATIC EFI_GUID FileGuid = { 0x0a134f0e, 0x075e, 0x40b3, { 0x9c, 0x63, 0x3b, 0x39, 0x06, 0x80, 0x46, 0x63 } };
  EFI_TPL Tpl;
  EFI_STATUS Status;
  OPEN_USB_INIT *Init;
  VOID *Buffer;
  UINTN Size;
  UINT32 Crc;
  UINT64 Signature;
  Log ("\n%a initialization and peripheral activation:\n",
       (FixedPcdGet32 (PcdOpenBringupMode) >= 6) ? OPEN_USB_LABEL : "F07");
  Tpl = gBS->RaiseTPL (TPL_HIGH_LEVEL); gBS->RestoreTPL (Tpl);
  if (Tpl != TPL_APPLICATION) { Log ("INIT stopped: requires TPL 4, actual=%u\n", Tpl); return; }
  if (!UsbConfigProviderLive ()) {
    Log ("INIT stopped: configuration provider/image guard failed\n"); return;
  }
  Buffer = NULL; Size = 0;
  Status = GetSectionFromAnyFv (&FileGuid, EFI_SECTION_PE32, 0, &Buffer, &Size);
  Log ("INIT FV PE32: %r bytes=%lu\n", Status, Size);
  if (EFI_ERROR (Status)) { if (Buffer != NULL) { FreePool (Buffer); } return; }
  Crc = 0;
  Status = gBS->CalculateCrc32 (Buffer, Size, &Crc);
  Log ("INIT source CRC=%08x status=%r\n", Crc, Status);
  if (EFI_ERROR (Status) || (Size != 32768) || (Crc != 0xC80EAD17)) {
    Log ("INIT stopped: packaged UsbInit bytes do not match\n"); FreePool (Buffer); return;
  }
  ResetDiagnosticPage ();
  DEBUG ((DEBUG_ERROR, "\n        OPEN-USB %a: dispatch pending firmware drivers\n",
          (FixedPcdGet32 (PcdOpenBringupMode) >= 6) ? OPEN_USB_LABEL : "F07"));
  gBS->Stall (1000000);
  Status = gDS->Dispatch ();
  Log ("INIT native DXE dispatch: %r raw=%016lx\n", Status, Status);
  Init = NULL;
  Status = gBS->LocateProtocol (&InitGuid, NULL, (VOID **)&Init);
  Log ("INIT protocol after dispatch: %r ptr=%p\n", Status, Init);
  if ((Status == EFI_NOT_FOUND) && (Init == NULL)) {
    if ((UsbResidentImages (FALSE) == MAX_UINTN) || (mUsbInitMatches != 0)) {
      Log ("INIT retry stopped: image resident or scan failed\n"); FreePool (Buffer); return;
    }
    Status = UsbInitLoad (Buffer, Size);
    if (EFI_ERROR (Status)) { FreePool (Buffer); return; }
    Status = gBS->LocateProtocol (&InitGuid, NULL, (VOID **)&Init);
    Log ("INIT protocol after explicit start: %r ptr=%p\n", Status, Init);
  }
  FreePool (Buffer);
  if (EFI_ERROR (Status) || (Init == NULL)) { return; }
  UsbResidentImages (FALSE);
  Log ("INIT image matches=%lu base=%p bytes=%lx\n", mUsbInitMatches, (VOID *)mUsbInitBase, mUsbInitSize);
  Status = SnapshotMap ();
  if (EFI_ERROR (Status) || ((UINTN)Init < 8) || !Readable ((UINTN)Init - 8, 64)) {
    Log ("INIT stopped: interface memory guard, map=%r\n", Status); return;
  }
  Signature = 0; CopyMem (&Signature, (UINT8 *)Init - 8, sizeof (Signature));
  Log ("INIT interface revision=%lx signature=%lx\n", Init->Revision, Signature);
  if (!UsbInitInterfaceMatches (Init, Signature)) {
    Log ("INIT stopped: interface owner/layout/RVA guard failed\n"); return;
  }
  UsbInitRunPeripheral (Init);
}

// Continue only after our guarded peripheral request succeeded and the one
// function interface observed in F07 is still present with its required hooks.
STATIC BOOLEAN
UsbReadyForWindows (VOID)
{
  EFI_HANDLE *Handles;
  EFI_USBFN_IO_PROTOCOL *UsbFn;
  EFI_STATUS Status;
  UINTN Count;
  BOOLEAN Ready;
  if (!mUsbPeripheralStarted) { Log ("BOOT guard: peripheral start did not succeed\n"); return FALSE; }
  Handles = NULL; Count = 0;
  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiUsbFunctionIoProtocolGuid, NULL, &Count, &Handles);
  Log ("BOOT guard: USB FUNCTION handles=%lu status=%r\n", Count, Status);
  if (EFI_ERROR (Status) || (Handles == NULL) || (Count != 1)) {
    if (Handles != NULL) { FreePool (Handles); }
    return FALSE;
  }
  UsbFn = NULL;
  Status = gBS->HandleProtocol (Handles[0], &gEfiUsbFunctionIoProtocolGuid, (VOID **)&UsbFn);
  FreePool (Handles);
  if (EFI_ERROR (Status) || (UsbFn == NULL) || EFI_ERROR (SnapshotMap ()) ||
      !Readable ((UINTN)UsbFn, sizeof (*UsbFn))) { return FALSE; }
  Ready = (BOOLEAN)((UsbFn->Revision == 0x10003) &&
    (UsbFn->AllocateTransferBuffer != NULL) && (UsbFn->FreeTransferBuffer != NULL) &&
    (UsbFn->EventHandler != NULL) && (UsbFn->Transfer != NULL) &&
    (UsbFn->ConfigureEnableEndpoints != NULL) && (UsbFn->StartController != NULL) &&
    (UsbFn->StopController != NULL));
  Log ("BOOT guard: USB function revision=%x required hooks=%u\n", UsbFn->Revision, Ready);
  return Ready;
}

STATIC VOID
Smem (VOID)
{
  EFI_RAMPARTITION_PROTOCOL *Protocol;
  RamPartitionEntry        *Banks;
  UINT32                   Count, I, Capacity;
  EFI_STATUS               Status;
  Status = gBS->LocateProtocol (&gEfiRamPartitionProtocolGuid, NULL, (VOID **)&Protocol);
  if (EFI_ERROR (Status)) { Log ("SMEM protocol: %r\n", Status); return; }
  Count = 0;
  Status = Protocol->GetRamPartitions (Protocol, NULL, &Count);
  if ((Status != EFI_BUFFER_TOO_SMALL) || (Count == 0) || (Count > 128)) {
    Log ("SMEM count=%u status=%r rejected\n", Count, Status); return;
  }
  Capacity = Count;
  Banks = AllocateZeroPool (Count * sizeof (*Banks));
  if (Banks == NULL) { Log ("SMEM allocation failed\n"); return; }
  Status = Protocol->GetRamPartitions (Protocol, Banks, &Count);
  Log ("SMEM banks=%u status=%r\n", Count, Status);
  if (!EFI_ERROR (Status) && (Count <= Capacity)) {
    for (I = 0; I < Count; I++) {
      Log ("RAM[%u] b=%012lx n=%012lx\n", I, Banks[I].Base, Banks[I].AvailableLength);
    }
  }
  FreePool (Banks);
}

STATIC VOID
Partitions (VOID)
{
  EFI_HANDLE                  *Handles;
  EFI_PARTITION_INFO_PROTOCOL  *Info;
  EFI_BLOCK_IO_PROTOCOL        *Io;
  EFI_STATUS                  Status;
  UINTN                       Count, I;
  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiPartitionInfoProtocolGuid, NULL, &Count, &Handles);
  if (EFI_ERROR (Status)) { Log ("PartitionInfo: %r\n", Status); return; }
  Log ("GPT protocols=%u; showing boot/OS volumes only (cached data)\n", Count);
  for (I = 0; I < Count; I++) {
    Status = gBS->HandleProtocol (Handles[I], &gEfiPartitionInfoProtocolGuid, (VOID **)&Info);
    if (EFI_ERROR (Status) || (Info->Type != PARTITION_TYPE_GPT)) { continue; }
    // GPT names have a fixed 36-character bound and need not be terminated.
    CHAR16 Name[37];
    CopyMem (Name, Info->Info.Gpt.PartitionName, sizeof (Name) - sizeof (CHAR16));
    Name[36] = L'\0';
    BOOLEAN Important = (BOOLEAN)((StrCmp (Name, L"super") == 0) ||
       (StrCmp (Name, L"userdata") == 0) || (StrCmp (Name, L"boot_a") == 0) ||
       (StrCmp (Name, L"boot_b") == 0));
    if (!Important) { continue; }
    Log ("PART[%u] %s GUID=%g\n", I, Name, &Info->Info.Gpt.UniquePartitionGUID);
    Log (" LBA=%lx..%lx type=%g\n", Info->Info.Gpt.StartingLBA,
         Info->Info.Gpt.EndingLBA, &Info->Info.Gpt.PartitionTypeGUID);
    Status = gBS->HandleProtocol (Handles[I], &gEfiBlockIoProtocolGuid, (VOID **)&Io);
    if (!EFI_ERROR (Status) && (Io != NULL) && (Io->Media != NULL)) {
      Log (" block=%u last=%lx align=%u readonly=%u\n", Io->Media->BlockSize,
           Io->Media->LastBlock, Io->Media->IoAlign, Io->Media->ReadOnly);
    }
  }
  FreePool (Handles);
}

STATIC VOID
Table (IN EFI_ACPI_DESCRIPTION_HEADER *Header)
{
  CHAR8  Signature[5];
  UINT32 Crc;
  UINTN  I, J;
  UINT8  Sum;
  UINT8  *Bytes;
  if (!Readable ((UINTN)Header, sizeof (*Header))) {
    Log ("ACPI unreadable header=%p\n", Header); return;
  }
  CopyMem (Signature, &Header->Signature, 4); Signature[4] = '\0';
  if ((Header->Length < sizeof (*Header)) || (Header->Length > 65536) ||
      !Readable ((UINTN)Header, Header->Length)) {
    Log ("ACPI %a invalid/unreadable length=%u at=%p\n", Signature, Header->Length, Header); return;
  }
  Bytes = (UINT8 *)Header;
  Sum = 0;
  for (I = 0; I < Header->Length; I++) { Sum = (UINT8)(Sum + Bytes[I]); }
  Crc = 0;
  gBS->CalculateCrc32 (Header, Header->Length, &Crc);
  Log ("ACPI %a at=%p len=%u rev=%u sum=%02x crc=%08x\n", Signature,
       Header, Header->Length, Header->Revision, Sum, Crc);
  // A02's 51-KiB CSRT exhausted the entire report before the memory map.
  // Keep checksums/CRCs for every table, but raw bytes only for bounded tables
  // relevant to this experiment. Never emit a partial table as a full dump.
  if ((Header->Length <= OPEN_ACPI_RAW_LIMIT) &&
      ((Header->Signature == SIGNATURE_32 ('F','A','C','P')) ||
       (Header->Signature == SIGNATURE_32 ('D','S','D','T')) ||
       (Header->Signature == SIGNATURE_32 ('A','P','I','C')) ||
       (Header->Signature == SIGNATURE_32 ('G','T','D','T')) ||
       (Header->Signature == SIGNATURE_32 ('D','B','G','2')))) {
    for (I = 0; I < Header->Length; I += 16) {
      Log ("%a+%04x ", Signature, (UINT32)I);
      for (J = I; (J < I + 16) && (J < Header->Length); J++) { Log ("%02x ", Bytes[J]); }
      Log ("\n");
    }
  } else {
    Log ("%a raw bytes omitted by report policy; full-table CRC above\n", Signature);
  }
  if ((Header->Signature == SIGNATURE_32 ('F','A','C','P')) && (Header->Length >= 148)) {
    UINT64 Dsdt;
    Dsdt = ReadUnaligned64 ((UINT64 *)(Bytes + 140));
    if (Dsdt == 0) { Dsdt = ReadUnaligned32 ((UINT32 *)(Bytes + 40)); }
    if ((Dsdt != 0) && Readable (Dsdt, sizeof (*Header))) {
      EFI_ACPI_DESCRIPTION_HEADER *D = (VOID *)(UINTN)Dsdt;
      if (D->Signature == SIGNATURE_32 ('D','S','D','T')) { Table (D); }
    }
  }
}

STATIC VOID
ConfigurationTables (VOID)
{
  EFI_MEMORY_ATTRIBUTES_TABLE *Mat;
  EFI_MEMORY_DESCRIPTOR *D;
  UINTN I, J;
  UINT64 Bytes;
  Log ("EFI CONFIGURATION TABLES=%u\n", gST->NumberOfTableEntries);
  for (I = 0; I < gST->NumberOfTableEntries; I++) {
    Log ("CFG %g at=%p\n", &gST->ConfigurationTable[I].VendorGuid,
         gST->ConfigurationTable[I].VendorTable);
    if (!CompareGuid (&gST->ConfigurationTable[I].VendorGuid, &gEfiMemoryAttributesTableGuid)) { continue; }
    Mat = gST->ConfigurationTable[I].VendorTable;
    if (!Readable ((UINTN)Mat, sizeof (*Mat))) { Log ("MAT header unreadable\n"); continue; }
    Log ("MAT version=%u entries=%u descriptor=%u\n", Mat->Version, Mat->NumberOfEntries, Mat->DescriptorSize);
    if ((Mat->NumberOfEntries > 1024) || (Mat->DescriptorSize < sizeof (*D)) ||
        (Mat->DescriptorSize > 1024)) { Log ("MAT dimensions rejected\n"); continue; }
    Bytes = sizeof (*Mat) + (UINT64)Mat->NumberOfEntries * Mat->DescriptorSize;
    if (!Readable ((UINTN)Mat, Bytes)) { Log ("MAT contents unreadable\n"); continue; }
    for (J = 0; J < Mat->NumberOfEntries; J++) {
      D = (VOID *)((UINT8 *)(Mat + 1) + J * Mat->DescriptorSize);
      Log ("MAT[%u] t=%u b=%012lx pages=%lx a=%lx\n", J, D->Type, D->PhysicalStart,
           D->NumberOfPages, D->Attribute);
    }
  }
}

STATIC VOID
Acpi (VOID)
{
  EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER *Rsdp;
  EFI_ACPI_DESCRIPTION_HEADER *Xsdt;
  UINTN I, Count;
  UINT64 Address;
  for (I = 0; I < gST->NumberOfTableEntries; I++) {
    if (!CompareGuid (&gST->ConfigurationTable[I].VendorGuid, &gEfiAcpi20TableGuid)) { continue; }
    Rsdp = gST->ConfigurationTable[I].VendorTable;
    if (!Readable ((UINTN)Rsdp, sizeof (*Rsdp))) { Log ("RSDP unreadable=%p\n", Rsdp); return; }
    Address = ReadUnaligned64 (&Rsdp->XsdtAddress);
    Log ("RSDP=%p rev=%u XSDT=%lx\n", Rsdp, Rsdp->Revision, Address);
    if (!Readable (Address, sizeof (*Xsdt))) { Log ("XSDT header unreadable\n"); return; }
    Xsdt = (VOID *)(UINTN)Address;
    if ((Xsdt->Signature != SIGNATURE_32 ('X','S','D','T')) || (Xsdt->Length < sizeof (*Xsdt)) ||
        (Xsdt->Length > 4096) || !Readable (Address, Xsdt->Length) ||
        (((Xsdt->Length - sizeof (*Xsdt)) % sizeof (UINT64)) != 0)) {
      Log ("Invalid XSDT\n"); return;
    }
    Count = (Xsdt->Length - sizeof (*Xsdt)) / sizeof (UINT64);
    Log ("INSTALLED ACPI TABLES=%u\n", Count);
    for (I = 0; I < Count; I++) {
      Address = ReadUnaligned64 ((UINT64 *)((UINT8 *)Xsdt + sizeof (*Xsdt) + I * sizeof (UINT64)));
      Table ((VOID *)(UINTN)Address);
    }
    return;
  }
  Log ("No ACPI 2.0 RSDP in configuration table\n");
}

STATIC VOID
Memory (VOID)
{
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR *Gcd;
  EFI_MEMORY_DESCRIPTOR           *D;
  EFI_HOB_GENERIC_HEADER          *Hob;
  EFI_HOB_RESOURCE_DESCRIPTOR     *Resource;
  UINTN                          Count, I;
  UINT64                         Conventional, HighConventional, BootLoader, Runtime;
  EFI_STATUS                     Status;
  Log ("MEMORY FIRST: ReadyToBoot snapshot, before Windows/ExitBootServices\n");
  Status = SnapshotMap ();
  Log ("EFI MAP status=%r\n", Status);
  if (EFI_ERROR (Status)) { return; }
  Conventional = 0; HighConventional = 0; BootLoader = 0; Runtime = 0;
  for (I = 0; I < mMapSize; I += mDescriptorSize) {
    UINT64 Size, End;
    D = (VOID *)((UINT8 *)mMap + I);
    if ((D->NumberOfPages > (MAX_UINT64 >> EFI_PAGE_SHIFT)) ||
        ((D->NumberOfPages << EFI_PAGE_SHIFT) > MAX_UINT64 - D->PhysicalStart)) {
      Log ("EFI[%u] INVALID RANGE\n", I / mDescriptorSize); continue;
    }
    Size = D->NumberOfPages << EFI_PAGE_SHIFT;
    End = D->PhysicalStart + Size;
    if (D->Type == EfiConventionalMemory) {
      Conventional += Size;
      if (End > 0x100000000ULL) {
        HighConventional += End - MAX (D->PhysicalStart, 0x100000000ULL);
      }
    } else if ((D->Type == EfiLoaderCode) || (D->Type == EfiLoaderData) ||
               (D->Type == EfiBootServicesCode) || (D->Type == EfiBootServicesData)) {
      BootLoader += Size;
    } else if ((D->Type == EfiRuntimeServicesCode) || (D->Type == EfiRuntimeServicesData)) {
      Runtime += Size;
    }
  }
  Log ("EFI totals BYTES(hex): conventional=%lx high(>=4GiB)=%lx\n", Conventional, HighConventional);
  Log ("EFI totals BYTES(hex): boot+loader=%lx runtime=%lx\n", BootLoader, Runtime);
  Log ("descriptor bytes=%u count=%u; t=7 conventional, t=0 reserved\n", mDescriptorSize, mMapSize / mDescriptorSize);
  // The snapshot is not changed while its entries are printed into mReport.
  for (I = 0; I < mMapSize; I += mDescriptorSize) {
    D = (VOID *)((UINT8 *)mMap + I);
    Log ("EFI[%u] t=%u b=%012lx p=%lx a=%lx\n", I / mDescriptorSize,
         D->Type, D->PhysicalStart, D->NumberOfPages, D->Attribute);
    if (D->VirtualStart != 0) { Log (" virt=%012lx\n", D->VirtualStart); }
  }
  Log ("RESOURCE HOBS\n");
  Hob = GetHobList ();
  for (I = 0; (Hob != NULL) && !END_OF_HOB_LIST (Hob) && (I < 4096); I++) {
    if (GET_HOB_TYPE (Hob) == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR) {
      Resource = (VOID *)Hob;
      Log ("HOB t=%u b=%012lx n=%012lx a=%lx\n", Resource->ResourceType,
           Resource->PhysicalStart, Resource->ResourceLength, Resource->ResourceAttribute);
    }
    Hob = GET_NEXT_HOB (Hob);
  }
  Status = gDS->GetMemorySpaceMap (&Count, &Gcd);
  Log ("GCD status=%r count=%u\n", Status, EFI_ERROR (Status) ? 0 : Count);
  if (!EFI_ERROR (Status)) {
    for (I = 0; I < Count; I++) {
      Log ("GCD[%u] t=%u b=%012lx n=%lx c=%lx a=%lx\n", I, Gcd[I].GcdMemoryType,
           Gcd[I].BaseAddress, Gcd[I].Length, Gcd[I].Capabilities, Gcd[I].Attributes);
    }
    FreePool (Gcd);
  }
}

VOID
OpenBringupDiagnostics (VOID)
{
  UINTN  I, Start, End, Line, Page, Pages, Row, Padding;
  UINT32 Crc;
  BOOLEAN Ready;
  BOOLEAN ContinueWindows;
  CHAR8  Text[97];
  if (FixedPcdGet32 (PcdOpenBringupMode) == 0) { return; }
  ContinueWindows = FALSE;
  DEBUG ((DEBUG_ERROR, "\nOPEN-BRINGUP: initializing and collecting firmware evidence...\n"));
  mReport = AllocateZeroPool (OPEN_REPORT_SIZE);
  if (mReport == NULL) { DEBUG ((DEBUG_ERROR, "OPEN-INSPECT: no report buffer\n")); CpuDeadLoop (); }
  if ((FixedPcdGet32 (PcdOpenBringupMode) == 5) ||
      (FixedPcdGet32 (PcdOpenBringupMode) >= 6)) {
    Log ("OPEN-USB %a 20261020; memory repair retained\n",
         (FixedPcdGet32 (PcdOpenBringupMode) >= 6) ? OPEN_USB_LABEL : "F07");
    Log ("AfterConsole; configuration + USB peripheral activation.\n");
    Ready = UsbPrerequisites ();
    UsbConfigRetry (Ready);
    if (Ready) { UsbInitBringUp (); }
    Usb (); UsbResidentImages (TRUE);
    if (FixedPcdGet32 (PcdOpenBringupMode) >= 6) { ContinueWindows = UsbReadyForWindows (); }
    if (FixedPcdGet32 (PcdOpenBringupMode) == 13 || FixedPcdGet32 (PcdOpenBringupMode) == 14) {
      if (!ContinueWindows) { DEBUG ((DEBUG_ERROR, "G80 USB prerequisites refused\n")); CpuDeadLoop (); }
      OpenRunBootRepairUsb ();
      return;
    }
    if (FixedPcdGet32 (PcdOpenBringupMode) == 12) {
      if (!ContinueWindows) { DEBUG ((DEBUG_ERROR, "G79 USB prerequisites refused\n")); CpuDeadLoop (); }
      OpenRunReadOnlyUsbRecovery ();
      CpuDeadLoop ();
    }
    if (FixedPcdGet32 (PcdOpenBringupMode) == 15 || FixedPcdGet32 (PcdOpenBringupMode) == 16) {
      { EFI_STATUS ReportStatus = OpenRunAdspPreflight ();
        DEBUG ((DEBUG_ERROR, "G119 report publication: %r\n", ReportStatus)); }
      // ACPI carries the preflight report; continue without timed photo pages.
      if (ContinueWindows) { FreePool (mReport); mReport = NULL; return; }
    } else if (FixedPcdGet32 (PcdOpenBringupMode) >= 7) {
      Line = 0;
      for (I = 0; I < mUsed; I++) { if (mReport[I] == '\n') { Line++; } }
      Padding = (OPEN_PAGE_LINES - (Line % OPEN_PAGE_LINES)) % OPEN_PAGE_LINES;
      for (I = 0; I < Padding; I++) { Log ("\n"); }
      if ((FixedPcdGet32 (PcdOpenBringupMode) >= 9) &&
          (FixedPcdGet32 (PcdOpenBringupMode) <= 11)) {
        OpenCollectGptSnapshot (Log);
        if ((FixedPcdGet32 (PcdOpenBringupMode) >= 10) && !OpenGptTypeAllowsBoot ()) {
          ContinueWindows = FALSE;
        }
      } else if (FixedPcdGet32 (PcdOpenBringupMode) == 8) {
        OpenCollectRawStorageEvidence (Log);
      } else {
        OpenCollectBootStorageEvidence (Log);
      }
    }
  } else if (FixedPcdGet32 (PcdOpenBringupMode) == 4) {
    Log ("OPEN-USB E06 20261020; memory repair retained\n");
    Log ("AfterConsole phase; one guarded UsbConfig retry; Windows paused.\n");
    Ready = UsbPrerequisites ();
    UsbConfigRetry (Ready);
    Usb (); UsbResidentImages (TRUE);
  } else if (FixedPcdGet32 (PcdOpenBringupMode) == 3) {
    Log ("OPEN-USB D05 20261020; memory repair retained\n");
    Log ("USB inspection; Windows intentionally paused.\n");
    Registers (); UsbPrerequisites (); Usb (); UsbResidentImages (TRUE);
  } else {
  Log ("OPEN-INSPECT B03 20261020 mode=%u\n", FixedPcdGet32 (PcdOpenBringupMode));
  Log ("mode 1=archived low-RAM; mode 2=memory repair\n");
  Log ("Storage-read-only inspection; Windows is intentionally paused.\n");
  Registers (); Usb (); Smem ();
  // Give the important first page its own boundary in the report.
  Line = 0;
  for (I = 0; I < mUsed; I++) { if (mReport[I] == '\n') { Line++; } }
  Padding = (OPEN_PAGE_LINES - (Line % OPEN_PAGE_LINES)) % OPEN_PAGE_LINES;
  for (I = 0; I < Padding; I++) { Log ("\n"); }
  Memory ();
  Partitions ();
  if (!EFI_ERROR (SnapshotMap ())) { ConfigurationTables (); Acpi (); }
  }
  Log ("END report; Windows %a; truncated=%u\n", ContinueWindows ? "continues after pages" : "paused", mTruncated);
  Crc = 0; gBS->CalculateCrc32 (mReport, mUsed, &Crc);
  Line = 0;
  for (I = 0; I < mUsed; I++) { if (mReport[I] == '\n') { Line++; } }
  Pages = (Line + OPEN_PAGE_LINES - 1) / OPEN_PAGE_LINES;
  // No timer callbacks or allocations in this loop. The existing large-font
  // framebuffer serial logger makes the pages photographable without input.
  for (;;) {
    Start = 0;
    for (Page = 0; Page < Pages; Page++) {
      if (!ResetDiagnosticPage ()) {
        DEBUG ((DEBUG_ERROR, "OPEN-INSPECT: unsupported framebuffer/cursor layout\n"));
        CpuDeadLoop ();
      }
      if (FixedPcdGet32 (PcdOpenBringupMode) >= 3) {
        DEBUG ((DEBUG_ERROR, "\n        OPEN-USB %a PAGE %u/%u CRC=%08x cut=%u\n",
                (FixedPcdGet32 (PcdOpenBringupMode) >= 6) ? OPEN_USB_LABEL :
                ((FixedPcdGet32 (PcdOpenBringupMode) == 5) ? "F07" :
                ((FixedPcdGet32 (PcdOpenBringupMode) == 4) ? "E06" : "D05")), Page + 1, Pages, Crc, mTruncated));
      } else {
      DEBUG ((DEBUG_ERROR, "\nOPEN-INSPECT B03 mode=%u PAGE %u/%u CRC=%08x cut=%u\n",
              FixedPcdGet32 (PcdOpenBringupMode), Page + 1, Pages, Crc, mTruncated));
      }
      for (Row = 0; Row < OPEN_PAGE_LINES; Row++) {
        End = Start;
        while ((End < mUsed) && (mReport[End] != '\n')) { End++; }
        I = MIN (End - Start, (FixedPcdGet32 (PcdOpenBringupMode) >= 3) ? sizeof (Text) - 9 : sizeof (Text) - 1);
        CopyMem (Text, mReport + Start, I); Text[I] = '\0';
        if (FixedPcdGet32 (PcdOpenBringupMode) >= 3) {
          DEBUG ((DEBUG_ERROR, "        %a\n", Text));
        } else {
          DEBUG ((DEBUG_ERROR, "%a\n", Text));
        }
        Start = (End < mUsed) ? End + 1 : mUsed;
      }
      DEBUG ((DEBUG_ERROR, "-- 12 second page; %a --\n",
              ContinueWindows ? "Windows continues after the final page" : "pages repeat; return to fastboot to exit"));
      gBS->Stall (12000000);
    }
    if (ContinueWindows) {
      FreePool (mMap); mMap = NULL;
      FreePool (mReport); mReport = NULL;
      ResetDiagnosticPage ();
      DEBUG ((DEBUG_ERROR, "\n        OPEN-USB %a: USB ready; continuing Windows boot\n", OPEN_USB_LABEL));
      gBS->Stall (3000000);
      return;
    }
  }
}
