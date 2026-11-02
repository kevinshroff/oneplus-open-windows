/** @file
  G133 inventory of a proposed DSP staging window. No mapping or region writes,
  reservation changes, device calls or PAS requests. Facts are observations from
  several service queries, not an atomic/global ownership or DMA proof.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Uefi.h>
#include <PiDxe.h>
#include <Pi/PiHob.h>
#include <Protocol/LoadedImage.h>
#include <Library/BaseLib.h>
#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PlatformMemoryMapLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DxeServicesTableLib.h>
#include "OpenKernelFootprint.h"

#define WINDOW_START 0xA9F80000ULL
#define WINDOW_END   0xAE880000ULL
#define KERNEL_START 0xA8000000ULL
#define KERNEL_BYTES 0x10000000ULL
#define MAX_ROWS 32U
#define MAP_BYTES (256U * 1024U)
#define HOB_BYTES (1024U * 1024U)

STATIC BOOLEAN mRan;
STATIC BOOLEAN mInventoryMatch;
BOOLEAN OpenKernelWindowInventoryComplete(VOID){return mRan && mInventoryMatch;}
STATIC EFI_GUID mScmInventory = {0x77ed108d,0x8524,0x4b8b,{0x9d,0x2e,0x34,0x98,0x7a,0xec,0xb9,0xc1}};

STATIC BOOLEAN
Intersects (UINT64 Base, UINT64 Bytes)
{
  return Bytes != 0 && Base <= MAX_UINT64 - Bytes &&
         Base < WINDOW_END && Base + Bytes > WINDOW_START;
}

STATIC BOOLEAN
Object (OPEN_KERNEL_REPORT R, CONST CHAR8 *Name, CONST VOID *P, UINTN Bytes)
{
  R ("K133_object %a base=%lx bytes=%lx valid_range=%u overlap=%u\n", Name,
     (UINT64)(UINTN)P, (UINT64)Bytes, (UINTN)P <= MAX_UINT64-Bytes,
     Intersects ((UINTN)P, Bytes));
  return (UINTN)P <= MAX_UINT64-Bytes && !Intersects((UINTN)P,Bytes);
}

VOID
OpenAppendKernelFootprint (OPEN_KERNEL_REPORT R)
{
  ARM_MEMORY_REGION_DESCRIPTOR_EX *Platform;
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR *Gcd = NULL;
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR ScmGcd;
  EFI_MEMORY_DESCRIPTOR *Mem = NULL, *D;
  EFI_LOADED_IMAGE_PROTOCOL *Image;
  EFI_HANDLE *Handles = NULL;
  EFI_HOB_GENERIC_HEADER *H;
  EFI_HOB_HANDOFF_INFO_TABLE *Phit;
  EFI_HOB_MEMORY_ALLOCATION *A;
  EFI_HOB_FIRMWARE_VOLUME *F;
  EFI_STATUS Status;
  VOID *HobBase, *Scm = NULL;
  UINTN I, Count = 0, Rows = 0, Size, Key = 0, Stride = 0;
  UINTN HobBytes = 0, Hobs = 0, ImageFailures = 0, ImageOverlaps = 0;
  UINTN HobLimit = 0, HobMatches = 0, ScmMatches = 0, ScmSlot = 0;
  UINTN GoodCompiled=0,GoodGcd=0,GoodEfi=0,StaticHobs=0,HobOverlapRows=0;
  BOOLEAN ObjectsClear=TRUE,ScmMapCandidate=FALSE;
  UINT32 Version = 0;
  BOOLEAN Complete = TRUE, HobEnd = FALSE, HandlesOwned = FALSE;
  UINT64 Bytes;

  if (R == NULL) { return; }
  if (mRan) { mInventoryMatch=FALSE; R ("K133_ERROR duplicate_call no_PAS=1\n"); return; }
  mRan = TRUE;
  R ("OPEN-KERNEL-FOOTPRINT G133 version=1\n");
  R ("K133_proposed dtb=A9F80000:80000 main=AA000000:4880000 region_writes=0 PAS_requests=0\n");

  Platform = GetPlatformMemoryMap ();
  Count = 0;
  if (Platform == NULL) { Complete = FALSE; }
  else {
    for (I = 0; I < MAX_ARM_MEMORY_REGION_DESCRIPTOR_COUNT && Platform[I].Length != 0; I++) {
      if (AsciiStrCmp (Platform[I].Name, "Kernel") != 0) { continue; }
      Count++;
      if(Platform[I].Address==KERNEL_START && Platform[I].Length==KERNEL_BYTES &&
         Platform[I].MemoryType==EfiReservedMemoryType && Platform[I].ResourceType==EFI_RESOURCE_SYSTEM_MEMORY)GoodCompiled++;
      R ("K133_compiled base=%lx bytes=%lx hob=%u resource=%u memtype=%u cap=%lx arm=%lx exact_bounds=%u\n",
        Platform[I].Address, Platform[I].Length, Platform[I].HobOption,
        Platform[I].ResourceType, Platform[I].MemoryType,
        Platform[I].ResourceAttribute, (UINT64)Platform[I].ArmAttributes,
        Platform[I].Address == KERNEL_START && Platform[I].Length == KERNEL_BYTES);
    }
    if (I == MAX_ARM_MEMORY_REGION_DESCRIPTOR_COUNT) { Complete = FALSE; }
  }
  R ("K133_compiled_matches=%lu\n", (UINT64)Count);
  if (Count != 1) { Complete = FALSE; }

  Status = gDS->GetMemorySpaceMap (&Count, &Gcd);
  R ("K133_gcd_status=%r count=%lu\n", Status, (UINT64)Count);
  if (EFI_ERROR (Status) || Count > 4096 || (Count != 0 && Gcd == NULL)) { Complete = FALSE; }
  else {
    Rows = 0;
    for (I = 0; I < Count; I++) {
      if (Gcd[I].BaseAddress > MAX_UINT64 - Gcd[I].Length) { Complete = FALSE; continue; }
      if (!Intersects (Gcd[I].BaseAddress, Gcd[I].Length)) { continue; }
      if (++Rows > MAX_ROWS) { Complete = FALSE; continue; }
      if(Gcd[I].GcdMemoryType==EfiGcdMemoryTypeSystemMemory &&
         Gcd[I].BaseAddress<=WINDOW_START && Gcd[I].BaseAddress+Gcd[I].Length>=WINDOW_END &&
         Gcd[I].Attributes==EFI_MEMORY_WB)GoodGcd++;
      R ("K133_gcd base=%lx bytes=%lx type=%u cap=%lx attr=%lx image=%p device=%p\n",
        Gcd[I].BaseAddress, Gcd[I].Length, Gcd[I].GcdMemoryType,
        Gcd[I].Capabilities, Gcd[I].Attributes, Gcd[I].ImageHandle, Gcd[I].DeviceHandle);
    }
    R ("K133_gcd_overlaps=%lu\n", (UINT64)Rows);
  }
  if (!EFI_ERROR (Status) && Gcd != NULL) { FreePool (Gcd); }

  /* Query the original callback slot's published maps, never the callback or
     table contents. OPAS independently binds its image/protocol identity. */
  Status = gBS->LocateProtocol (&mScmInventory, NULL, &Scm);
  if (Status != EFI_SUCCESS || Scm == NULL || (UINTN)Scm > MAX_UINTN-64) { Complete = FALSE; }
  else { ScmSlot = (UINTN)Scm+56; }
  R ("K133_scm locate=%r table=%p slot=%lx table_reads=0 hook_writes=0\n", Status, Scm, (UINT64)ScmSlot);
  if (ScmSlot != 0) {
    Status = gDS->GetMemorySpaceDescriptor (ScmSlot, &ScmGcd);
    R ("K133_scm_gcd_status=%r\n", Status);
    if (Status != EFI_SUCCESS) { Complete = FALSE; }
    else {
      R ("K133_scm_gcd base=%lx bytes=%lx type=%u cap=%lx attr=%lx\n",
        ScmGcd.BaseAddress, ScmGcd.Length, ScmGcd.GcdMemoryType, ScmGcd.Capabilities, ScmGcd.Attributes);
      if (ScmGcd.GcdMemoryType != EfiGcdMemoryTypeSystemMemory ||
          ScmGcd.BaseAddress > MAX_UINT64-ScmGcd.Length || ScmGcd.BaseAddress > ScmSlot ||
          ScmGcd.Length < 8 || ScmSlot-ScmGcd.BaseAddress > ScmGcd.Length-8) { Complete = FALSE; }
    }
  }

  HobBase = GetHobList ();
  Size = MAP_BYTES;
  Mem = AllocatePool (Size);
  if (Mem == NULL) { Status = EFI_OUT_OF_RESOURCES; Complete = FALSE; }
  else {
    Status = gBS->GetMemoryMap (&Size, Mem, &Key, &Stride, &Version);
    R ("K133_efi_status=%r bytes=%lu stride=%lu version=%u\n", Status, (UINT64)Size, (UINT64)Stride, Version);
    if (EFI_ERROR (Status) || Size > MAP_BYTES || Stride < sizeof (*Mem) ||
        Stride > 1024 || Size % Stride != 0 || Version != EFI_MEMORY_DESCRIPTOR_VERSION) { Complete = FALSE; }
    else {
      Rows = 0;
      for (I = 0; I < Size; I += Stride) {
        D = (VOID *)((UINT8 *)Mem + I);
        if (D->NumberOfPages > (MAX_UINT64-D->PhysicalStart)/4096) { Complete = FALSE; continue; }
        Bytes = D->NumberOfPages * 4096;
        if (HobBase != NULL && D->PhysicalStart <= (UINTN)HobBase && (UINTN)HobBase-D->PhysicalStart < Bytes) {
          HobMatches++;
          R ("K133_hob_storage base=%lx pages=%lx type=%u attr=%lx\n",
            D->PhysicalStart, D->NumberOfPages, D->Type, D->Attribute);
          if (D->Type == EfiBootServicesData) {
            UINT64 Room = D->PhysicalStart+Bytes-(UINTN)HobBase;
            HobLimit = (UINTN)HobBase+(UINTN)(Room > HOB_BYTES ? HOB_BYTES : Room);
          }
        }
        if (ScmSlot != 0 && D->PhysicalStart <= ScmSlot && Bytes >= 8 && ScmSlot-D->PhysicalStart <= Bytes-8) {
          ScmMatches++;
          ScmMapCandidate=(D->Attribute&(EFI_MEMORY_RO|EFI_MEMORY_RP))==0;
          R ("K133_scm_efi base=%lx pages=%lx type=%u attr=%lx\n",
            D->PhysicalStart, D->NumberOfPages, D->Type, D->Attribute);
          if (D->Type < EfiBootServicesCode || D->Type > EfiRuntimeServicesData) { Complete = FALSE; }
        }
        if (!Intersects (D->PhysicalStart, Bytes)) { continue; }
        if (++Rows > MAX_ROWS) { Complete = FALSE; continue; }
        if(D->Type==EfiReservedMemoryType && D->PhysicalStart<=WINDOW_START &&
           D->PhysicalStart+Bytes>=WINDOW_END)GoodEfi++;
        R ("K133_efi base=%lx pages=%lx type=%u attr=%lx\n",
          D->PhysicalStart, D->NumberOfPages, D->Type, D->Attribute);
      }
      R ("K133_efi_overlaps=%lu\n", (UINT64)Rows);
    }
    FreePool (Mem);
  }
  if (Mem == NULL) { R ("K133_efi_status=%r\n", Status); }
  R ("K133_scm_efi_matches=%lu\n", (UINT64)ScmMatches);
  if (ScmMatches != 1) { Complete = FALSE; }

  ObjectsClear = Object (R, "HobList", HobBase, HobBase == NULL ? 0 : sizeof (EFI_HOB_HANDOFF_INFO_TABLE));
  R ("K133_hob_storage_matches=%lu base=%p limit=%lx\n", (UINT64)HobMatches, HobBase, (UINT64)HobLimit);
  H = NULL;
  if (HobBase != NULL && HobMatches == 1 && HobLimit >= (UINTN)HobBase && HobLimit-(UINTN)HobBase >= sizeof (*Phit)) {
    H = HobBase;
    Phit = HobBase;
    /* DXE copies the HOB allocation without rebasing PHIT's absolute fields.
       Record them, but bound the current list by its actual mapped storage. */
    R ("K133_phit type=%u length=%u memory_bottom=%lx free_bottom=%lx original_end=%lx\n",
      H->HobType, H->HobLength, Phit->EfiMemoryBottom, Phit->EfiFreeMemoryBottom, Phit->EfiEndOfHobList);
    if (H->HobType != EFI_HOB_TYPE_HANDOFF || H->HobLength < sizeof (*Phit)) {
      Complete = FALSE; H = NULL;
    }
  } else { Complete = FALSE; }
  Rows = 0;
  while (H != NULL && Hobs < 4096 && HobBytes <= HOB_BYTES-sizeof (*H)) {
    if ((UINTN)H > HobLimit || HobLimit-(UINTN)H < sizeof (*H)) { Complete = FALSE; break; }
    if (H->HobLength < sizeof (*H) || (H->HobLength & 7) != 0 ||
        H->HobLength > HobLimit-(UINTN)H) { Complete = FALSE; break; }
    Hobs++;
    if (H->HobType == EFI_HOB_TYPE_END_OF_HOB_LIST) {
      HobEnd = H->HobLength == sizeof (*H);
      break;
    }
    if (H->HobType == EFI_HOB_TYPE_MEMORY_ALLOCATION) {
      if (H->HobLength < sizeof (*A)) { Complete = FALSE; break; }
      A = (VOID *)H;
      if (A->AllocDescriptor.MemoryBaseAddress > MAX_UINT64-A->AllocDescriptor.MemoryLength) { Complete = FALSE; }
      else if (Intersects (A->AllocDescriptor.MemoryBaseAddress, A->AllocDescriptor.MemoryLength)) {
        if (++Rows <= MAX_ROWS) {
          BOOLEAN NameZero=TRUE;
          for(UINTN N=0;N<sizeof(EFI_GUID);N++)if(((UINT8 *)&A->AllocDescriptor.Name)[N]!=0)NameZero=FALSE;
          if(A->AllocDescriptor.MemoryBaseAddress==KERNEL_START &&
             A->AllocDescriptor.MemoryLength==KERNEL_BYTES &&
             A->AllocDescriptor.MemoryType==EfiReservedMemoryType && NameZero)StaticHobs++;
          R ("K133_hob_alloc base=%lx bytes=%lx type=%u name=%g static_kernel_bounds=%u\n",
            A->AllocDescriptor.MemoryBaseAddress, A->AllocDescriptor.MemoryLength,
            A->AllocDescriptor.MemoryType, &A->AllocDescriptor.Name,
            A->AllocDescriptor.MemoryBaseAddress == KERNEL_START && A->AllocDescriptor.MemoryLength == KERNEL_BYTES);
        } else { Complete = FALSE; }
      }
    } else if (H->HobType == EFI_HOB_TYPE_FV || H->HobType == EFI_HOB_TYPE_FV2) {
      if (H->HobLength < sizeof (*F)) { Complete = FALSE; break; }
      F = (VOID *)H;
      if (F->BaseAddress > MAX_UINT64-F->Length) { Complete = FALSE; }
      else if (Intersects (F->BaseAddress, F->Length)) {
        if (++Rows <= MAX_ROWS) { R ("K133_hob_fv base=%lx bytes=%lx type=%u\n", F->BaseAddress, F->Length, H->HobType); }
        else { Complete = FALSE; }
      }
    }
    HobBytes += H->HobLength;
    H = (VOID *)((UINT8 *)H+H->HobLength);
  }
  HobOverlapRows=Rows;
  if (!HobEnd) { Complete = FALSE; }
  R ("K133_hob_count=%lu walked_bytes=%lu overlaps=%lu end=%u\n", (UINT64)Hobs, (UINT64)HobBytes, (UINT64)Rows, HobEnd);

  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiLoadedImageProtocolGuid, NULL, &Count, &Handles);
  HandlesOwned = !EFI_ERROR (Status) && Handles != NULL;
  R ("K133_images_status=%r count=%lu\n", Status, (UINT64)Count);
  if (EFI_ERROR (Status) || Count > 512 || (Count != 0 && Handles == NULL)) { Complete = FALSE; }
  else {
    for (I = 0; I < Count; I++) {
      Image = NULL;
      Status = gBS->HandleProtocol (Handles[I], &gEfiLoadedImageProtocolGuid, (VOID **)&Image);
      if (EFI_ERROR (Status) || Image == NULL || (UINTN)Image->ImageBase > MAX_UINT64-Image->ImageSize) { ImageFailures++; continue; }
      if (Intersects ((UINTN)Image->ImageBase, Image->ImageSize)) {
        ImageOverlaps++;
        if (ImageOverlaps <= MAX_ROWS) { R ("K133_image base=%p bytes=%lx handle=%p\n", Image->ImageBase, Image->ImageSize, Handles[I]); }
        else { Complete = FALSE; }
      }
    }
    if (ImageFailures != 0) { Complete = FALSE; }
  }
  if (HandlesOwned) { FreePool (Handles); }
  R ("K133_image_overlaps=%lu failures=%lu\n", (UINT64)ImageOverlaps, (UINT64)ImageFailures);
  ObjectsClear = Object (R, "SystemTable", gST, sizeof (*gST)) && ObjectsClear;
  ObjectsClear = Object (R, "BootServices", gBS, sizeof (*gBS)) && ObjectsClear;
  ObjectsClear = Object (R, "DxeServices", gDS, sizeof (*gDS)) && ObjectsClear;
  ObjectsClear = Object (R, "RuntimeServices", gST->RuntimeServices, sizeof (EFI_RUNTIME_SERVICES)) && ObjectsClear;
  Rows=0;
  if (gST->NumberOfTableEntries > 1024 ||
      (gST->NumberOfTableEntries != 0 && gST->ConfigurationTable == NULL)) { Complete = FALSE; }
  else {
    ObjectsClear = Object (R, "ConfigTableArray", gST->ConfigurationTable,
            gST->NumberOfTableEntries * sizeof (EFI_CONFIGURATION_TABLE)) && ObjectsClear;
    Rows = 0;
    for (I = 0; I < gST->NumberOfTableEntries; I++) {
      if (Intersects ((UINTN)gST->ConfigurationTable[I].VendorTable, 1)) {
        if (++Rows <= MAX_ROWS) {
          R ("K133_config_pointer guid=%g table=%p object_bytes=unknown\n",
             &gST->ConfigurationTable[I].VendorGuid, gST->ConfigurationTable[I].VendorTable);
        } else { Complete = FALSE; }
      }
    }
  }
  mInventoryMatch=Complete && GoodCompiled==1 && GoodGcd==1 && GoodEfi==1 &&
    StaticHobs==1 && HobOverlapRows==1 && ImageOverlaps==0 && ImageFailures==0 &&
    ObjectsClear && Rows==0 && ScmMapCandidate;
  R("G134_inventory_policy matched=%u CPU_permissions=not_queried DMA_ownership=not_proved\n",mInventoryMatch);
  R ("K133_DONE queries_complete=%u PAS_allowed=0 DMA_ownership=not_proved region_writes=0\n", Complete);
}
