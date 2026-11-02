/* Supplemental resource description only: no hardware or partition writes. */
#include <Uefi.h>
#include <Protocol/AcpiTable.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include "OpenPlatformResourcesAml.h"
VOID OpenPublishPlatformResources(VOID)
{
 STATIC BOOLEAN Attempted = FALSE;
 EFI_ACPI_TABLE_PROTOCOL *Acpi;
 EFI_STATUS Status;
 VOID *Copy;
 UINTN Key = 0, I;
 UINT8 Sum = 0;
 if (Attempted) { return; }
 Attempted = TRUE;
 for (I = 0; I < sizeof(mPlatformResources); I++) { Sum = (UINT8)(Sum + mPlatformResources[I]); }
 if (Sum != 0 || sizeof(mPlatformResources) != 376) { return; }
 Status = gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid, NULL, (VOID **)&Acpi);
 if (EFI_ERROR(Status)) { return; }
 Copy = AllocateCopyPool(sizeof(mPlatformResources), mPlatformResources);
 if (Copy == NULL) { return; }
 Status = Acpi->InstallAcpiTable(Acpi, Copy, sizeof(mPlatformResources), &Key);
 FreePool(Copy);
 DEBUG((DEBUG_INFO, "G182 supplementary resources status=%r bytes=376 producer_qualified=0\n", Status));
}
