/* SPDX-License-Identifier: MIT
 * Original experimental Windows HAL adapter. No private SMMU register writes.
 */
#pragma once
#include <ntddk.h>
#define A740_HAL_MAX_INPUTS 64
#define A740_HAL_MAX_ROLE_INPUTS 4
#define A740_HAL_TAG 'H047'
typedef struct {
    ULONG InputId, AvailableDomainTypes, Attempted;
    NTSTATUS CreateStatus, DeleteStatus;
} A740_HAL_INPUT;
typedef struct {
    ULONG Phase, Count;
    NTSTATUS Status;
    A740_HAL_INPUT Input[A740_HAL_MAX_INPUTS];
} A740_HAL_REPORT;
typedef struct {
    DMA_IOMMU_INTERFACE_EX Api;
    PDEVICE_OBJECT Pdo;
    A740_HAL_REPORT Report;
    PIOMMU_DMA_DEVICE ProbeRetained;
} A740_HAL;
typedef struct {
    A740_HAL *Hal;
    PIOMMU_DMA_DOMAIN Domain;
    PIOMMU_DMA_DEVICE Device[A740_HAL_MAX_ROLE_INPUTS];
    ULONG Count, Attached, Type, Mappings;
    BOOLEAN Poisoned;
} A740_HAL_ROLE;
/* PASSIVE, caller serialized. No MMIO, mapping, domain attach or power action. */
NTSTATUS A740HalDiscover(A740_HAL *Hal, PDEVICE_OBJECT Pdo);
/* Only call after the selected boot owner has stopped the actual masters.
 * IDs must be observed from QueryInputMappings AND selected by reviewed current
 * IORT role mapping. This API never guesses SID==InputMappingId.
 * No fallback, bypass mapping, unknown-device detach, or whole-RAM mapping.
 * On any partial attach failure retain role/handles for explicit cold-reset
 * recovery. Caller may release only before masters start or after real stop. */
NTSTATUS A740HalOpenRole(A740_HAL_ROLE *Role, A740_HAL *Hal,
    const ULONG *InputIds, ULONG Count, IOMMU_DMA_DOMAIN_TYPE Type);
/* Explicit IOVA mapping of a retained owned whole-page MDL. Permissions: bit0
 * device read, bit1 device write. No CPU cache ownership change is implied. */
NTSTATUS A740HalMap(A740_HAL_ROLE *Role, PMDL Mdl, ULONGLONG Iova,
                    SIZE_T Bytes, ULONG Permissions);
NTSTATUS A740HalUnmap(A740_HAL_ROLE *Role, ULONGLONG Iova, SIZE_T Bytes);
/* Requires genuinely stopped master(s), all mappings already removed. */
NTSTATUS A740HalCloseStopped(A740_HAL_ROLE *Role);
