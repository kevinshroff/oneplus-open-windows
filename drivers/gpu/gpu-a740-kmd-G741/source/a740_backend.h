/* SPDX-License-Identifier: MIT */
#pragma once
#include "a740_hal.h"
/* Real WDDM StartDevice callpoint. Initial composition discovers HAL support
 * and refuses render start until the missing boot/GMU/CP stages exist. */
NTSTATUS A740RequirePoweredHandoff(PCM_RESOURCE_LIST Resources);
NTSTATUS A740BindDevice(PDEVICE_OBJECT Pdo, PCM_RESOURCE_LIST Translated);
NTSTATUS A740OpenMappedRoles(const ULONG *GpuInputs,ULONG GpuCount,
    const ULONG *GmuInputs,ULONG GmuCount,IOMMU_DMA_DOMAIN_TYPE Type);
NTSTATUS A740LastStatus(VOID);
NTSTATUS A740ReleaseProbe(VOID);
ULONGLONG A740ChipId(VOID);
NTSTATUS A740GpuId(PULONGLONG Value);
/* Real boot owner will call this stage after upstream rails/clock ownership is
 * established, not from a caller-supplied success bit. It only reads OS-granted
 * clock resources, never enables domains/rails or reads GPU/SMMU apertures. */
NTSTATUS A740ReadPoweredClockResources(VOID);
