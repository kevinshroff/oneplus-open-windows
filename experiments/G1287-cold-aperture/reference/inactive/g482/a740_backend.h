/* SPDX-License-Identifier: MIT */
#pragma once
#include "a740_hal.h"
/* Real WDDM StartDevice callpoint. Initial composition discovers HAL support
 * and refuses render start until actual owner/GMU/CP/rendering qualification. */
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

#include "g321_runtime.h"
/* Real G196->S1/MDL->G190 path, invoked only by a future actual stopped board
 * owner. StartDevice cannot fabricate that owner; rendering remains withheld. */
NTSTATUS A740PrepareGmu(const ULONG *Inputs,ULONG Count,const G321_OWNER *Owner,
 const g196_inputs *Buffers,const G482_BOARD_INPUT *Board,ULONGLONG Generation,ULONGLONG StopSerial);
NTSTATUS A740RunGmu(VOID);
NTSTATUS A740ReleaseGmuStopped(ULONGLONG FreshStopSerial);

#include "g433_runtime.h"
NTSTATUS A740PrepareCp(const ULONG *,ULONG,const G433_GPU_OPS *,const UCHAR *,SIZE_T,ULONGLONG);
NTSTATUS A740RunCp(VOID);
NTSTATUS A740ReleaseCpStopped(ULONGLONG);

NTSTATUS A740QualifyRuntime(const G321_OWNER *,ULONGLONG Generation,ULONGLONG StopSerial);
