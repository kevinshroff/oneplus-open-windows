/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#pragma once
#include "open_smmu_inactive.h"
/* Reuse the existing real owner callbacks, buffer ledger and image plan.
 * Including the original header supplies types only; this successor never
 * acquires/calls the public HAL API or old G321Prepare/Start implementation.
 * Existing Enter/Leave/Lease/Stopped callbacks are retained. ValidateBacking
 * is deliberately not required for an inactive candidate: actual owned NC
 * allocation/PFN checks replace that missing domain-dependent callback, while
 * active cache/TCR policy remains unqualified and cannot be published. */
#include "g321_runtime.h"
typedef struct {
 KMUTEX Lock;G321_OWNER Owner;g321_plan Plan;g196_preflight Inputs;
 G321_BUFFER Buffer[G321_MAX_EXTENTS];OSMI_TABLES Tables;
 ULONG AllocatedNcMask,MappedNcMask;MEMORY_CACHING_TYPE AllocationCache[G321_MAX_EXTENTS],MappingCache[G321_MAX_EXTENTS];
 PUCHAR ImageCopy;ULONGLONG Generation,StopSerial;NTSTATUS LastStatus;
 BOOLEAN Initialized,Attempted,TablesPrepared,Poisoned,Closed;
} G321_INACTIVE_RUNTIME;
VOID G321InactiveInitialize(G321_INACTIVE_RUNTIME *);
NTSTATUS G321PrepareInactive(G321_INACTIVE_RUNTIME *,const G321_OWNER *,
 const g196_inputs *,ULONGLONG Generation,ULONGLONG StopSerial);
NTSTATUS G321ReleaseInactiveStopped(G321_INACTIVE_RUNTIME *,ULONGLONG FreshStopSerial);
/* Deliberate hard boundary: no active context, GMU/HFI startup or success path. */
NTSTATUS G321InactiveActivationStatus(const G321_INACTIVE_RUNTIME *);
