#pragma once
#include <ntifs.h>
#include "open_smmu_activate.h"
#include "../reference/inactive/source/g321_inactive.h"
/* Caller holds the real active-owner exclusion and reference/rundown for all
 * operations. A binding owns one reference; each native mapping owns another.
 * Close the disabled/never-mutated IO mapping before retiring its binding.
 * Old inactive-only callbacks/context cannot serve as the active producer. */
typedef struct {
 OSMA_SESSION Session;OSMI_TABLES Tables;G321_BUFFER Buffer[G321_MAX_EXTENTS];
 g321_plan Plan;g196_preflight Inputs;
 ULONG AllocatedNcMask,MappedNcMask;MEMORY_CACHING_TYPE AllocationCache[G321_MAX_EXTENTS],MappingCache[G321_MAX_EXTENTS];PUCHAR ImageCopy;PDEVICE_OBJECT ConsumerPdo;
 ULONGLONG Generation,StopSerial;volatile LONG References;BOOLEAN ActivationAttempted,Disabled,Poisoned;
}OSMA_TABLE_BINDING;
typedef struct {
 PUCHAR Base;PDEVICE_OBJECT Pdo;OSMA_PROOFS Proof;OSMA_TABLE_BINDING *Tables;
 ULONG Bank,Slot;ArmSmmu4KIo Io;
}OSMA_NATIVE_IO;
/* Real RAM ownership move: source's closed/cleared ledger can no longer free
 * these pages. Does NOT manufacture active stop, D0, bank, security or PAS. */
NTSTATUS OsmaTakeInactiveTables(G321_INACTIVE_RUNTIME *,PDEVICE_OBJECT,OSMA_TABLE_BINDING **);
/* Actual translated RW/exclusive START grant + real active proof references.
 * Creates its own bounded NC MMIO mapping only after proof validation; no
 * hardware access occurs here. Existing clock-only RO map is not reused. */
NTSTATUS OsmaOpenNativeIo(OSMA_NATIVE_IO *,PDEVICE_OBJECT,PCM_RESOURCE_LIST,
 OSMA_TABLE_BINDING *,const OSMA_PROOFS *,ULONG Bank,ULONG Slot);
NTSTATUS OsmaActivateOwnedBinding(OSMA_NATIVE_IO *);
NTSTATUS OsmaDisableOwnedBindingStopped(OSMA_NATIVE_IO *,ULONGLONG FreshPhysicalStopSerial);
NTSTATUS OsmaCloseNativeIo(OSMA_NATIVE_IO *);
NTSTATUS OsmaFreeRetiredBinding(OSMA_TABLE_BINDING *);
NTSTATUS OsmaWitnessOwnedBindingHeld(OSMA_NATIVE_IO*);
