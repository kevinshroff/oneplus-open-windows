/* SPDX-License-Identifier: MIT. No active translation or hardware operation. */
#pragma once
#include <ntddk.h>
#include "vendor/ArmSmmu4K.h"
#include "vendor/ArmSmmu4KAudit.h"
#define OSMI_MAX_INPUTS 16u
#define OSMI_MAX_LEAVES 16384u
#define OSMI_PA_LIMIT (UINT64_C(1)<<36)
enum osmi_state {OSMI_NEW,OSMI_BUILDING,OSMI_BUILT,OSMI_POISONED,OSMI_CLOSED};
typedef struct {PMDL Mdl;UINT64 Iova;SIZE_T Bytes;} OSMI_INPUT;
/* Caller owns/retains genuine immutable locked MDLs under existing G321
 * stopped-owner exclusion. MDLs are not object-manager-referenceable objects:
 * ownership remains in G321's allocation ledger until successful destruction.
 * Never hand this candidate pool/root to hardware. There is NO publish API.
 */
typedef struct {
 enum osmi_state State;
 PVOID Pool;PHYSICAL_ADDRESS PoolPhysical;SIZE_T PoolBytes;
 MEMORY_CACHING_TYPE PoolCache;ULONG PoolOrigin;
 ArmSmmu4KRange *Ranges;SIZE_T RangeCount;
 UCHAR *Visited;
 ArmSmmu4KConfig Config;ArmSmmu4KResult Tables;
 ArmSmmu4KTableAuditResult Audit;
 NTSTATUS Status;
 /* Always FALSE: active TCR/cache-walk/secure CB policy is not qualified. */
 BOOLEAN ActivationQualified;
} OSMI_TABLES;
/* Constructor for fresh storage only; never reset a retained/live object. */
VOID OsmiInitialize(OSMI_TABLES *);
NTSTATUS OsmiBuildInactive(OSMI_TABLES *,const OSMI_INPUT *,ULONG Count);
NTSTATUS OsmiAuditInactive(OSMI_TABLES *);
/* No hardware has ever received this root. Poisoned storage stays retained. */
NTSTATUS OsmiDestroyInactive(OSMI_TABLES *);
