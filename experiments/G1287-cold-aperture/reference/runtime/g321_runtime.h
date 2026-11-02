/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#pragma once
#include "a740_hal.h"
#include "g196_preflight.h"
#include "g321_plan.h"
#include "g482_board.h"
/* Every callback must come from the actual exclusive resource/power owner.
 * Enter/Leave acquire its D0 + callback-rundown exclusion, not just a success
 * flag. Callbacks run at PASSIVE under our bounded mutex and cannot re-enter.
 * Enter/Lease must prove current upstream register/TCM access power/clocks
 * before any read. G482 supplies concrete stopped/FW-ready board setup.
 * Stopped must cover DMA/TLB drain and callback retirement, never just reset1.
 * ValidateBacking proves native4KiB domain/cache compatibility for the actual
 * owned MDL; MmNonCached allocation alone is insufficient evidence.
 * Storage/context must remain pinned until successful release or full reset. */
typedef struct {
 void *Cookie;
 NTSTATUS (*Enter)(void *,ULONGLONG generation);
 VOID (*Leave)(void *);
 NTSTATUS (*Lease)(void *,ULONGLONG generation);
 NTSTATUS (*Stopped)(void *,ULONGLONG serial,ULONGLONG generation);
 /* Enter/Lease additionally prove actual chip/speed-bin applicability,
  * source GMU220/hub200MHz and preboot DDR/interconnect/provider ownership.
  * No current producer is supplied by this source capsule. */
 NTSTATUS (*ValidateBacking)(void *,PMDL,PVOID,ULONGLONG,SIZE_T);
} G321_OWNER;
typedef struct {PMDL Mdl;PVOID Cpu;BOOLEAN MapAttempted,Mapped;} G321_BUFFER;
typedef struct G321_RUNTIME {
 KMUTEX Lock;volatile LONG Cancelled;
 G482_BINDING *Io;G482_BOARD_REPORT Board;UCHAR RscCode[20];BOOLEAN BoardAdmitted;
 A740_HAL_ROLE Role;G321_OWNER Owner;g321_plan Plan;
 G321_BUFFER Buffer[G321_MAX_EXTENTS];
 g196_preflight Inputs;g190_backend Core;
 ULONG InputIds[A740_HAL_MAX_ROLE_INPUTS],InputCount;
 PUCHAR ImageCopy;ULONGLONG Generation,StopSerial;
 NTSTATUS LastStatus;g190_status CoreStatus;
 BOOLEAN Initialized,Attempted,Prepared,MastersMayRun,Poisoned,Closed;
 /* Native preboot copy only: full hardware revalidation every<=64 words.
  * Appended storage; no generic backend/ops ABI or existing Core offset change. */
 ULONG LoadWordsLeft,LoadRegion,LoadNextOffset,LoadWrite;
} G321_RUNTIME;
VOID G321Initialize(G321_RUNTIME *);
/* No guessed stream IDs: every selected ID must have actual successful probe
 * create/delete + managed-S1 mask. Inputs are checked by the real G196 adapter.
 * No fallback to managed-S2, caller tables, passthrough or raw SMMU registers. */
NTSTATUS G321Prepare(G321_RUNTIME *,A740_HAL *,const ULONG *,ULONG,
 const G321_OWNER *,const g196_inputs *,G482_BINDING *,const G482_BOARD_INPUT *,ULONGLONG generation,ULONGLONG stop_serial);
NTSTATUS G321Start(G321_RUNTIME *);
VOID G321Cancel(G321_RUNTIME *);
/* Fresh external stop/rundown witness required even after a failed run.
 * Uncertain HAL failures remain poisoned until full-reset recovery. */
NTSTATUS G321ReleaseStopped(G321_RUNTIME *,ULONGLONG fresh_stop_serial);
