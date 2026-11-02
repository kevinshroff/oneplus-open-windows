/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#pragma once
#include "g321_runtime.h"
#include "g433_cp.h"
#include "g440_gpu_power.h"
#include "g456_hwinit.h"
typedef struct {ULONGLONG Iova[4];SIZE_T Bytes[4];} G433_LAYOUT;
/* Extensions to the SAME G321_OWNER.Cookie, exclusion and power generation.
 * No implementation is supplied by StartDevice. These must be real owner
 * operations; success flags, raw SMMU setup and guessed stream IDs are invalid. */
typedef struct {
 /* Cold/reset-qualified first bring-up only: no previous CP release or
  * foreign GPU context in this generation; actual DMA/TLB/IRQ/rundown stop.
  * Re-proved after OOB/GX acquisition before concrete G456 register setup. */
 NTSTATUS (*GpuStopped)(void *,ULONGLONG fresh_serial,ULONGLONG generation);
 /* Concrete current-owner board facts; no implicit DDR/cache/security profile. */
 G456_FACTS Board;
 /* Invoked only after actual CP_ME_INIT fence1, before secure-mode packet.
  * Actual selected ZAP authentication/PAS13 ownership; no raw SMC fallback.
  * Callback may not reenter this runtime or release its owner exclusion. */
 NTSTATUS (*AuthenticateZap)(void *,ULONGLONG generation);
 NTSTATUS (*ReadGpuRegister)(void *,ULONG byte_offset,PULONG);
 NTSTATUS (*WriteGpuRegister)(void *,ULONG byte_offset,ULONG);
 NTSTATUS (*AhbFenceStatus)(void *,PULONG);
} G433_GPU_OPS;
typedef struct G433_RUNTIME {
 KMUTEX Lock;volatile LONG Cancelled;G321_RUNTIME *Gmu;G433_GPU_OPS Gpu;
 A740_HAL_ROLE Role;G321_BUFFER Buffer[4];G433_LAYOUT Layout;g433_cp Core;g440_gpu_power Power;G456_REPORT Hwinit;
 ULONGLONG Generation,StopSerial;NTSTATUS LastStatus;
 BOOLEAN Initialized,Attempted,Prepared,RunAttempted,MastersMayRun,Poisoned,Closed;
} G433_RUNTIME;
VOID G433Initialize(G433_RUNTIME *);
/* SQE input is a retained nonpaged kernel file buffer, never a user pointer. */
NTSTATUS G433Prepare(G433_RUNTIME *,G321_RUNTIME *,A740_HAL *,const ULONG *,ULONG,
 const G433_GPU_OPS *,const UCHAR *sqe_file,SIZE_T file_bytes,ULONGLONG fresh_gpu_stop_serial);
NTSTATUS G433Run(G433_RUNTIME *);
VOID G433Cancel(G433_RUNTIME *);
NTSTATUS G433ReleaseStopped(G433_RUNTIME *,ULONGLONG fresh_gpu_stop_serial);
/* Caller serializes the composition; lock order CP -> GMU -> actual owner.
 * Release CP before G321. No user submission/readiness follows CP init alone. */
