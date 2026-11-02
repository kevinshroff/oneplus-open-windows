/* SPDX-License-Identifier: MIT
 * Fixed read-only kernel RESULT transport. WDF-managed request buffers retain
 * their lifetime across timeout/cancel and target deletion. Caller is PASSIVE
 * and serializes the parent device. This does not acquire a hardware lease.
 */
#ifndef OPEN_CHARGE_PROVIDER_IO_H
#define OPEN_CHARGE_PROVIDER_IO_H
#include "health_capture.h"
typedef struct {
 uint32_t Stage,FailedStage,ValidationAttempted,Valid;
 uint32_t CreatedMask,OpenedMask,SentMask,ReceivedMask,ClosedMask,DeletedMask;
 uint32_t ManagedBuffers,HealthCode,LastStatus,SendStatus[2],ReceivedBytes[2];
 uint32_t Reserved;
 uint64_t Begin100ns,Validation100ns,End100ns;
 CH_HEALTH Health;
}CH_IO_RESULT;
NTSTATUS ChReadKernelHealth(WDFDEVICE parent,uint64_t nonce,uint64_t oldNonce,
 uint64_t oldTime,uint32_t role,CH_IO_RESULT*out);
#endif
