/* SPDX-License-Identifier: MIT -- fixed native diagnostic ABI. */
#ifndef G93_PROTOCOL_H
#define G93_PROTOCOL_H
#include <stdint.h>
#include "g93_power.h"
#define G93_ABI 1u
#define G93_MAGIC UINT64_C(0x314c43333947504f)
#define G93_IOCTL_STATUS UINT32_C(0x226a00)
#define G93_IOCTL_SNAPSHOT UINT32_C(0x226a04)
#define G93_IOCTL_PMIC UINT32_C(0x226a08)
#define G93_IOCTL_RUN UINT32_C(0x22ea0c)
#define G93_IOCTL_RESULT UINT32_C(0x226a10)
typedef struct {uint32_t Size,Version;uint64_t Magic,Nonce;}G93_REQUEST;
typedef struct {
 uint32_t Size,Version;uint64_t Magic;
 uint32_t KernelBuild,Processors,CurrentIrql,FirmwareBytes,FirmwareMatch,RegisterCount,FirmwareStatus,MapCalls;
 uint64_t Sequence,InterruptTime;uint8_t BuildId[16];
 uint32_t RunAttempts,ObserverCaptures,ObserverFault,OffPmicVerified;
}G93_STATUS;
typedef struct {G93_STATUS Status;uint32_t Count,Reserved,Values[50];}G93_SNAPSHOT;
typedef struct {G93_STATUS Status;G93_OBS_RESULT Observer;uint32_t FixedRegistersUnchanged,Attempt,Reserved;uint64_t ElapsedTicks,CounterFrequency;}G93_PMIC;
typedef struct {
 G93_STATUS Status;uint64_t Nonce;G93_POWER_RESULT Power;
 uint32_t Before[50],After[50],BaselineValid,FixedRegistersUnchanged,Attempt,Reserved;
 uint64_t ElapsedTicks,CounterFrequency;
}G93_RUN;
_Static_assert(sizeof(G93_REQUEST)==24,"G93 request");
_Static_assert(sizeof(G93_STATUS)==96,"G93 status");
_Static_assert(sizeof(G93_SNAPSHOT)==304,"G93 snapshot");
_Static_assert(sizeof(G93_PMIC)==1744,"G93 PMIC");
_Static_assert(sizeof(G93_POWER_RESULT)==44308,"G93 supply lease core");
_Static_assert(sizeof(G93_RUN)==44848,"G93 frozen raw result");
#endif
