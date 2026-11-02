/* SPDX-License-Identifier: MIT -- fixed native diagnostic ABI. */
#ifndef G90_PROTOCOL_H
#define G90_PROTOCOL_H
#include <stdint.h>
#include "g90_power.h"
#define G90_ABI 1u
#define G90_MAGIC UINT64_C(0x314c43303947504f)
#define G90_IOCTL_STATUS UINT32_C(0x226a00)
#define G90_IOCTL_SNAPSHOT UINT32_C(0x226a04)
#define G90_IOCTL_PMIC UINT32_C(0x226a08)
#define G90_IOCTL_RUN UINT32_C(0x22ea0c)
#define G90_IOCTL_RESULT UINT32_C(0x226a10)
typedef struct {uint32_t Size,Version;uint64_t Magic,Nonce;}G90_REQUEST;
typedef struct {
 uint32_t Size,Version;uint64_t Magic;
 uint32_t KernelBuild,Processors,CurrentIrql,FirmwareBytes,FirmwareMatch,RegisterCount,FirmwareStatus,MapCalls;
 uint64_t Sequence,InterruptTime;uint8_t BuildId[16];
 uint32_t RunAttempts,ObserverCaptures,ObserverFault,OffPmicVerified;
}G90_STATUS;
typedef struct {G90_STATUS Status;uint32_t Count,Reserved,Values[50];}G90_SNAPSHOT;
typedef struct {G90_STATUS Status;G90_OBS_RESULT Observer;uint32_t FixedRegistersUnchanged,Attempt,Reserved;uint64_t ElapsedTicks,CounterFrequency;}G90_PMIC;
typedef struct {
 G90_STATUS Status;uint64_t Nonce;G90_POWER_RESULT Power;
 uint32_t Before[50],After[50],BaselineValid,FixedRegistersUnchanged,Attempt,Reserved;
 uint64_t ElapsedTicks,CounterFrequency;
}G90_RUN;
_Static_assert(sizeof(G90_REQUEST)==24,"G90 request");
_Static_assert(sizeof(G90_STATUS)==96,"G90 status");
_Static_assert(sizeof(G90_SNAPSHOT)==304,"G90 snapshot");
_Static_assert(sizeof(G90_PMIC)==1744,"G90 PMIC");
_Static_assert(sizeof(G90_POWER_RESULT)==44308,"G90 supply lease core");
_Static_assert(sizeof(G90_RUN)==44848,"G90 frozen raw result");
#endif
