/* SPDX-License-Identifier: MIT -- fixed native diagnostic ABI. */
#ifndef G91_PROTOCOL_H
#define G91_PROTOCOL_H
#include <stdint.h>
#include "g91_power.h"
#define G91_ABI 1u
#define G91_MAGIC UINT64_C(0x314c43313947504f)
#define G91_IOCTL_STATUS UINT32_C(0x226a00)
#define G91_IOCTL_SNAPSHOT UINT32_C(0x226a04)
#define G91_IOCTL_PMIC UINT32_C(0x226a08)
#define G91_IOCTL_RUN UINT32_C(0x22ea0c)
#define G91_IOCTL_RESULT UINT32_C(0x226a10)
typedef struct {uint32_t Size,Version;uint64_t Magic,Nonce;}G91_REQUEST;
typedef struct {
 uint32_t Size,Version;uint64_t Magic;
 uint32_t KernelBuild,Processors,CurrentIrql,FirmwareBytes,FirmwareMatch,RegisterCount,FirmwareStatus,MapCalls;
 uint64_t Sequence,InterruptTime;uint8_t BuildId[16];
 uint32_t RunAttempts,ObserverCaptures,ObserverFault,OffPmicVerified;
}G91_STATUS;
typedef struct {G91_STATUS Status;uint32_t Count,Reserved,Values[50];}G91_SNAPSHOT;
typedef struct {G91_STATUS Status;G91_OBS_RESULT Observer;uint32_t FixedRegistersUnchanged,Attempt,Reserved;uint64_t ElapsedTicks,CounterFrequency;}G91_PMIC;
typedef struct {
 G91_STATUS Status;uint64_t Nonce;G91_POWER_RESULT Power;
 uint32_t Before[50],After[50],BaselineValid,FixedRegistersUnchanged,Attempt,Reserved;
 uint64_t ElapsedTicks,CounterFrequency;
}G91_RUN;
_Static_assert(sizeof(G91_REQUEST)==24,"G91 request");
_Static_assert(sizeof(G91_STATUS)==96,"G91 status");
_Static_assert(sizeof(G91_SNAPSHOT)==304,"G91 snapshot");
_Static_assert(sizeof(G91_PMIC)==1744,"G91 PMIC");
_Static_assert(sizeof(G91_POWER_RESULT)==44308,"G91 supply lease core");
_Static_assert(sizeof(G91_RUN)==44848,"G91 frozen raw result");
#endif
