/* SPDX-License-Identifier: MIT -- fixed native diagnostic ABI. */
#ifndef G89_PROTOCOL_H
#define G89_PROTOCOL_H
#include <stdint.h>
#include "g89_power.h"
#define G89_ABI 1u
#define G89_MAGIC UINT64_C(0x314c43393847504f)
#define G89_IOCTL_STATUS UINT32_C(0x226a00)
#define G89_IOCTL_SNAPSHOT UINT32_C(0x226a04)
#define G89_IOCTL_PMIC UINT32_C(0x226a08)
#define G89_IOCTL_RUN UINT32_C(0x22ea0c)
#define G89_IOCTL_RESULT UINT32_C(0x226a10)
typedef struct {uint32_t Size,Version;uint64_t Magic,Nonce;}G89_REQUEST;
typedef struct {
 uint32_t Size,Version;uint64_t Magic;
 uint32_t KernelBuild,Processors,CurrentIrql,FirmwareBytes,FirmwareMatch,RegisterCount,FirmwareStatus,MapCalls;
 uint64_t Sequence,InterruptTime;uint8_t BuildId[16];
 uint32_t RunAttempts,ObserverCaptures,ObserverFault,OffPmicVerified;
}G89_STATUS;
typedef struct {G89_STATUS Status;uint32_t Count,Reserved,Values[50];}G89_SNAPSHOT;
typedef struct {G89_STATUS Status;G89_OBS_RESULT Observer;uint32_t FixedRegistersUnchanged,Attempt,Reserved;uint64_t ElapsedTicks,CounterFrequency;}G89_PMIC;
typedef struct {
 G89_STATUS Status;uint64_t Nonce;G89_POWER_RESULT Power;
 uint32_t Before[50],After[50],BaselineValid,FixedRegistersUnchanged,Attempt,Reserved;
 uint64_t ElapsedTicks,CounterFrequency;
}G89_RUN;
_Static_assert(sizeof(G89_REQUEST)==24,"G89 request");
_Static_assert(sizeof(G89_STATUS)==96,"G89 status");
_Static_assert(sizeof(G89_SNAPSHOT)==304,"G89 snapshot");
_Static_assert(sizeof(G89_PMIC)==1744,"G89 PMIC");
_Static_assert(sizeof(G89_POWER_RESULT)==44308,"G89 supply lease core");
_Static_assert(sizeof(G89_RUN)==44848,"G89 frozen raw result");
#endif
