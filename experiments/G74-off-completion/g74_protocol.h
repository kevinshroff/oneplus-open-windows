/* SPDX-License-Identifier: MIT -- fixed native diagnostic ABI. */
#ifndef G74_PROTOCOL_H
#define G74_PROTOCOL_H
#include <stdint.h>
#include "g74_power.h"
#define G74_ABI 1u
#define G74_MAGIC UINT64_C(0x31464f343747504f)
#define G74_IOCTL_STATUS UINT32_C(0x226a00)
#define G74_IOCTL_SNAPSHOT UINT32_C(0x226a04)
#define G74_IOCTL_PMIC UINT32_C(0x226a08)
#define G74_IOCTL_RUN UINT32_C(0x22ea0c)
#define G74_IOCTL_RESULT UINT32_C(0x226a10)
typedef struct {uint32_t Size,Version;uint64_t Magic,Nonce;}G74_REQUEST;
typedef struct {
 uint32_t Size,Version;uint64_t Magic;
 uint32_t KernelBuild,Processors,CurrentIrql,FirmwareBytes,FirmwareMatch,RegisterCount,FirmwareStatus,MapCalls;
 uint64_t Sequence,InterruptTime;uint8_t BuildId[16];
 uint32_t RunAttempts,ObserverCaptures,ObserverFault,OffPmicVerified;
}G74_STATUS;
typedef struct {G74_STATUS Status;uint32_t Count,Reserved,Values[50];}G74_SNAPSHOT;
typedef struct {G74_STATUS Status;G74_OBS_RESULT Observer;uint32_t FixedRegistersUnchanged,Attempt,Reserved;uint64_t ElapsedTicks,CounterFrequency;}G74_PMIC;
typedef struct {
 G74_STATUS Status;uint64_t Nonce;G74_OFF_RESULT Off;
 uint32_t Before[50],After[50],BaselineValid,FixedRegistersUnchanged,Attempt,Reserved;
 uint64_t ElapsedTicks,CounterFrequency;
}G74_RUN;
_Static_assert(sizeof(G74_REQUEST)==24,"G74 request");
_Static_assert(sizeof(G74_STATUS)==96,"G74 status");
_Static_assert(sizeof(G74_SNAPSHOT)==304,"G74 snapshot");
_Static_assert(sizeof(G74_PMIC)==1744,"G74 PMIC");
_Static_assert(sizeof(G74_OFF_RESULT)==44192,"G74 OFF core");
_Static_assert(sizeof(G74_RUN)==44728,"G74 frozen raw result");
#endif
