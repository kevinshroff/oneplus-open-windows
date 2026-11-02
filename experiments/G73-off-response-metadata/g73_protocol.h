/* SPDX-License-Identifier: MIT -- fixed native diagnostic ABI. */
#ifndef G73_PROTOCOL_H
#define G73_PROTOCOL_H
#include <stdint.h>
#include "g73_power.h"
#define G73_ABI 1u
#define G73_MAGIC UINT64_C(0x31464f333747504f)
#define G73_IOCTL_STATUS UINT32_C(0x226a00)
#define G73_IOCTL_SNAPSHOT UINT32_C(0x226a04)
#define G73_IOCTL_PMIC UINT32_C(0x226a08)
#define G73_IOCTL_RUN UINT32_C(0x22ea0c)
#define G73_IOCTL_RESULT UINT32_C(0x226a10)
typedef struct {uint32_t Size,Version;uint64_t Magic,Nonce;}G73_REQUEST;
typedef struct {
 uint32_t Size,Version;uint64_t Magic;
 uint32_t KernelBuild,Processors,CurrentIrql,FirmwareBytes,FirmwareMatch,RegisterCount,FirmwareStatus,MapCalls;
 uint64_t Sequence,InterruptTime;uint8_t BuildId[16];
 uint32_t RunAttempts,ObserverCaptures,ObserverFault,OffPmicVerified;
}G73_STATUS;
typedef struct {G73_STATUS Status;uint32_t Count,Reserved,Values[50];}G73_SNAPSHOT;
typedef struct {G73_STATUS Status;G73_OBS_RESULT Observer;uint32_t FixedRegistersUnchanged,Attempt,Reserved;uint64_t ElapsedTicks,CounterFrequency;}G73_PMIC;
typedef struct {
 G73_STATUS Status;uint64_t Nonce;G73_OFF_RESULT Off;
 uint32_t Before[50],After[50],BaselineValid,FixedRegistersUnchanged,Attempt,Reserved;
 uint64_t ElapsedTicks,CounterFrequency;
}G73_RUN;
_Static_assert(sizeof(G73_REQUEST)==24,"G73 request");
_Static_assert(sizeof(G73_STATUS)==96,"G73 status");
_Static_assert(sizeof(G73_SNAPSHOT)==304,"G73 snapshot");
_Static_assert(sizeof(G73_PMIC)==1744,"G73 PMIC");
_Static_assert(sizeof(G73_OFF_RESULT)==44192,"G73 OFF core");
_Static_assert(sizeof(G73_RUN)==44728,"G73 frozen raw result");
#endif
