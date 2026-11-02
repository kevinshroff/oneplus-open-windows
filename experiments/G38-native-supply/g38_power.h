/* SPDX-License-Identifier: MIT */
#ifndef G38_POWER_H
#define G38_POWER_H
#include "g38_observer.h"
typedef struct {uint32_t Kind,Address,Value;} G38_RSC_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,RequestAddress,RequestData,MsgId,Completion,Response,Triggered,Mutated;
 uint32_t Before[17],After[17];G38_RSC_EVENT Trace[256];
} G38_RSC_RESULT;
typedef struct {
 void*Context;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);
 void(*WaitMillisecond)(void*);
} G38_RSC_IO;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,TxnCount,PmicCount,EnableAttempted,ReleaseAttempted,PreflightVerified,OnVerified,OffVerified,RscUncertain,ObserverUncertain,SourceStatusBaseline;
 uint32_t ClientBefore[3],ClientOn,ClientAfter[3];
 G38_RSC_RESULT Transactions[9];G38_OBS_RESULT Pmic[3];
 uint32_t GuardBefore[8],GuardAfter[8],Waits1ms,Waits10ms;
} G38_POWER_RESULT;
typedef struct {
 G38_RSC_IO Rsc;G38_OBS_IO Observer;void(*WaitTenMilliseconds)(void*);
} G38_POWER_IO;
void G38Transfer(const G38_RSC_IO*,G38_RSC_RESULT*,uint32_t,uint32_t,int);
void G38PowerTrial(const G38_POWER_IO*,G38_POWER_RESULT*);
int G38RscWriteAllowed(uint32_t,uint32_t);
#endif
