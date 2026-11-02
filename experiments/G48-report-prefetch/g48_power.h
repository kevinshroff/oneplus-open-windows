/* SPDX-License-Identifier: MIT */
#ifndef G48_POWER_H
#define G48_POWER_H
#include "g48_observer.h"
typedef struct {uint32_t Kind,Address,Value;} G48_RSC_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,RequestAddress,RequestData,MsgId,Completion,Response,Triggered,Mutated;
 uint32_t Before[17],After[17];G48_RSC_EVENT Trace[256];
} G48_RSC_RESULT;
typedef struct {
 void*Context;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);
 void(*WaitMillisecond)(void*);
} G48_RSC_IO;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,TxnCount,PmicCount,EnableAttempted,ReleaseAttempted,PreflightVerified,OnVerified,OffVerified,RscUncertain,ObserverUncertain,SourceStatusBaseline;
 uint32_t ClientBefore[3],ClientOn,ClientAfter[3];
 G48_RSC_RESULT Transactions[9];G48_OBS_RESULT Pmic[3];
 uint32_t GuardBefore[8],GuardAfter[8],Waits1ms,Waits10ms;
} G48_POWER_RESULT;
typedef struct {
 G48_RSC_IO Rsc;G48_OBS_IO Observer;void(*WaitTenMilliseconds)(void*);
 int(*Powered)(void*);int(*SafeToRelease)(void*);
} G48_POWER_IO;
void G48Transfer(const G48_RSC_IO*,G48_RSC_RESULT*,uint32_t,uint32_t,int);
void G48PowerTrial(const G48_POWER_IO*,G48_POWER_RESULT*);
int G48RscWriteAllowed(uint32_t,uint32_t);
#endif
