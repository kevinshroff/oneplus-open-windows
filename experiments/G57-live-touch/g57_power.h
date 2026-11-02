/* SPDX-License-Identifier: MIT */
#ifndef G57_POWER_H
#define G57_POWER_H
#include "g57_observer.h"
typedef struct {uint32_t Kind,Address,Value;} G57_RSC_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,RequestAddress,RequestData,MsgId,Completion,Response,Triggered,Mutated;
 uint32_t Before[17],After[17];G57_RSC_EVENT Trace[256];
} G57_RSC_RESULT;
typedef struct {
 void*Context;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);
 void(*WaitMillisecond)(void*);
} G57_RSC_IO;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,TxnCount,PmicCount,EnableAttempted,ReleaseAttempted,PreflightVerified,OnVerified,OffVerified,RscUncertain,ObserverUncertain,SourceStatusBaseline;
 uint32_t ClientBefore[3],ClientOn,ClientAfter[3];
 G57_RSC_RESULT Transactions[9];G57_OBS_RESULT Pmic[3];
 uint32_t GuardBefore[8],GuardAfter[8],Waits1ms,Waits10ms;
} G57_POWER_RESULT;
typedef struct {
 G57_RSC_IO Rsc;G57_OBS_IO Observer;void(*WaitTenMilliseconds)(void*);
 int(*Powered)(void*);int(*SafeToRelease)(void*);
} G57_POWER_IO;
void G57Transfer(const G57_RSC_IO*,G57_RSC_RESULT*,uint32_t,uint32_t,int);
void G57PowerTrial(const G57_POWER_IO*,G57_POWER_RESULT*);
int G57RscWriteAllowed(uint32_t,uint32_t);
#endif
