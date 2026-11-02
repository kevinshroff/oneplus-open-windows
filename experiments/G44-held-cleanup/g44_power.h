/* SPDX-License-Identifier: MIT */
#ifndef G44_POWER_H
#define G44_POWER_H
#include "g44_observer.h"
typedef struct {uint32_t Kind,Address,Value;} G44_RSC_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,RequestAddress,RequestData,MsgId,Completion,Response,Triggered,Mutated;
 uint32_t Before[17],After[17];G44_RSC_EVENT Trace[256];
} G44_RSC_RESULT;
typedef struct {
 void*Context;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);
 void(*WaitMillisecond)(void*);
} G44_RSC_IO;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,TxnCount,PmicCount,EnableAttempted,ReleaseAttempted,PreflightVerified,OnVerified,OffVerified,RscUncertain,ObserverUncertain,SourceStatusBaseline;
 uint32_t ClientBefore[3],ClientOn,ClientAfter[3];
 G44_RSC_RESULT Transactions[9];G44_OBS_RESULT Pmic[3];
 uint32_t GuardBefore[8],GuardAfter[8],Waits1ms,Waits10ms;
} G44_POWER_RESULT;
typedef struct {
 G44_RSC_IO Rsc;G44_OBS_IO Observer;void(*WaitTenMilliseconds)(void*);
 int(*Powered)(void*);int(*SafeToRelease)(void*);
} G44_POWER_IO;
void G44Transfer(const G44_RSC_IO*,G44_RSC_RESULT*,uint32_t,uint32_t,int);
void G44PowerTrial(const G44_POWER_IO*,G44_POWER_RESULT*);
int G44RscWriteAllowed(uint32_t,uint32_t);
void G44ReleaseHeld(const G44_POWER_IO*,G44_POWER_RESULT*);
#endif
