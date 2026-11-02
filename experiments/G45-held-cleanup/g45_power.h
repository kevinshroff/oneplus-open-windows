/* SPDX-License-Identifier: MIT */
#ifndef G45_POWER_H
#define G45_POWER_H
#include "g45_observer.h"
typedef struct {uint32_t Kind,Address,Value;} G45_RSC_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,RequestAddress,RequestData,MsgId,Completion,Response,Triggered,Mutated;
 uint32_t Before[17],After[17];G45_RSC_EVENT Trace[256];
} G45_RSC_RESULT;
typedef struct {
 void*Context;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);
 void(*WaitMillisecond)(void*);
} G45_RSC_IO;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,TxnCount,PmicCount,EnableAttempted,ReleaseAttempted,PreflightVerified,OnVerified,OffVerified,RscUncertain,ObserverUncertain,SourceStatusBaseline;
 uint32_t ClientBefore[3],ClientOn,ClientAfter[3];
 G45_RSC_RESULT Transactions[9];G45_OBS_RESULT Pmic[3];
 uint32_t GuardBefore[8],GuardAfter[8],Waits1ms,Waits10ms;
} G45_POWER_RESULT;
typedef struct {
 G45_RSC_IO Rsc;G45_OBS_IO Observer;void(*WaitTenMilliseconds)(void*);
 int(*Powered)(void*);int(*SafeToRelease)(void*);
} G45_POWER_IO;
void G45Transfer(const G45_RSC_IO*,G45_RSC_RESULT*,uint32_t,uint32_t,int);
void G45PowerTrial(const G45_POWER_IO*,G45_POWER_RESULT*);
int G45RscWriteAllowed(uint32_t,uint32_t);
void G45ReleaseHeld(const G45_POWER_IO*,G45_POWER_RESULT*);
#endif
