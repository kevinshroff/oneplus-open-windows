/* SPDX-License-Identifier: MIT */
#ifndef G42_POWER_H
#define G42_POWER_H
#include "g42_observer.h"
typedef struct {uint32_t Kind,Address,Value;} G42_RSC_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,RequestAddress,RequestData,MsgId,Completion,Response,Triggered,Mutated;
 uint32_t Before[17],After[17];G42_RSC_EVENT Trace[256];
} G42_RSC_RESULT;
typedef struct {
 void*Context;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);
 void(*WaitMillisecond)(void*);
} G42_RSC_IO;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,TxnCount,PmicCount,EnableAttempted,ReleaseAttempted,PreflightVerified,OnVerified,OffVerified,RscUncertain,ObserverUncertain,SourceStatusBaseline;
 uint32_t ClientBefore[3],ClientOn,ClientAfter[3];
 G42_RSC_RESULT Transactions[9];G42_OBS_RESULT Pmic[3];
 uint32_t GuardBefore[8],GuardAfter[8],Waits1ms,Waits10ms;
} G42_POWER_RESULT;
typedef struct {
 G42_RSC_IO Rsc;G42_OBS_IO Observer;void(*WaitTenMilliseconds)(void*);
 int(*Powered)(void*);int(*SafeToRelease)(void*);
} G42_POWER_IO;
void G42Transfer(const G42_RSC_IO*,G42_RSC_RESULT*,uint32_t,uint32_t,int);
void G42PowerTrial(const G42_POWER_IO*,G42_POWER_RESULT*);
int G42RscWriteAllowed(uint32_t,uint32_t);
void G42ReleaseHeld(const G42_POWER_IO*,G42_POWER_RESULT*);
#endif
