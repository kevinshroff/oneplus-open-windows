/* SPDX-License-Identifier: MIT -- finite OFF-only response-bit experiment. */
#ifndef G73_POWER_H
#define G73_POWER_H
#include "g73_observer.h"
#define G73_TXNS 12u
enum {G73_READ=0,G73_OFF_ACK=1,G73_OFF_NO_ACK=2};
typedef struct {uint32_t Kind,Address,Value;}G73_RSC_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,RequestAddress,RequestData,MsgId,Completion,Response,Triggered,Mutated;
 uint32_t Before[17],After[17];G73_RSC_EVENT Trace[256];
}G73_RSC_RESULT;
typedef struct {void*Context;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);void(*WaitMillisecond)(void*);}G73_RSC_IO;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,TxnCount,PmicCount,PreflightVerified,FlipAttempted,RestoreAttempted,FlipVerified,OriginalVerified,RscUncertain,ObserverUncertain,OffVerified;
 uint32_t ClientBefore[3],ClientAfter[3],AckRaw,NoAckRaw,GuardBefore[8],GuardAfter[8],Waits1ms,LastOffWriteTxn,LastOffObserveTxn;
 G73_RSC_RESULT Transactions[G73_TXNS];G73_OBS_RESULT Pmic[3];
}G73_OFF_RESULT;
typedef struct {G73_RSC_IO Rsc;G73_OBS_IO Observer;}G73_OFF_IO;
void G73Transfer(const G73_RSC_IO*,G73_RSC_RESULT*,uint32_t,uint32_t,int);
int G73RscWriteAllowed(uint32_t,uint32_t);
void G73OffTrial(const G73_OFF_IO*,G73_OFF_RESULT*);
#endif
