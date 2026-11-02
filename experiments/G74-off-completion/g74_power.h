/* SPDX-License-Identifier: MIT -- finite OFF-only response-bit experiment. */
#ifndef G74_POWER_H
#define G74_POWER_H
#include "g74_observer.h"
#define G74_TXNS 12u
enum {G74_READ=0,G74_OFF_ACK=1,G74_OFF_NO_ACK=2};
typedef struct {uint32_t Kind,Address,Value;}G74_RSC_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,RequestAddress,RequestData,MsgId,Completion,Response,Triggered,Mutated;
 uint32_t Before[17],After[17];G74_RSC_EVENT Trace[256];
}G74_RSC_RESULT;
typedef struct {void*Context;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);void(*WaitMillisecond)(void*);}G74_RSC_IO;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,TxnCount,PmicCount,PreflightVerified,FlipAttempted,RestoreAttempted,FlipVerified,OriginalVerified,RscUncertain,ObserverUncertain,OffVerified;
 uint32_t ClientBefore[3],ClientAfter[3],AckRaw,NoAckRaw,GuardBefore[8],GuardAfter[8],Waits1ms,LastOffWriteTxn,LastOffObserveTxn;
 G74_RSC_RESULT Transactions[G74_TXNS];G74_OBS_RESULT Pmic[3];
}G74_OFF_RESULT;
typedef struct {G74_RSC_IO Rsc;G74_OBS_IO Observer;}G74_OFF_IO;
void G74Transfer(const G74_RSC_IO*,G74_RSC_RESULT*,uint32_t,uint32_t,int);
int G74RscWriteAllowed(uint32_t,uint32_t);
void G74OffTrial(const G74_OFF_IO*,G74_OFF_RESULT*);
#endif
