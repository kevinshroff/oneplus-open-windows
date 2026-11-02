/* SPDX-License-Identifier: MIT -- finite cold-profile digital supply lease.
 * Caller owns one zeroed result, one IO scope and its lifetime. This portable
 * component is not a Windows PnP/RPMh/PEP resource owner by itself.
 */
#ifndef G93_POWER_H
#define G93_POWER_H
#include "g93_observer.h"
#define G93_TXNS 12u
enum {G93_READ=0,G93_OFF_ACK=1,G93_OFF_NO_ACK=2,G93_ON_ACK=3};
typedef struct {uint32_t Kind,Address,Value;}G93_RSC_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,RequestAddress,RequestData,MsgId,Completion,Response,Triggered,Mutated;
 uint32_t Before[17],After[17];G93_RSC_EVENT Trace[256];
}G93_RSC_RESULT;
typedef struct {void*Context;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);void(*WaitMillisecond)(void*);}G93_RSC_IO;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Started,AcquireFinished,ReleaseStarted,Active,NeedsRelease,PreflightVerified,OnVerified,OffVerified,RscUncertain,ObserverUncertain;
 uint32_t TxnCount,PmicCount,PmicKinds[3],EnableAttempted,ReleaseAttempted,EnableTxn,ReleaseTxn,LastOffObserveTxn,History,HistoryValid,Waits1ms,Waits10ms;
 uint32_t ClientBefore[3],ClientAtRelease[3],ClientOn,ClientAfter[3];
 uint32_t GuardBefore[8],GuardOn[8],GuardRelease[8],GuardAfter[8];
 G93_RSC_RESULT Transactions[G93_TXNS];G93_OBS_RESULT Pmic[3];
}G93_POWER_RESULT;
typedef struct {G93_RSC_IO Rsc;G93_OBS_IO Observer;void(*WaitTenMilliseconds)(void*);}G93_POWER_IO;
void G93Transfer(const G93_RSC_IO*,G93_RSC_RESULT*,uint32_t,uint32_t,int);
int G93RscWriteAllowed(uint32_t,uint32_t);
int G93SupplyAcquire(const G93_POWER_IO*,G93_POWER_RESULT*);
/* True means exact cleanup, independently of any retained operation error. */
int G93SupplyRelease(const G93_POWER_IO*,G93_POWER_RESULT*);
void G93PowerTrial(const G93_POWER_IO*,G93_POWER_RESULT*);
#endif
