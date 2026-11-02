/* SPDX-License-Identifier: MIT -- finite cold-profile digital supply lease.
 * Caller owns one zeroed result, one IO scope and its lifetime. This portable
 * component is not a Windows PnP/RPMh/PEP resource owner by itself.
 */
#ifndef G89_POWER_H
#define G89_POWER_H
#include "g89_observer.h"
#define G89_TXNS 12u
enum {G89_READ=0,G89_OFF_ACK=1,G89_OFF_NO_ACK=2,G89_ON_ACK=3};
typedef struct {uint32_t Kind,Address,Value;}G89_RSC_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,RequestAddress,RequestData,MsgId,Completion,Response,Triggered,Mutated;
 uint32_t Before[17],After[17];G89_RSC_EVENT Trace[256];
}G89_RSC_RESULT;
typedef struct {void*Context;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);void(*WaitMillisecond)(void*);}G89_RSC_IO;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Started,AcquireFinished,ReleaseStarted,Active,NeedsRelease,PreflightVerified,OnVerified,OffVerified,RscUncertain,ObserverUncertain;
 uint32_t TxnCount,PmicCount,PmicKinds[3],EnableAttempted,ReleaseAttempted,EnableTxn,ReleaseTxn,LastOffObserveTxn,History,HistoryValid,Waits1ms,Waits10ms;
 uint32_t ClientBefore[3],ClientAtRelease[3],ClientOn,ClientAfter[3];
 uint32_t GuardBefore[8],GuardOn[8],GuardRelease[8],GuardAfter[8];
 G89_RSC_RESULT Transactions[G89_TXNS];G89_OBS_RESULT Pmic[3];
}G89_POWER_RESULT;
typedef struct {G89_RSC_IO Rsc;G89_OBS_IO Observer;void(*WaitTenMilliseconds)(void*);}G89_POWER_IO;
void G89Transfer(const G89_RSC_IO*,G89_RSC_RESULT*,uint32_t,uint32_t,int);
int G89RscWriteAllowed(uint32_t,uint32_t);
int G89SupplyAcquire(const G89_POWER_IO*,G89_POWER_RESULT*);
/* True means exact cleanup, independently of any retained operation error. */
int G89SupplyRelease(const G89_POWER_IO*,G89_POWER_RESULT*);
void G89PowerTrial(const G89_POWER_IO*,G89_POWER_RESULT*);
#endif
