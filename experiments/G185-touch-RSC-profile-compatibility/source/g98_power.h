/* SPDX-License-Identifier: MIT -- finite cold-profile digital supply lease.
 * Caller owns one zeroed result, one IO scope and its lifetime. This portable
 * component is not a Windows PnP/RPMh/PEP resource owner by itself.
 */
#ifndef G98_POWER_H
#define G98_POWER_H
#include "g98_observer.h"
#define G98_TXNS 12u
enum {G98_READ=0,G98_OFF_ACK=1,G98_OFF_NO_ACK=2,G98_ON_ACK=3};
typedef struct {uint32_t Kind,Address,Value;}G98_RSC_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,RequestAddress,RequestData,MsgId,Completion,Response,Triggered,Mutated;
 uint32_t Before[17],After[17];G98_RSC_EVENT Trace[256];
}G98_RSC_RESULT;
typedef struct {void*Context;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);void(*WaitMillisecond)(void*);}G98_RSC_IO;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Started,AcquireFinished,ReleaseStarted,Active,NeedsRelease,PreflightVerified,OnVerified,OffVerified,RscUncertain,ObserverUncertain;
 uint32_t TxnCount,PmicCount,PmicKinds[3],EnableAttempted,ReleaseAttempted,EnableTxn,ReleaseTxn,LastOffObserveTxn,History,HistoryValid,Waits1ms,Waits10ms;
 uint32_t ClientBefore[3],ClientAtRelease[3],ClientOn,ClientAfter[3];
 uint32_t GuardBefore[8],GuardOn[8],GuardRelease[8],GuardAfter[8];
 G98_RSC_RESULT Transactions[G98_TXNS];G98_OBS_RESULT Pmic[3];
}G98_POWER_RESULT;
typedef struct {G98_RSC_IO Rsc;G98_OBS_IO Observer;void(*WaitTenMilliseconds)(void*);int(*Powered)(void*);int(*SafeToRelease)(void*);}G98_POWER_IO;
void G98Transfer(const G98_RSC_IO*,G98_RSC_RESULT*,uint32_t,uint32_t,int);
int G98RscWriteAllowed(uint32_t,uint32_t);
int G98SupplyAcquire(const G98_POWER_IO*,G98_POWER_RESULT*);
/* True means exact cleanup, independently of any retained operation error. */
int G98SupplyRelease(const G98_POWER_IO*,G98_POWER_RESULT*);
void G98PowerTrial(const G98_POWER_IO*,G98_POWER_RESULT*);
#endif
