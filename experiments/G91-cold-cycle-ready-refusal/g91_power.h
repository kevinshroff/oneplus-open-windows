/* SPDX-License-Identifier: MIT -- finite cold-profile digital supply lease.
 * Caller owns one zeroed result, one IO scope and its lifetime. This portable
 * component is not a Windows PnP/RPMh/PEP resource owner by itself.
 */
#ifndef G91_POWER_H
#define G91_POWER_H
#include "g91_observer.h"
#define G91_TXNS 12u
enum {G91_READ=0,G91_OFF_ACK=1,G91_OFF_NO_ACK=2,G91_ON_ACK=3};
typedef struct {uint32_t Kind,Address,Value;}G91_RSC_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,RequestAddress,RequestData,MsgId,Completion,Response,Triggered,Mutated;
 uint32_t Before[17],After[17];G91_RSC_EVENT Trace[256];
}G91_RSC_RESULT;
typedef struct {void*Context;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);void(*WaitMillisecond)(void*);}G91_RSC_IO;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Started,AcquireFinished,ReleaseStarted,Active,NeedsRelease,PreflightVerified,OnVerified,OffVerified,RscUncertain,ObserverUncertain;
 uint32_t TxnCount,PmicCount,PmicKinds[3],EnableAttempted,ReleaseAttempted,EnableTxn,ReleaseTxn,LastOffObserveTxn,History,HistoryValid,Waits1ms,Waits10ms;
 uint32_t ClientBefore[3],ClientAtRelease[3],ClientOn,ClientAfter[3];
 uint32_t GuardBefore[8],GuardOn[8],GuardRelease[8],GuardAfter[8];
 G91_RSC_RESULT Transactions[G91_TXNS];G91_OBS_RESULT Pmic[3];
}G91_POWER_RESULT;
typedef struct {G91_RSC_IO Rsc;G91_OBS_IO Observer;void(*WaitTenMilliseconds)(void*);}G91_POWER_IO;
void G91Transfer(const G91_RSC_IO*,G91_RSC_RESULT*,uint32_t,uint32_t,int);
int G91RscWriteAllowed(uint32_t,uint32_t);
int G91SupplyAcquire(const G91_POWER_IO*,G91_POWER_RESULT*);
/* True means exact cleanup, independently of any retained operation error. */
int G91SupplyRelease(const G91_POWER_IO*,G91_POWER_RESULT*);
void G91PowerTrial(const G91_POWER_IO*,G91_POWER_RESULT*);
#endif
