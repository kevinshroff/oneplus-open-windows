/* SPDX-License-Identifier: MIT -- finite cold-profile digital supply lease.
 * Caller owns one zeroed result, one IO scope and its lifetime. This portable
 * component is not a Windows PnP/RPMh/PEP resource owner by itself.
 */
#ifndef G96_POWER_H
#define G96_POWER_H
#include "g96_observer.h"
#define G96_TXNS 12u
enum {G96_READ=0,G96_OFF_ACK=1,G96_OFF_NO_ACK=2,G96_ON_ACK=3};
typedef struct {uint32_t Kind,Address,Value;}G96_RSC_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,RequestAddress,RequestData,MsgId,Completion,Response,Triggered,Mutated;
 uint32_t Before[17],After[17];G96_RSC_EVENT Trace[256];
}G96_RSC_RESULT;
typedef struct {void*Context;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);void(*WaitMillisecond)(void*);}G96_RSC_IO;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Started,AcquireFinished,ReleaseStarted,Active,NeedsRelease,PreflightVerified,OnVerified,OffVerified,RscUncertain,ObserverUncertain;
 uint32_t TxnCount,PmicCount,PmicKinds[3],EnableAttempted,ReleaseAttempted,EnableTxn,ReleaseTxn,LastOffObserveTxn,History,HistoryValid,Waits1ms,Waits10ms;
 uint32_t ClientBefore[3],ClientAtRelease[3],ClientOn,ClientAfter[3];
 uint32_t GuardBefore[8],GuardOn[8],GuardRelease[8],GuardAfter[8];
 G96_RSC_RESULT Transactions[G96_TXNS];G96_OBS_RESULT Pmic[3];
}G96_POWER_RESULT;
typedef struct {G96_RSC_IO Rsc;G96_OBS_IO Observer;void(*WaitTenMilliseconds)(void*);int(*Powered)(void*);int(*SafeToRelease)(void*);}G96_POWER_IO;
void G96Transfer(const G96_RSC_IO*,G96_RSC_RESULT*,uint32_t,uint32_t,int);
int G96RscWriteAllowed(uint32_t,uint32_t);
int G96SupplyAcquire(const G96_POWER_IO*,G96_POWER_RESULT*);
/* True means exact cleanup, independently of any retained operation error. */
int G96SupplyRelease(const G96_POWER_IO*,G96_POWER_RESULT*);
void G96PowerTrial(const G96_POWER_IO*,G96_POWER_RESULT*);
#endif
