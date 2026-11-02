/* SPDX-License-Identifier: MIT
 * Serialized GLINK1/features0 owner with fixed board FV and charge pulse.
 * No arbitrary voltage/property/duration or raw packet API.
 * Caller supplies a live, independently admitted mapping and monotonic time.
 * This protocol core does not establish a Windows PnP/power/resource lease.
 */
#ifndef OPEN_CHARGER_LINK_CORE_H
#define OPEN_CHARGER_LINK_CORE_H
#include <stdint.h>
#include "charger_codec.h"
#define CL_FIFO_BYTES 16384u
#define CL_FIFO_MASK 16383u
#define CL_FRAME_BYTES 2048u
#define CL_INTENTS 32u
#define CL_OTHER_PORTS 32u
#define CL_TRACE_SLOTS 32u
#define CL_QUIET_US UINT64_C(20000)
#define CL_OPEN_US UINT64_C(10000000)
#define CL_RPC_US UINT64_C(2000000)
#define CL_BATCH_US UINT64_C(10000000)
#define CL_PULSE_US UINT64_C(90000000)
#define CL_PULSE_HARD_US UINT64_C(900000000)
#define CL_HEALTH_RENEW_LIMIT UINT64_C(64)
#define CL_RESTART_GAP_US UINT64_C(5000000)
#define CL_PULSE_BATCH_US (CL_RESTART_GAP_US+CL_PULSE_HARD_US+2*CL_BATCH_US)
#define CL_CLOSE_US UINT64_C(2000000)
#define CL_CLOSED_QUIET_US UINT64_C(50000)
enum { CL_NEW,CL_NEGOTIATING,CL_OPENING,CL_READY,CL_CLOSING,CL_CLOSED,CL_FAILED };
enum { CL_F_NONE,CL_F_IO,CL_F_INITIAL,CL_F_DESCRIPTOR,CL_F_OWNER,CL_F_FRAME,
 CL_F_CHANNEL,CL_F_INTENT,CL_F_REPLY,CL_F_TIMEOUT,CL_F_PEER_CLOSE,
 CL_F_PEER_RESTART,CL_F_CLOCK,CL_F_EXHAUSTED };
enum { CL_POLL_FAULT=-1,CL_POLL_IDLE=0,CL_POLL_PROGRESS=1,CL_POLL_CLOSED=2 };
typedef struct {
 int (*ReadDescriptor)(void *,uint32_t[8]);
 int (*ReadRx)(void *,uint32_t,uint8_t *,uint32_t);
 int (*WriteTx)(void *,uint32_t,const uint8_t *,uint32_t);
 int (*PublishHostWord)(void *,uint32_t,uint32_t);
 void (*Barrier)(void *);int (*Kick)(void *);void *Context;
} CL_IO;
typedef struct { uint32_t Id,Bytes,State; } CL_REMOTE_INTENT;
typedef struct {
 uint32_t Id,State,Used,Remaining;uint64_t BeganUs;
 uint8_t Data[CL_REPLY_LIMIT];
} CL_LOCAL_INTENT;
typedef struct { uint32_t Present,Cid,NameBytes,Signals;uint8_t Name[128]; } CL_PORT;
typedef struct {
 uint64_t Serial,TimeUs,Batch;
 uint32_t Direction,Command,Channel,Parameter,Bytes,TxHead,RxTail,Query;
 uint8_t Frame[CL_FRAME_BYTES];
} CL_TRACE;
typedef struct {
 uint64_t Generation,BeginUs,EndUs;
 uint32_t Complete,Aborted,Kind,Reserved,ReplyBytes[CL_QUERY_COUNT];
 CL_BATTERY Battery;uint8_t Replies[CL_QUERY_COUNT][CL_REPLY_LIMIT];
} CL_BATCH;
typedef struct {
 uint32_t Phase,Fault,TransportUncertain,RpcUncertain,OwnTx,OwnRx,RemoteCid;
 uint32_t VersionSent,VersionAckSent,VersionAckSeen,OpenSent,OpenAcked,RemoteOpen;
 uint32_t CloseRequested,CloseSent,CloseAcked,RemoteClosed,RemoteCloseAcked;
 uint32_t BatchActive,Query,Pending,ReplyReceived,TxDone,RemoteIntentIndex;
 uint32_t IntentRequestPending,NextLocalId,CurrentOffers,TraceCount,EventBytes;
 uint32_t BoardFvAttempted,BoardFvAcked,PulseAttempted,PulseEnableAcked;
 uint32_t PulseDisableAcked,StopPulseRequested,CloseAfterPulse,RestartOffAcked,LastDescriptor[8];
 uint64_t PulseUntilUs,PulseDisableSinceUs,RestartUntilUs;
 uint64_t PulseHardUntilUs,LastHealthLeaseUs,HealthLeaseRenewals;
 uint64_t BeginUs,LastNowUs,LastActivityUs,PendingSinceUs,CloseSinceUs,ClosedQuietUs;
 uint64_t TraceNext,TraceOverwritten,TxFrames,RxFrames,TxWriteAttempts;
 uint64_t CounterWriteAttempts,KickAttempts,Steps,BatchesStarted,BatchesCompleted;
 uint64_t Events,IgnoredOpens,TxStallSinceUs,IncompleteSinceUs;
 uint8_t LastEvent[CL_REPLY_LIMIT];
 CL_PORT Other[CL_OTHER_PORTS];
 CL_REMOTE_INTENT Remote[CL_INTENTS];CL_LOCAL_INTENT Local[CL_INTENTS];
 CL_BATCH Working,LastBatch;
 CL_TRACE Trace[CL_TRACE_SLOTS];
} CL_STATE;
void ClInitialize(CL_STATE *);
/* Accepted request returns1; busy/closed returns0; invalid/fault returns-1.
 * A completed batch does not close the channel. No requests are replayed after
 * timeout or ambiguous transport error. The caller serializes every operation. */
int ClRequestBatch(CL_STATE *,uint64_t now);
/* One attempt per owner lifetime, even if rejected/timed out at the service.
 * GET cached voltage and SET reply word4 are never hardware verification. */
int ClRequestBoardFv(CL_STATE *,uint64_t now);
/* One disable/fixed5s gap/enable/fixed90s hold/disable sequence, only after an
 * acknowledged board FV action. Initial disable failure never permits enable.
 * A live native owner pumps this independently of client handles. A transport
 * fault is still uncertainty, never a guarantee of disabled hardware. */
int ClRequestRestartPulse(CL_STATE *,uint64_t now);
/* Internal caller contract: invoke only after independently reading and
 * validating fresh paired kernel-provider results. No physical values or
 * duration are admitted here. Native adapter integration is a required gate.
 * Fixed90s renewals can never exceed fixed15min from enable acknowledgement.
 * A late/duplicate renewal cannot revive an expired charging interval. */
int ClRequestHealthLease(CL_STATE *,uint64_t now);
int ClRequestStopPulse(CL_STATE *,uint64_t now);
int ClRequestClose(CL_STATE *,uint64_t now);
int ClPoll(CL_STATE *,const CL_IO *,uint64_t now);
int ClTxAllowed(const CL_STATE *,const uint8_t *,uint32_t);
#endif
