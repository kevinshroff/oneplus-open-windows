/* SPDX-License-Identifier: MIT */
#ifndef G159_CORE_H
#define G159_CORE_H
#include <stdint.h>
#include "g159_codec.h"
#define G159_FIFO_BYTES 16384u
#define G159_FIFO_MASK 16383u
#define G159_FRAME_BYTES 2048u
#define G159_INTENTS 32u
#define G159_TRACE_LIMIT 128u
enum {G159_WAIT=0,G159_COMPLETE=1,G159_REFUSED=2};
enum {G159_F_IO=1,G159_F_DESCRIPTOR=2,G159_F_INITIAL=3,G159_F_OWNER=4,
 G159_F_FRAME=5,G159_F_CHANNEL=6,G159_F_INTENT=7,G159_F_LIMIT=8,
 G159_F_REPLY=9,G159_F_REMOTE_CLOSE=10,G159_F_SPACE=11,G159_F_TIMEOUT=12};
typedef struct {
 int(*ReadDescriptor)(void*,uint32_t[8]);
 int(*ReadRx)(void*,uint32_t,uint8_t*,uint32_t);
 int(*WriteTx)(void*,uint32_t,const uint8_t*,uint32_t);
 int(*PublishHostWord)(void*,uint32_t,uint32_t);
 void(*Barrier)(void*);int(*Kick)(void*);void*Context;
}G159_IO;
typedef struct {uint32_t Id,Bytes,State;}G159_REMOTE_INTENT;
typedef struct {uint32_t State,Used,Remaining;uint8_t Data[G159_REPLY_LIMIT];}G159_LOCAL_INTENT;
typedef struct {uint32_t Direction,Command,Channel,Parameter,Bytes,TxHead,RxTail,Query;}G159_TRACE;
typedef struct {
 uint32_t Started,Complete,Fault,Terminal,OwnTxHead,OwnRxTail,Steps,TraceCount;
 uint32_t TxFrames,RxFrames,TxWriteAttempts,CounterWriteAttempts,KickAttempts;
 uint32_t RemoteOpenSeen,OpenSent,OpenAcked,IntentsAdvertised,IgnoredOpens;
 uint32_t QueryIndex,Pending,ReplyReceived,TxCompleted,CurrentRemoteIntent;
 uint32_t QueriesSentMask,RepliesMask,IntentRequestPending,Unsolicited;
 uint32_t Closing,CloseSent,CloseAcked,RemoteClosed,RemoteCloseAckSent,CloseQuietSteps;
 uint32_t LastDescriptor[8];
 G159_BATTERY Battery;
 G159_REMOTE_INTENT Remote[G159_INTENTS];
 G159_LOCAL_INTENT Local[G159_INTENTS];
 uint32_t ReplyBytes[G159_QUERY_COUNT];uint8_t Replies[G159_QUERY_COUNT][G159_REPLY_LIMIT];
 G159_TRACE Trace[G159_TRACE_LIMIT];
}G159_STATE;
int G159Step(G159_STATE*,const G159_IO*);
int G159ValidateTx(const uint8_t*,uint32_t);
#endif
