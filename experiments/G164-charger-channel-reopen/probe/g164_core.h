/* SPDX-License-Identifier: MIT */
#ifndef G164_CORE_H
#define G164_CORE_H
#include <stdint.h>
#include "g164_codec.h"
#define G164_FIFO_BYTES 16384u
#define G164_FIFO_MASK 16383u
#define G164_FRAME_BYTES 2048u
#define G164_INTENTS 32u
#define G164_TRACE_LIMIT 128u
enum {G164_WAIT=0,G164_COMPLETE=1,G164_REFUSED=2};
enum {G164_F_IO=1,G164_F_DESCRIPTOR=2,G164_F_INITIAL=3,G164_F_OWNER=4,
 G164_F_FRAME=5,G164_F_CHANNEL=6,G164_F_INTENT=7,G164_F_LIMIT=8,
 G164_F_REPLY=9,G164_F_REMOTE_CLOSE=10,G164_F_SPACE=11,G164_F_TIMEOUT=12};
typedef struct {
 int(*ReadDescriptor)(void*,uint32_t[8]);
 int(*ReadRx)(void*,uint32_t,uint8_t*,uint32_t);
 int(*WriteTx)(void*,uint32_t,const uint8_t*,uint32_t);
 int(*PublishHostWord)(void*,uint32_t,uint32_t);
 void(*Barrier)(void*);int(*Kick)(void*);void*Context;
}G164_IO;
typedef struct {uint32_t Id,Bytes,State;}G164_REMOTE_INTENT;
typedef struct {uint32_t State,Used,Remaining;uint8_t Data[G164_REPLY_LIMIT];}G164_LOCAL_INTENT;
typedef struct {uint32_t Direction,Command,Channel,Parameter,Bytes,TxHead,RxTail,Query;}G164_TRACE;
typedef struct {
 uint32_t Started,Complete,Fault,Terminal,OwnTxHead,OwnRxTail,Steps,TraceCount;
 uint32_t TxFrames,RxFrames,TxWriteAttempts,CounterWriteAttempts,KickAttempts;
 uint32_t RemoteOpenSeen,OpenSent,OpenAcked,IntentsAdvertised,IgnoredOpens;
 uint32_t QueryIndex,Pending,ReplyReceived,TxCompleted,CurrentRemoteIntent;
 uint32_t QueriesSentMask,RepliesMask,IntentRequestPending,Unsolicited;
 uint32_t Closing,CloseSent,CloseAcked,RemoteClosed,RemoteCloseAckSent,CloseQuietSteps,RemoteCid;
 uint32_t LastDescriptor[8];
 G164_BATTERY Battery;
 G164_REMOTE_INTENT Remote[G164_INTENTS];
 G164_LOCAL_INTENT Local[G164_INTENTS];
 uint32_t ReplyBytes[G164_QUERY_COUNT];uint8_t Replies[G164_QUERY_COUNT][G164_REPLY_LIMIT];
 G164_TRACE Trace[G164_TRACE_LIMIT];
}G164_STATE;
int G164Step(G164_STATE*,const G164_IO*);
int G164ValidateTx(const G164_STATE*,const uint8_t*,uint32_t);
#endif
