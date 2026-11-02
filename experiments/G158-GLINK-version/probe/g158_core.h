/* SPDX-License-Identifier: MIT
 * Finite AP GLINK version negotiation. No channel or charger command exists.
 */
#ifndef G158_CORE_H
#define G158_CORE_H
#include <stdint.h>
#define G158_FIFO_BYTES 16384u
#define G158_FIFO_MASK 16383u
#define G158_FRAME_LIMIT 16u
#define G158_TRACE_LIMIT 32u
enum { G158_WAIT=0, G158_COMPLETE=1, G158_REFUSED=2 };
enum { G158_F_NONE=0,G158_F_IO=1,G158_F_DESCRIPTOR=2,G158_F_INITIAL=3,
       G158_F_OWNER=4,G158_F_SPACE=5,G158_F_FRAME=6,G158_F_LIMIT=7 };
typedef struct {
 int (*ReadDescriptor)(void*,uint32_t[8]);
 int (*ReadRx8)(void*,uint32_t,uint8_t[8]);
 int (*WriteTx8)(void*,uint32_t,const uint8_t[8]);
 int (*PublishHostWord)(void*,uint32_t,uint32_t);
 void (*Barrier)(void*);
 int (*Kick)(void*);
 void *Context;
} G158_IO;
typedef struct {
 uint32_t Direction,Command,Version,Features,TxHead,RxTail,TxTail,RxHead;
} G158_TRACE;
typedef struct {
 uint32_t Started,Complete,Fault,OwnTxHead,OwnRxTail,LocalVersionSent;
 uint32_t PeerVersionSeen,PeerVersionAckSent,LocalAckObserved;
 uint32_t TxFrames,RxFrames,TxWriteAttempts,CounterWriteAttempts,KickAttempts;
 uint32_t Steps,TraceCount,NextCommand,NextCommandPresent;
 uint32_t LastDescriptor[8];
 G158_TRACE Trace[G158_TRACE_LIMIT];
} G158_STATE;
int G158Step(G158_STATE*,const G158_IO*);
#endif
