/* SPDX-License-Identifier: MIT
 * Repeatable GLINK SMEM transport for Qualcomm PMIC charger router (0x800a).
 * Derived from G177/G178 proven SMEM wire framing without one-shot or 15-min lockouts.
 */
#ifndef OPEN_CK_GLINK_CORE_H
#define OPEN_CK_GLINK_CORE_H
#include <stdint.h>
#include "charger_codec.h"

#define CK_FIFO_BYTES 16384u
#define CK_FIFO_MASK  16383u
#define CK_FRAME_BYTES 2048u
#define CK_INTENTS    32u
#define CK_OTHER_PORTS 32u

#define CK_OPEN_US    UINT64_C(10000000)
#define CK_RPC_US     UINT64_C(2000000)
#define CK_BATCH_US   UINT64_C(10000000)
#define CK_CLOSE_US   UINT64_C(2000000)

enum {
    CK_GL_NEW = 0,
    CK_GL_NEGOTIATING,
    CK_GL_OPENING,
    CK_GL_READY,
    CK_GL_CLOSING,
    CK_GL_CLOSED,
    CK_GL_FAILED
};

enum {
    CK_GL_POLL_FAULT    = -1,
    CK_GL_POLL_IDLE     = 0,
    CK_GL_POLL_PROGRESS = 1,
    CK_GL_POLL_CLOSED   = 2
};

enum {
    CK_OP_NONE = 0,
    CK_OP_SAMPLE,      /* 10 GET telemetry queries (0..9) */
    CK_OP_SET_FV,      /* CL_FV_QUERY (4470 mV) */
    CK_OP_DISABLE,     /* CL_RESTART_OFF_QUERY (prop 24 = 0) */
    CK_OP_ENABLE       /* CL_ENABLE_QUERY (prop 24 = 1) */
};

typedef struct {
    int  (*ReadDescriptor)(void *, uint32_t[8]);
    int  (*ReadRx)(void *, uint32_t, uint8_t *, uint32_t);
    int  (*WriteTx)(void *, uint32_t, const uint8_t *, uint32_t);
    int  (*PublishHostWord)(void *, uint32_t, uint32_t);
    void (*Barrier)(void *);
    int  (*Kick)(void *);
    void *Context;
} CK_GL_IO;

typedef struct { uint32_t Id, Bytes, State; } CK_REMOTE_INTENT;
typedef struct {
    uint32_t Id, State, Used, Remaining;
    uint64_t BeganUs;
    uint8_t  Data[CL_REPLY_LIMIT];
} CK_LOCAL_INTENT;

typedef struct {
    uint32_t Phase, Fault;
    uint32_t OwnTx, OwnRx, RemoteCid;
    uint32_t VersionSent, VersionAckSent, VersionAckSeen;
    uint32_t OpenSent, OpenAcked, RemoteOpen;
    uint32_t CloseRequested, CloseSent, CloseAcked, RemoteClosed, RemoteCloseAcked;
    uint32_t OpActive, OpKind, Query, Pending, ReplyReceived, TxDone, RemoteIntentIndex;
    uint32_t IntentRequestPending, NextLocalId, CurrentOffers;
    uint32_t LastCompletedOp, LastOpOk;
    uint32_t LastDescriptor[8];
    uint64_t BeginUs, LastNowUs, PendingSinceUs, OpBeginUs, CloseSinceUs;
    uint64_t TxFrames, RxFrames, OpsCompleted, Kicks;
    CL_BATTERY Working, LastBattery;
    CK_REMOTE_INTENT Remote[CK_INTENTS];
    CK_LOCAL_INTENT  Local[CK_INTENTS];
} CK_GL_STATE;

void CkGlInit(CK_GL_STATE *s);
int  CkGlRequest(CK_GL_STATE *s, uint32_t op_kind, uint64_t now_us);
int  CkGlRequestClose(CK_GL_STATE *s, uint64_t now_us);
int  CkGlPoll(CK_GL_STATE *s, const CK_GL_IO *io, uint64_t now_us);

#endif
