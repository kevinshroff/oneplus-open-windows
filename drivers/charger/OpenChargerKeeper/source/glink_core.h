/* SPDX-License-Identifier: MIT
 * Repeatable GLINK SMEM transport for Qualcomm PMIC charger router (0x800a).
 * Derived from G177/G178 proven SMEM wire framing without one-shot or 15-min lockouts.
 */
#ifndef OPEN_CK_GLINK_CORE_H
#define OPEN_CK_GLINK_CORE_H
#include <stdint.h>
#include "charger_codec.h"
#include "ipcrtr_sensors.h"

#define CK_FIFO_BYTES 16384u
#define CK_FIFO_MASK  16383u
#define CK_FRAME_BYTES 2048u
#define CK_INTENTS    32u
#define CK_OTHER_PORTS 32u
#define CK_AUD_CID     3u
#define CK_AUD_INTENTS 24u
#define CK_AUD_BUF     1536u
#define CK_AUD_QSLOTS  8u
#define CK_FRPC_CID     4u
#define CK_FRPC_INTENTS 4u
#define CK_FRPC_BUF     256u
#define CK_MAX_CHANS   16u

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
    uint32_t Len;
    uint8_t  Data[CK_AUD_BUF];
} CK_AUD_SLOT;

typedef struct {
    uint32_t RemoteCid;
    uint32_t OpenSent, OpenAcked, RemoteOpen;
    uint32_t CurrentOffers, NextLocalId, IntentReqPending;
    uint32_t SpfQuerySent, SpfRspReceived;
    uint32_t SpfRspOpcode, SpfState, SpfRspLen;
    uint8_t  SpfRaw[64];
    uint32_t TxHead, TxTail;
    CK_AUD_SLOT TxQ[CK_AUD_QSLOTS];
    uint32_t RxHead, RxTail, RxDrops;
    CK_AUD_SLOT RxQ[CK_AUD_QSLOTS];
    CK_REMOTE_INTENT Remote[CK_AUD_INTENTS];
    struct {
        uint32_t Id, State, Used, Remaining;
        uint8_t  Data[CK_AUD_BUF];
    } Local[CK_AUD_INTENTS];
} CK_AUD_STATE;

typedef struct {
    uint32_t RemoteCid;
    uint32_t OpenSent, OpenAcked, RemoteOpen;
    uint32_t CurrentOffers, NextLocalId, IntentReqPending;
    uint32_t TxPending, TxLen;
    uint8_t  TxBuf[64];
    uint32_t RspCount, RspLen;
    uint64_t LastRspCtx;
    int32_t  LastRspRetval;
    uint8_t  LastRspRaw[64];
    CK_REMOTE_INTENT Remote[CK_FRPC_INTENTS];
    struct {
        uint32_t Id, State, Used, Remaining;
        uint8_t  Data[CK_FRPC_BUF];
    } Local[CK_FRPC_INTENTS];
} CK_FRPC_STATE;

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
    CK_IPC_STATE     Ipc;
    CK_AUD_STATE     Aud;
    CK_FRPC_STATE    Frpc;
    uint32_t         ChanCount;
    char             ChanNames[CK_MAX_CHANS][24];
} CK_GL_STATE;

void CkGlInit(CK_GL_STATE *s);
int  CkGlRequest(CK_GL_STATE *s, uint32_t op_kind, uint64_t now_us);
int  CkGlRequestClose(CK_GL_STATE *s, uint64_t now_us);
int  CkGlPoll(CK_GL_STATE *s, const CK_GL_IO *io, uint64_t now_us);
int  CkAudEnqueueTx(CK_AUD_STATE *aud, const uint8_t *data, uint32_t len);
int  CkAudPopRx(CK_AUD_STATE *aud, uint8_t *out, uint32_t cap, uint32_t *out_len);

#endif
