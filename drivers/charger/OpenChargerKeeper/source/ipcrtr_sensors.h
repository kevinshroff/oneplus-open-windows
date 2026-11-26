/* SPDX-License-Identifier: MIT
 * QRTR + QMI SNS_CLIENT_SVC (service 400) Accelerometer over ADSP GLINK IPCRTR.
 */
#ifndef OPEN_CK_IPCRTR_SENSORS_H
#define OPEN_CK_IPCRTR_SENSORS_H
#include <stdint.h>

#define CK_IPC_CID         2u
#define CK_IPC_INTENTS     8u
#define CK_IPC_BUF_BYTES   2048u
#define CK_IPC_TXQ_SLOTS   16u
#define CK_IPC_TXQ_MAX     1408u
#define CK_IPC_RXQ_SLOTS   16u
#define CK_IPC_RXQ_MAX     1408u
#define CK_IPC_MAX_SVCS    24u

#define QRTR_PORT_CTRL     0xFFFFFFFEu
#define QRTR_LOCAL_NODE    1u
#define QRTR_CLIENT_PORT   0x1001u
#define SNS_CLIENT_SVC_ID  400u

typedef struct {
    uint32_t Service;
    uint32_t Instance;
    uint32_t Node;
    uint32_t Port;
} CK_QRTR_SVC;

typedef struct {
    uint32_t Id, Bytes, State;
} CK_IPC_REMOTE_INTENT;

typedef struct {
    uint32_t Id, State, Used, Remaining;
    uint8_t  Data[CK_IPC_BUF_BYTES];
} CK_IPC_LOCAL_INTENT;

typedef struct {
    uint32_t Len;
    uint8_t  Data[CK_IPC_TXQ_MAX];
} CK_IPC_TX_SLOT;

typedef struct {
    uint32_t Len;
    uint8_t  Data[CK_IPC_RXQ_MAX];
} CK_IPC_RX_SLOT;

typedef struct {
    uint32_t RemoteCid;
    uint32_t OpenSent, OpenAcked, RemoteOpen;
    uint32_t CurrentOffers, NextLocalId, IntentReqPending;
    uint32_t HelloSent;
    uint32_t SnsFound, SnsNode, SnsPort;
    uint32_t SuidSent, SuidFound;
    uint64_t SuidLow, SuidHigh;
    uint32_t AccelReqSent, AccelValid, AccelSeq;
    int32_t  AxMilliG, AyMilliG, AzMilliG;
    uint32_t TxPackets, RxPackets, IndPackets, LastIndMsgId, TxnId;
    uint32_t ServicesCount;
    CK_QRTR_SVC Services[CK_IPC_MAX_SVCS];
    CK_IPC_REMOTE_INTENT Remote[CK_IPC_INTENTS];
    CK_IPC_LOCAL_INTENT  Local[CK_IPC_INTENTS];
    uint32_t TxHead, TxTail;
    CK_IPC_TX_SLOT TxQ[CK_IPC_TXQ_SLOTS];
    uint32_t RxHead, RxTail, RxDrops;
    CK_IPC_RX_SLOT RxQ[CK_IPC_RXQ_SLOTS];
} CK_IPC_STATE;

/* Snapshot returned by IOCTL_CK_ACCEL (0x0022600C) */
typedef struct {
    uint32_t Size;
    uint32_t Version;
    uint32_t Magic;
    uint32_t OpenAcked;
    uint32_t RemoteOpen;
    uint32_t HelloSent;
    uint32_t SnsFound;
    uint32_t SnsNode;
    uint32_t SnsPort;
    uint32_t SuidSent;
    uint32_t SuidFound;
    uint32_t AccelReqSent;
    uint32_t AccelValid;
    uint32_t AccelSeq;
    int32_t  AxMilliG;
    int32_t  AyMilliG;
    int32_t  AzMilliG;
    uint32_t TxPackets;
    uint32_t RxPackets;
    uint32_t IndPackets;
    uint32_t LastIndMsgId;
    uint32_t ServicesCount;
    uint64_t SuidLow;
    uint64_t SuidHigh;
    CK_QRTR_SVC Services[CK_IPC_MAX_SVCS];
} CK_ACCEL_SNAPSHOT;

void CkIpcInit(CK_IPC_STATE *ipc);
void CkIpcQueueHello(CK_IPC_STATE *ipc);
void CkIpcOnQrtrPacket(CK_IPC_STATE *ipc, const uint8_t *pkt, uint32_t len);
int  CkIpcPeekTx(const CK_IPC_STATE *ipc, const uint8_t **data, uint32_t *len);
void CkIpcPopTx(CK_IPC_STATE *ipc);
int  CkIpcEnqueueRawTx(CK_IPC_STATE *ipc, const uint8_t *data, uint32_t len);
int  CkIpcPopRx(CK_IPC_STATE *ipc, uint8_t *out, uint32_t cap, uint32_t *out_len);

#endif
