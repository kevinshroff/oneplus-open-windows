/* SPDX-License-Identifier: MIT
 * QRTR + QMI SNS_CLIENT_SVC (service 400) Accelerometer over ADSP GLINK IPCRTR.
 * Zero dynamic allocation; pure C11 wire codec.
 */
#include "ipcrtr_sensors.h"

static uint16_t R16(const uint8_t *b){ return (uint16_t)b[0] | ((uint16_t)b[1] << 8); }
static uint32_t R32(const uint8_t *b){ return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24); }
static uint64_t R64(const uint8_t *b){ return (uint64_t)R32(b) | ((uint64_t)R32(b + 4) << 32); }
static void W16(uint8_t *b, uint16_t v){ b[0] = (uint8_t)v; b[1] = (uint8_t)(v >> 8); }
static void W32(uint8_t *b, uint32_t v){ for(uint32_t i=0;i<4;i++) b[i] = (uint8_t)(v >> (i*8)); }
static void W64(uint8_t *b, uint64_t v){ W32(b, (uint32_t)v); W32(b + 4, (uint32_t)(v >> 32)); }

void CkIpcInit(CK_IPC_STATE *ipc){
    if(!ipc) return;
    uint8_t *p = (uint8_t*)ipc;
    for(uint32_t i=0; i<sizeof(*ipc); i++) p[i] = 0;
    ipc->NextLocalId = 100u;
    ipc->TxnId = 1u;
}

static int EnqueueTx(CK_IPC_STATE *ipc, const uint8_t *data, uint32_t len){
    if(!ipc || !data || !len || len > CK_IPC_TXQ_MAX) return 0;
    uint32_t next = (ipc->TxHead + 1u) % CK_IPC_TXQ_SLOTS;
    if(next == ipc->TxTail) return 0; /* queue full */
    ipc->TxQ[ipc->TxHead].Len = len;
    for(uint32_t i=0; i<len; i++) ipc->TxQ[ipc->TxHead].Data[i] = data[i];
    ipc->TxHead = next;
    return 1;
}

int CkIpcPeekTx(const CK_IPC_STATE *ipc, const uint8_t **data, uint32_t *len){
    if(!ipc || ipc->TxHead == ipc->TxTail) return 0;
    *data = ipc->TxQ[ipc->TxTail].Data;
    *len  = ipc->TxQ[ipc->TxTail].Len;
    return 1;
}

void CkIpcPopTx(CK_IPC_STATE *ipc){
    if(!ipc || ipc->TxHead == ipc->TxTail) return;
    ipc->TxTail = (ipc->TxTail + 1u) % CK_IPC_TXQ_SLOTS;
    ipc->TxPackets++;
}

int CkIpcEnqueueRawTx(CK_IPC_STATE *ipc, const uint8_t *data, uint32_t len){
    return EnqueueTx(ipc, data, len);
}

static void EnqueueRx(CK_IPC_STATE *ipc, const uint8_t *data, uint32_t len){
    if(!ipc || !data || !len || len > CK_IPC_RXQ_MAX) return;
    uint32_t next = (ipc->RxHead + 1u) % CK_IPC_RXQ_SLOTS;
    if(next == ipc->RxTail){ ipc->RxDrops++; return; }
    ipc->RxQ[ipc->RxHead].Len = len;
    for(uint32_t i=0; i<len; i++) ipc->RxQ[ipc->RxHead].Data[i] = data[i];
    ipc->RxHead = next;
}

int CkIpcPopRx(CK_IPC_STATE *ipc, uint8_t *out, uint32_t cap, uint32_t *out_len){
    if(!ipc || !out || !out_len || ipc->RxHead == ipc->RxTail) return 0;
    uint32_t len = ipc->RxQ[ipc->RxTail].Len;
    if(len > cap) len = cap;
    for(uint32_t i=0; i<len; i++) out[i] = ipc->RxQ[ipc->RxTail].Data[i];
    *out_len = len;
    ipc->RxTail = (ipc->RxTail + 1u) % CK_IPC_RXQ_SLOTS;
    return 1;
}

static void EnqueueQrtr(CK_IPC_STATE *ipc, uint32_t type, uint32_t src_port,
                        uint32_t dst_node, uint32_t dst_port,
                        const uint8_t *payload, uint32_t plen){
    uint8_t pkt[CK_IPC_TXQ_MAX];
    uint32_t aligned = (plen + 3u) & ~3u;
    if(32u + aligned > CK_IPC_TXQ_MAX) return;
    for(uint32_t i=0; i<32u + aligned; i++) pkt[i] = 0;
    W32(pkt + 0,  1u); /* QRTR v1 */
    W32(pkt + 4,  type);
    W32(pkt + 8,  QRTR_LOCAL_NODE);
    W32(pkt + 12, src_port);
    W32(pkt + 16, 0u); /* confirm_rx */
    W32(pkt + 20, plen);
    W32(pkt + 24, dst_node);
    W32(pkt + 28, dst_port);
    for(uint32_t i=0; i<plen; i++) pkt[32u + i] = payload[i];
    EnqueueTx(ipc, pkt, 32u + aligned);
}

void CkIpcQueueHello(CK_IPC_STATE *ipc){
    if(!ipc || ipc->HelloSent) return;
    uint8_t ctrl[20];
    for(uint32_t i=0; i<20; i++) ctrl[i] = 0;
    W32(ctrl + 0, 2u); /* QRTR_TYPE_HELLO */
    EnqueueQrtr(ipc, 2u, QRTR_PORT_CTRL, 0u, QRTR_PORT_CTRL, ctrl, 20u);
    ipc->HelloSent = 1u;
}

static uint32_t PutVarint(uint8_t *b, uint32_t v){
    uint32_t n = 0;
    do {
        uint8_t byte = (uint8_t)(v & 0x7Fu);
        v >>= 7;
        if(v) byte |= 0x80u;
        b[n++] = byte;
    } while(v);
    return n;
}

/* Build QMI SNS_CLIENT_REQ_V01 (msg_id=0x0020) wrapping sns_client_request_msg protobuf */
static void SendSnsClientReq(CK_IPC_STATE *ipc, uint64_t suid_lo, uint64_t suid_hi,
                             uint32_t sns_msg_id, const uint8_t *inner, uint32_t inner_len){
    uint8_t pb[128];
    uint32_t p = 0;
    /* Field 1: suid (sns_std_suid: 0x09 <lo8> 0x11 <hi8>) */
    pb[p++] = 0x0Au; pb[p++] = 18u;
    pb[p++] = 0x09u; W64(pb + p, suid_lo); p += 8;
    pb[p++] = 0x11u; W64(pb + p, suid_hi); p += 8;
    /* Field 2: msg_id (varint) */
    pb[p++] = 0x10u; p += PutVarint(pb + p, sns_msg_id);
    /* Field 3: susp_config { client_proc_type=0 (APSS), delivery_type=0 (WAKEUP) } */
    pb[p++] = 0x1Au; pb[p++] = 4u;
    pb[p++] = 0x08u; pb[p++] = 0u;
    pb[p++] = 0x10u; pb[p++] = 0u;
    /* Field 4: request (sns_std_request) { field 2: payload = inner } */
    uint32_t req_len = 2u + inner_len;
    pb[p++] = 0x22u; pb[p++] = (uint8_t)req_len;
    pb[p++] = 0x12u; pb[p++] = (uint8_t)inner_len;
    for(uint32_t i=0; i<inner_len; i++) pb[p++] = inner[i];

    /* QMI header (7B) + TLV 0x01 (type 1B + len 2B + uint16 payload_len + pb) */
    uint8_t qmi[160];
    uint32_t tlv_val_len = 2u + p;
    uint32_t msg_len = 3u + tlv_val_len;
    qmi[0] = 0x00u; /* QMI REQUEST */
    W16(qmi + 1, (uint16_t)(ipc->TxnId++));
    W16(qmi + 3, 0x0020u); /* SNS_CLIENT_REQ_V01 */
    W16(qmi + 5, (uint16_t)msg_len);
    qmi[7] = 0x01u; /* TLV 0x01: payload */
    W16(qmi + 8, (uint16_t)tlv_val_len);
    W16(qmi + 10, (uint16_t)p);
    for(uint32_t i=0; i<p; i++) qmi[12u + i] = pb[i];

    EnqueueQrtr(ipc, 1u /* DATA */, QRTR_CLIENT_PORT, ipc->SnsNode, ipc->SnsPort, qmi, 7u + msg_len);
}

static void SendSuidLookupAccel(CK_IPC_STATE *ipc){
    /* sns_suid_req: field 1 data_type="accel" (0x0A 0x05 "accel"), field 3 default_only=true (0x18 0x01) */
    static const uint8_t inner[9] = { 0x0Au, 5u, 'a', 'c', 'c', 'e', 'l', 0x18u, 1u };
    SendSnsClientReq(ipc, 0xababababababababULL, 0xababababababababULL, 512u, inner, 9u);
    ipc->SuidSent = 1u;
}

static void SendAccelStart(CK_IPC_STATE *ipc){
    /* sns_std_sensor_config: field 1 sample_rate = 10.0f (0x41200000) -> 0x0D 00 00 20 41 */
    static const uint8_t inner[5] = { 0x0Du, 0x00u, 0x00u, 0x20u, 0x41u };
    SendSnsClientReq(ipc, ipc->SuidLow, ipc->SuidHigh, 513u, inner, 5u);
    ipc->AccelReqSent = 1u;
}

/* Convert IEEE-754 float32 (m/s^2) to integer milli-G (1 G = 9.80665 m/s^2) without FPU! */
static int32_t FloatMpS2ToMilliG(uint32_t bits){
    int sign = (bits >> 31) ? -1 : 1;
    int exp  = (int)((bits >> 23) & 0xFFu) - 127;
    uint32_t frac = bits & 0x7FFFFFu;
    if(exp == -127 || exp < -14) return 0;
    if(exp > 10) return sign * 16000;
    uint64_t mant = (1ULL << 23) | (uint64_t)frac;
    /* value = mant * 2^(exp - 23). milli-G = value * 1000 / 9.80665 ≈ value * 101.97162 ≈ value * 104419 / 1024 */
    uint64_t scaled = mant * 104419ULL;
    int shift = 23 + 10 - exp; /* divide by 2^shift */
    uint64_t mg = (shift >= 0) ? (scaled >> shift) : (scaled << (-shift));
    if(mg > 16000ULL) mg = 16000ULL;
    return sign * (int32_t)mg;
}

static int ReadVarint(const uint8_t *b, uint32_t len, uint32_t *pos, uint64_t *out){
    uint64_t v = 0; uint32_t sh = 0;
    while(*pos < len && sh < 64u){
        uint8_t c = b[(*pos)++];
        v |= ((uint64_t)(c & 0x7Fu)) << sh;
        if(!(c & 0x80u)){ *out = v; return 1; }
        sh += 7u;
    }
    return 0;
}

static int SkipPbField(const uint8_t *b, uint32_t len, uint32_t *pos, uint32_t wt){
    uint64_t v = 0;
    switch(wt){
    case 0: return ReadVarint(b, len, pos, &v);
    case 1: if(*pos + 8u > len) return 0; *pos += 8u; return 1;
    case 2: if(!ReadVarint(b, len, pos, &v) || *pos + v > len) return 0; *pos += (uint32_t)v; return 1;
    case 5: if(*pos + 4u > len) return 0; *pos += 4u; return 1;
    default: return 0;
    }
}

static void ParseSuidEvent(CK_IPC_STATE *ipc, const uint8_t *b, uint32_t len){
    uint32_t pos = 0;
    while(pos < len){
        uint64_t tag = 0;
        if(!ReadVarint(b, len, &pos, &tag)) break;
        uint32_t fn = (uint32_t)(tag >> 3), wt = (uint32_t)(tag & 7u);
        if(fn == 2u && wt == 2u){ /* repeated sns_std_suid suid */
            uint64_t slen = 0;
            if(!ReadVarint(b, len, &pos, &slen) || pos + slen > len) break;
            uint32_t sp = pos, send = pos + (uint32_t)slen;
            uint64_t lo = 0, hi = 0;
            int got_lo = 0, got_hi = 0;
            while(sp < send){
                uint64_t stag = 0;
                if(!ReadVarint(b, send, &sp, &stag)) break;
                uint32_t sfn = (uint32_t)(stag >> 3), swt = (uint32_t)(stag & 7u);
                if(sfn == 1u && swt == 1u && sp + 8u <= send){ lo = R64(b + sp); sp += 8u; got_lo = 1; }
                else if(sfn == 2u && swt == 1u && sp + 8u <= send){ hi = R64(b + sp); sp += 8u; got_hi = 1; }
                else if(!SkipPbField(b, send, &sp, swt)) break;
            }
            if(got_lo && got_hi && !ipc->SuidFound){
                ipc->SuidLow = lo;
                ipc->SuidHigh = hi;
                ipc->SuidFound = 1u;
                SendAccelStart(ipc);
            }
            pos = send;
        } else {
            if(!SkipPbField(b, len, &pos, wt)) break;
        }
    }
}

static void ParseAccelEvent(CK_IPC_STATE *ipc, const uint8_t *b, uint32_t len){
    uint32_t pos = 0;
    uint32_t raw[3] = {0, 0, 0};
    uint32_t cnt = 0;
    while(pos < len && cnt < 3u){
        uint64_t tag = 0;
        if(!ReadVarint(b, len, &pos, &tag)) break;
        uint32_t fn = (uint32_t)(tag >> 3), wt = (uint32_t)(tag & 7u);
        if(fn == 1u && wt == 5u && pos + 4u <= len){
            raw[cnt++] = R32(b + pos); pos += 4u;
        } else if(fn == 1u && wt == 2u){
            /* packed repeated float */
            uint64_t plen = 0;
            if(!ReadVarint(b, len, &pos, &plen) || pos + plen > len) break;
            uint32_t end = pos + (uint32_t)plen;
            while(pos + 4u <= end && cnt < 3u){ raw[cnt++] = R32(b + pos); pos += 4u; }
            pos = end;
        } else {
            if(!SkipPbField(b, len, &pos, wt)) break;
        }
    }
    if(cnt == 3u){
        ipc->AxMilliG = FloatMpS2ToMilliG(raw[0]);
        ipc->AyMilliG = FloatMpS2ToMilliG(raw[1]);
        ipc->AzMilliG = FloatMpS2ToMilliG(raw[2]);
        ipc->AccelValid = 1u;
        ipc->AccelSeq++;
    }
}

static void ParseClientEventMsg(CK_IPC_STATE *ipc, const uint8_t *b, uint32_t len){
    uint32_t pos = 0;
    while(pos < len){
        uint64_t tag = 0;
        if(!ReadVarint(b, len, &pos, &tag)) break;
        uint32_t fn = (uint32_t)(tag >> 3), wt = (uint32_t)(tag & 7u);
        if(fn == 2u && wt == 2u){ /* repeated sns_client_event events */
            uint64_t elen = 0;
            if(!ReadVarint(b, len, &pos, &elen) || pos + elen > len) break;
            uint32_t ep = pos, eend = pos + (uint32_t)elen;
            uint32_t msg_id = 0;
            const uint8_t *pay = 0;
            uint32_t pay_len = 0;
            while(ep < eend){
                uint64_t etag = 0;
                if(!ReadVarint(b, eend, &ep, &etag)) break;
                uint32_t efn = (uint32_t)(etag >> 3), ewt = (uint32_t)(etag & 7u);
                if(efn == 1u && ewt == 0u){ uint64_t mv = 0; if(!ReadVarint(b, eend, &ep, &mv)) break; msg_id = (uint32_t)mv; }
                else if(efn == 3u && ewt == 2u){
                    uint64_t pl = 0; if(!ReadVarint(b, eend, &ep, &pl) || ep + pl > eend) break;
                    pay = b + ep; pay_len = (uint32_t)pl; ep += pay_len;
                } else if(!SkipPbField(b, eend, &ep, ewt)) break;
            }
            ipc->LastIndMsgId = msg_id;
            if(pay && pay_len){
                if(msg_id == 768u) ParseSuidEvent(ipc, pay, pay_len);
                else if(msg_id == 1025u) ParseAccelEvent(ipc, pay, pay_len);
            }
            pos = eend;
        } else {
            if(!SkipPbField(b, len, &pos, wt)) break;
        }
    }
}

void CkIpcOnQrtrPacket(CK_IPC_STATE *ipc, const uint8_t *pkt, uint32_t len){
    if(!ipc || !pkt || len < 32u) return;
    uint32_t ver      = R32(pkt + 0);
    uint32_t type     = R32(pkt + 4);
    uint32_t src_node = R32(pkt + 8);
    uint32_t src_port = R32(pkt + 12);
    uint32_t confirm  = R32(pkt + 16);
    uint32_t psize    = R32(pkt + 20);
    uint32_t dst_node = R32(pkt + 24);
    uint32_t dst_port = R32(pkt + 28);
    if(ver != 1u || 32u + psize > len) return;
    ipc->RxPackets++;

    /* Forward non-SNS-client QRTR packets to userspace RX ring (for tqftpserv, etc.) */
    if(!(type == 1u && dst_port == QRTR_CLIENT_PORT)){
        EnqueueRx(ipc, pkt, len);
    }

    const uint8_t *pay = pkt + 32u;

    if(confirm && type == 1u){
        /* Send QRTR_TYPE_RESUME_TX (7) so ADSP keeps streaming */
        uint8_t ctrl[20];
        for(uint32_t i=0; i<20; i++) ctrl[i] = 0;
        W32(ctrl + 0, 7u);
        W32(ctrl + 4, dst_node);
        W32(ctrl + 8, dst_port);
        EnqueueQrtr(ipc, 7u, QRTR_PORT_CTRL, src_node, QRTR_PORT_CTRL, ctrl, 20u);
    }

    if(type == 2u){ /* HELLO from ADSP */
        CkIpcQueueHello(ipc);
    } else if(type == 4u && psize >= 20u){ /* NEW_SERVER */
        uint32_t svc  = R32(pay + 4);
        uint32_t inst = R32(pay + 8);
        uint32_t node = R32(pay + 12);
        uint32_t port = R32(pay + 16);
        if(ipc->ServicesCount < CK_IPC_MAX_SVCS){
            uint32_t idx = ipc->ServicesCount++;
            ipc->Services[idx].Service  = svc;
            ipc->Services[idx].Instance = inst;
            ipc->Services[idx].Node     = node;
            ipc->Services[idx].Port     = port;
        }
        if(svc == SNS_CLIENT_SVC_ID && !ipc->SnsFound){
            ipc->SnsFound = 1u;
            ipc->SnsNode  = node;
            ipc->SnsPort  = port;
            SendSuidLookupAccel(ipc);
        }
    } else if(type == 1u && dst_port == QRTR_CLIENT_PORT && psize >= 7u){
        /* QMI response or indication from SNS_CLIENT_SVC */
        uint8_t  qtype = pay[0];
        uint16_t mid   = R16(pay + 3);
        uint16_t mlen  = R16(pay + 5);
        if(qtype == 0x04u && mid == 0x0021u && 7u + mlen <= psize){
            ipc->IndPackets++;
            uint32_t off = 7u, end = 7u + mlen;
            while(off + 3u <= end){
                uint8_t  tt = pay[off];
                uint16_t tl = R16(pay + off + 1);
                off += 3u;
                if(off + tl > end) break;
                if(tt == 0x02u && tl >= 2u){
                    uint16_t pblen = R16(pay + off);
                    if(2u + pblen <= tl){
                        ParseClientEventMsg(ipc, pay + off + 2u, pblen);
                    }
                }
                off += tl;
            }
        }
    }
    (void)src_port;
}
