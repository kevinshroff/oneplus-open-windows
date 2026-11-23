/* SPDX-License-Identifier: MIT
 * Repeatable GLINK SMEM transport for Qualcomm PMIC charger router (0x800a).
 */
#include "glink_core.h"

static uint16_t U16(const uint8_t *b){return (uint16_t)b[0]|((uint16_t)b[1]<<8);}
static uint32_t U32(const uint8_t *b){return (uint32_t)b[0]|((uint32_t)b[1]<<8)|((uint32_t)b[2]<<16)|((uint32_t)b[3]<<24);}
static void P16(uint8_t *b, uint16_t v){b[0]=(uint8_t)v;b[1]=(uint8_t)(v>>8);}
static void P32(uint8_t *b, uint32_t v){for(uint32_t i=0;i<4;i++)b[i]=(uint8_t)(v>>(i*8));}
static void Zero(void *p, uint32_t n){uint8_t *b=(uint8_t*)p;for(uint32_t i=0;i<n;i++)b[i]=0;}
static uint32_t Align8(uint32_t n){return (n+7u)&~7u;}
static uint32_t Used(uint32_t t, uint32_t h){return (h-t)&CK_FIFO_MASK;}
static uint32_t Free(uint32_t t, uint32_t h){return CK_FIFO_BYTES-1u-Used(t,h);}

static int IsChargerName(const uint8_t *b, uint32_t n){
    static const char target[]="PMIC_RTR_ADSP_APPS";
    if(n!=18u && !(n==19u && b[18]==0))return 0;
    for(uint32_t i=0;i<18u;i++)if(b[i]!=(uint8_t)target[i])return 0;
    return 1;
}

static int Fail(CK_GL_STATE *s, uint32_t code){
    s->Fault=code;s->Phase=CK_GL_FAILED;s->OpActive=0;return CK_GL_POLL_FAULT;
}

void CkGlInit(CK_GL_STATE *s){
    if(!s)return;
    Zero(s, (uint32_t)sizeof(*s));
    s->NextLocalId = 1;
}

int CkGlRequest(CK_GL_STATE *s, uint32_t op_kind, uint64_t now_us){
    if(!s || op_kind < CK_OP_SAMPLE || op_kind > CK_OP_ENABLE) return -1;
    if(s->Phase != CK_GL_READY || s->OpActive || s->CloseRequested) return 0;
    Zero(&s->Working, (uint32_t)sizeof(s->Working));
    s->OpActive = 1;
    s->OpKind = op_kind;
    s->OpBeginUs = now_us;
    s->Pending = 0;
    s->ReplyReceived = 0;
    s->TxDone = 0;
    s->Query = (op_kind == CK_OP_SAMPLE) ? 0u :
               (op_kind == CK_OP_SET_FV) ? CL_FV_QUERY :
               (op_kind == CK_OP_DISABLE) ? CL_RESTART_OFF_QUERY : CL_ENABLE_QUERY;
    return 1;
}

int CkGlRequestClose(CK_GL_STATE *s, uint64_t now_us){
    if(!s) return -1;
    if(s->Phase == CK_GL_CLOSED || s->Phase == CK_GL_FAILED) return 0;
    s->CloseRequested = 1;
    if(!s->CloseSinceUs) s->CloseSinceUs = now_us;
    if(s->Phase == CK_GL_READY) s->Phase = CK_GL_CLOSING;
    return 1;
}

static int SendFrame(CK_GL_STATE *s, const CK_GL_IO *io, const uint8_t *frame, uint32_t n){
    uint32_t aligned = Align8(n);
    if(aligned > CK_FRAME_BYTES) return 0;
    if(Free(s->LastDescriptor[0], s->OwnTx) < aligned) return 0;
    uint8_t padded[CK_FRAME_BYTES];
    Zero(padded, aligned);
    for(uint32_t i=0;i<n;i++) padded[i]=frame[i];
    if(!io->WriteTx(io->Context, s->OwnTx, padded, aligned)) return 0;
    uint32_t next = (s->OwnTx + aligned) & CK_FIFO_MASK;
    if(!io->PublishHostWord(io->Context, 1u, next)) return 0;
    s->OwnTx = next;
    s->TxFrames++;
    if(io->Kick(io->Context)) s->Kicks++;
    return 1;
}

static int SendCmd(CK_GL_STATE *s, const CK_GL_IO *io, uint16_t cmd, uint16_t p1, uint32_t p2){
    uint8_t f[8];
    P16(f+0, cmd); P16(f+2, p1); P32(f+4, p2);
    return SendFrame(s, io, f, 8u);
}

static int QueueIntent(CK_GL_STATE *s, const CK_GL_IO *io){
    for(uint32_t i=0;i<CK_INTENTS;i++){
        if(s->Local[i].State == 0){
            uint8_t f[16];
            uint32_t id = s->NextLocalId++;
            if(!id){ id = s->NextLocalId++; }
            P16(f+0, 5u); P16(f+2, 1u); P32(f+4, 1u); /* RX_INTENT, cid=1, count=1 */
            P32(f+8, CL_REPLY_LIMIT); P32(f+12, id);
            if(!SendFrame(s, io, f, 16u)) return 0;
            Zero(&s->Local[i], (uint32_t)sizeof(s->Local[i]));
            s->Local[i].Id = id;
            s->Local[i].State = 1;
            s->CurrentOffers++;
            return 1;
        }
    }
    return 0;
}

static void HandleRx(CK_GL_STATE *s, const CK_GL_IO *io, const uint8_t *f, uint32_t n, uint64_t now_us){
    if(n < 8u) return;
    uint16_t cmd = U16(f+0), p1 = U16(f+2);
    uint32_t p2 = U32(f+4);
    (void)io;
    switch(cmd){
    case 0u: /* VERSION */
        if(!s->VersionAckSent && p1 == 1u){
            /* ack in TX pump */
            s->VersionAckSent = 1u;
            SendCmd(s, io, 1u, 1u, 0u);
        }
        break;
    case 1u: /* VERSION_ACK */
        if(p1 == 1u) s->VersionAckSeen = 1u;
        break;
    case 2u: /* OPEN from remote */
        if(n >= 8u + p2 && IsChargerName(f+8, p2)){
            s->RemoteCid = p1;
            s->RemoteOpen = 1u;
            SendCmd(s, io, 4u, p1, 0u); /* OPEN_ACK */
            if(!s->OpenSent){
                static const char nm[] = "PMIC_RTR_ADSP_APPS";
                uint8_t of[32];
                Zero(of, 32u);
                P16(of+0, 2u); P16(of+2, 1u); P32(of+4, 19u);
                for(uint32_t i=0;i<18u;i++) of[8+i]=(uint8_t)nm[i];
                if(SendFrame(s, io, of, 32u)) s->OpenSent = 1u;
            }
        }
        break;
    case 4u: /* OPEN_ACK */
        if(p1 == 1u) s->OpenAcked = 1u;
        break;
    case 3u: /* CLOSE from remote */
        if(p1 == s->RemoteCid){
            s->RemoteClosed = 1u;
            SendCmd(s, io, 11u, p1, 0u); /* CLOSE_ACK */
            s->RemoteCloseAcked = 1u;
        }
        break;
    case 11u: /* CLOSE_ACK */
        if(p1 == 1u) s->CloseAcked = 1u;
        break;
    case 5u: /* RX_INTENT from remote */
        if(p1 == s->RemoteCid && p2 >= 1u && n >= 8u + p2*8u){
            for(uint32_t k=0;k<p2;k++){
                uint32_t sz = U32(f+8+k*8), id = U32(f+12+k*8);
                uint32_t slot = CK_INTENTS;
                for(uint32_t i=0;i<CK_INTENTS;i++){
                    if(s->Remote[i].State && s->Remote[i].Id == id){ slot = i; break; }
                }
                if(slot == CK_INTENTS){
                    for(uint32_t i=0;i<CK_INTENTS;i++){
                        if(s->Remote[i].State == 0){ slot = i; break; }
                    }
                }
                if(slot < CK_INTENTS){
                    s->Remote[slot].Id = id;
                    s->Remote[slot].Bytes = sz;
                    s->Remote[slot].State = 1;
                }
            }
            s->IntentRequestPending = 0;
        }
        break;
    case 6u:  /* RX_DONE */
    case 14u: /* RX_DONE_W_REUSE */
        if(p1 == s->RemoteCid){
            s->TxDone = 1u;
            for(uint32_t i=0;i<CK_INTENTS;i++){
                if(s->Remote[i].State == 2 && s->Remote[i].Id == p2){
                    s->Remote[i].State = (cmd == 14u) ? 1 : 0;
                    break;
                }
            }
        }
        break;
    case 7u: /* RX_INTENT_REQ */
        if(p1 == s->RemoteCid){
            uint32_t ok = (p2 && p2 <= CL_REPLY_LIMIT) ? 1u : 0u;
            if(ok) QueueIntent(s, io);
            SendCmd(s, io, 8u, 1u, ok); /* RX_INTENT_REQ_ACK */
        }
        break;
    case 8u: /* RX_INTENT_REQ_ACK */
        if(p1 == s->RemoteCid && p2 == 0u) s->IntentRequestPending = 0;
        break;
    case 9u:  /* TX_DATA */
    case 12u: /* TX_DATA_CONT */
        if(p1 == s->RemoteCid && n >= 16u){
            uint32_t chunk = U32(f+8), rem = U32(f+12);
            if(16u + chunk <= n){
                for(uint32_t i=0;i<CK_INTENTS;i++){
                    if(s->Local[i].State == 1 && s->Local[i].Id == p2){
                        if(s->Local[i].Used + chunk <= CL_REPLY_LIMIT){
                            for(uint32_t k=0;k<chunk;k++) s->Local[i].Data[s->Local[i].Used+k] = f[16+k];
                            s->Local[i].Used += chunk;
                            s->Local[i].Remaining = rem;
                        }
                        if(rem == 0u){
                            /* Complete message received */
                            if(s->OpActive && s->Pending){
                                if(CLDecodeReply(s->Query, s->Local[i].Data, s->Local[i].Used, &s->Working)){
                                    s->ReplyReceived = 1u;
                                }
                            }
                            SendCmd(s, io, 6u, 1u, p2); /* RX_DONE */
                            s->Local[i].State = 0;
                            if(s->CurrentOffers) s->CurrentOffers--;
                            QueueIntent(s, io);
                        }
                        break;
                    }
                }
            }
        }
        break;
    default:
        break;
    }
    (void)now_us;
}

static uint32_t FrameLen(const uint8_t *hdr){
    uint16_t cmd = U16(hdr+0);
    uint32_t p2 = U32(hdr+4);
    switch(cmd){
    case 2u: return Align8(8u + p2);
    case 5u: return Align8(8u + p2*8u);
    case 9u:
    case 12u: return 0u; /* need 16-byte header to read chunk size */
    default: return 8u;
    }
}

int CkGlPoll(CK_GL_STATE *s, const CK_GL_IO *io, uint64_t now_us){
    uint32_t d[8];
    if(!s || !io || !io->ReadDescriptor || !io->ReadRx || !io->WriteTx || !io->PublishHostWord || !io->Kick)
        return CK_GL_POLL_FAULT;
    if(s->Phase == CK_GL_CLOSED) return CK_GL_POLL_CLOSED;
    if(s->Phase == CK_GL_FAILED) return CK_GL_POLL_FAULT;

    if(!s->BeginUs) s->BeginUs = now_us;
    s->LastNowUs = now_us;

    if(!io->ReadDescriptor(io->Context, d)) return Fail(s, 1u);
    for(uint32_t i=0;i<8;i++) s->LastDescriptor[i] = d[i];

    if(s->Phase == CK_GL_NEW){
        s->OwnTx = d[1];
        s->OwnRx = d[2];
        s->Phase = CK_GL_NEGOTIATING;
    }

    int progress = 0;
    /* 1. Drain RX FIFO */
    uint32_t avail = Used(s->OwnRx, d[3]);
    if(avail >= 8u){
        uint8_t hdr[16];
        if(!io->ReadRx(io->Context, s->OwnRx, hdr, 8u)) return Fail(s, 2u);
        uint16_t cmd = U16(hdr+0);
        uint32_t flen = FrameLen(hdr);
        if(cmd == 9u || cmd == 12u){
            if(avail >= 16u){
                if(!io->ReadRx(io->Context, s->OwnRx, hdr, 16u)) return Fail(s, 2u);
                flen = Align8(16u + U32(hdr+8));
            } else {
                flen = 0u;
            }
        }
        if(flen >= 8u && flen <= CK_FRAME_BYTES && avail >= flen){
            uint8_t buf[CK_FRAME_BYTES];
            if(!io->ReadRx(io->Context, s->OwnRx, buf, flen)) return Fail(s, 2u);
            uint32_t next_rx = (s->OwnRx + flen) & CK_FIFO_MASK;
            if(!io->PublishHostWord(io->Context, 2u, next_rx)) return Fail(s, 3u);
            s->OwnRx = next_rx;
            s->RxFrames++;
            HandleRx(s, io, buf, flen, now_us);
            progress = 1;
        }
    }

    /* 2. State machine progression */
    if(s->Phase == CK_GL_NEGOTIATING){
        if(!s->VersionSent){
            if(SendCmd(s, io, 0u, 1u, 0u)){ s->VersionSent = 1u; progress = 1; }
        }
        if(s->VersionAckSeen && s->VersionAckSent){
            s->Phase = CK_GL_OPENING;
            progress = 1;
        } else if(now_us - s->BeginUs > CK_OPEN_US){
            return Fail(s, 10u);
        }
    } else if(s->Phase == CK_GL_OPENING){
        if(s->OpenAcked && s->RemoteOpen){
            while(s->CurrentOffers < 4u){
                if(!QueueIntent(s, io)) break;
                progress = 1;
            }
            s->Phase = s->CloseRequested ? CK_GL_CLOSING : CK_GL_READY;
            progress = 1;
        } else if(now_us - s->BeginUs > CK_OPEN_US){
            return Fail(s, 11u);
        }
    } else if(s->Phase == CK_GL_CLOSING){
        if(!s->CloseSent){
            if(SendCmd(s, io, 3u, 1u, 0u)){ s->CloseSent = 1u; progress = 1; }
        }
        if(s->CloseAcked){
            s->Phase = CK_GL_CLOSED;
            return CK_GL_POLL_CLOSED;
        }
        if(now_us - s->CloseSinceUs > CK_CLOSE_US){
            s->Phase = CK_GL_CLOSED;
            return CK_GL_POLL_CLOSED;
        }
    } else if(s->Phase == CK_GL_READY && s->OpActive){
        if(!s->Pending){
            uint8_t payload[24];
            uint32_t plen = CLBuildQuery(s->Query, payload);
            if(!plen) return Fail(s, 12u);
            /* Find remote intent */
            uint32_t ridx = CK_INTENTS;
            for(uint32_t i=0;i<CK_INTENTS;i++){
                if(s->Remote[i].State == 1 && s->Remote[i].Bytes >= plen){ ridx = i; break; }
            }
            if(ridx == CK_INTENTS){
                if(!s->IntentRequestPending){
                    if(SendCmd(s, io, 7u, 1u, plen)){ s->IntentRequestPending = 1u; progress = 1; }
                }
            } else {
                uint8_t f[64];
                Zero(f, 64u);
                P16(f+0, 9u); P16(f+2, 1u); P32(f+4, s->Remote[ridx].Id);
                P32(f+8, plen); P32(f+12, 0u);
                for(uint32_t k=0;k<plen;k++) f[16+k] = payload[k];
                if(SendFrame(s, io, f, 16u + plen)){
                    s->Remote[ridx].State = 2;
                    s->Pending = 1u;
                    s->ReplyReceived = 0u;
                    s->TxDone = 0u;
                    s->PendingSinceUs = now_us;
                    progress = 1;
                }
            }
        } else {
            if(s->ReplyReceived){
                s->Pending = 0u;
                s->ReplyReceived = 0u;
                if(s->OpKind == CK_OP_SAMPLE && s->Query + 1u < CL_GET_COUNT){
                    s->Query++;
                } else {
                    s->LastBattery = s->Working;
                    s->LastCompletedOp = s->OpKind;
                    s->LastOpOk = (s->Working.ServiceRejectedMask == 0u) ? 1u : 0u;
                    s->OpActive = 0u;
                    s->OpsCompleted++;
                }
                progress = 1;
            } else if(now_us - s->PendingSinceUs > CK_RPC_US || now_us - s->OpBeginUs > CK_BATCH_US){
                /* Timeout on single op: abort op cleanly without poisoning whole driver */
                s->LastCompletedOp = s->OpKind;
                s->LastOpOk = 0u;
                s->OpActive = 0u;
                s->Pending = 0u;
                progress = 1;
            }
        }
    }
    return progress ? CK_GL_POLL_PROGRESS : CK_GL_POLL_IDLE;
}
