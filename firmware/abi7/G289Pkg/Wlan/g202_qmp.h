/* SPDX-License-Identifier: GPL-2.0-only
 * Bounded source port of the selected qcom_aoss/qcom-ipcc path. Source only.
 * A single pre-OS coordinator must serialize this shared channel with any
 * firmware QMP user. This source has no entrypoint or runtime/Windows claim.
 */
#ifndef G202_QMP_H
#define G202_QMP_H
#include "g202_rpmh_abi.h"
typedef struct {
 void*Context;
 G202_STATUS(*Read32)(void*,uint64_t,uint32_t*);
 G202_STATUS(*Write32)(void*,uint64_t,uint32_t);
 G202_STATUS(*Stall)(void*,uint32_t);
}G202_QMP_IO;
typedef struct {
 G202_QMP_IO Io;uint32_t Descriptor[15],Offset,Size;
 uint32_t Opened,Borrowed,Uncertain,NextFrame,Pending,ChannelChanged;
 G202_STATUS FirstError;
}G202_QMP;
/* Read descriptor twice with bounds and fixed source-version checks. */
G202_STATUS G202QmpInspect(G202_QMP*);
/* Borrows a fully up channel, or runs the source handshake only from local
 * DOWN. No speculative recovery/close of an unknown warm channel. */
G202_STATUS G202QmpOpen(G202_QMP*);
/* Strictly next of the13 fixed64-byte selected WLAN PDC frames. */
G202_STATUS G202QmpSendNextPdc(G202_QMP*);
/* Closes only a certain own channel. Borrowed channel is left up. A close
 * does not undo PDC policy; no readback/rollback command is known for it. */
G202_STATUS G202QmpClose(G202_QMP*);
G202_STATUS G202BindEfiQmp(G202_QMP*);
#endif
