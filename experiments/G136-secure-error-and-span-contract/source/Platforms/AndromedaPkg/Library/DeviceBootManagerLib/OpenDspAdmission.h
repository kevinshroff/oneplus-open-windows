/* SPDX-License-Identifier: MIT */
#ifndef OPEN_DSP_ADMISSION_H
#define OPEN_DSP_ADMISSION_H
#include "OpenPasObserver.h"
typedef OP_U64 (*OPEN_AT_QUERY)(void *,OP_U64,unsigned);
typedef struct {
 OP_U64 Pages,Queries,FirstBad,ReadPar,WritePar;
 unsigned Refusal;
} OPEN_CPU_ADMISSION;
enum {OPEN_CPU_ARGUMENT=1,OPEN_CPU_READ_FAULT=2,OPEN_CPU_WRITE_FAULT=4,
 OPEN_CPU_ALIAS=8,OPEN_CPU_NOT_WB=16,OPEN_CPU_BUDGET=32};
/* Only stage-1 translation/permission admission. No target memory is accessed;
 * it establishes neither stage-2 policy nor DMA/physical-device ownership. */
unsigned OpenCheckCpuRange(OPEN_CPU_ADMISSION *,OPEN_AT_QUERY,void *,OP_U64,OP_U64);
OP_U64 OpenDspCurrentEl(void);
OP_U64 OpenDspAt(void *,OP_U64,unsigned);
#endif
