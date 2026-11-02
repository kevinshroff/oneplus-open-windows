/* SPDX-License-Identifier: MIT */
#ifndef G104_CORE_H
#define G104_CORE_H
#include "g102_core.h"
#define G104_TRACE 16384u
#define G104_RX_WORD_COUNT_MASK 0x01ffffffu
#define G104_OWNED_IRQ 0x7fc07e7fu
#define G104_ERROR_IRQ 0x33007e0eu
typedef struct{uint32_t Kind,Address,Value,Command;}G104_EVENT;
typedef struct{
 uint32_t Size,Code,Stage,Commands,Completed,QueryMask,CleanMask,RestoredMask;
 uint32_t TraceCount,TraceDropped,Reads,Writes,Cancels,Aborts,Uncertain,Cancelled;
 uint64_t BeginUs,EndUs;
 uint32_t Values[2][10];
 G102_RESULT Before,After;
 G104_EVENT Trace[G104_TRACE];
}G104_RESULT;
typedef struct{
 void*Context;
 int(*Read)(void*,uint32_t,uint32_t*);
 int(*Write)(void*,uint32_t,uint32_t);
 int(*Available)(void*);
 uint64_t(*NowUs)(void*);
 void(*DelayUs)(void*,uint32_t);
}G104_IO;
enum{G104_OK,G104_ARGUMENT,G104_PREFLIGHT,G104_IO_ERROR,G104_LIMIT,G104_CANCELLED,
 G104_TIME_ERROR,G104_TIMEOUT,G104_BUS_ERROR,G104_FIFO_ERROR,G104_DIRTY,G104_RESTORE,G104_IDENTITY};
void G104Identify(const G104_IO*,G104_RESULT*);
#endif
