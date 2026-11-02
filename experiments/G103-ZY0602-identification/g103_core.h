/* SPDX-License-Identifier: MIT */
#ifndef G103_CORE_H
#define G103_CORE_H
#include "g102_core.h"
#define G103_TRACE 16384u
#define G103_OWNED_IRQ 0x7fc07e7fu
#define G103_ERROR_IRQ 0x33007e0eu
typedef struct{uint32_t Kind,Address,Value,Command;}G103_EVENT;
typedef struct{
 uint32_t Size,Code,Stage,Commands,Completed,QueryMask,CleanMask,RestoredMask;
 uint32_t TraceCount,TraceDropped,Reads,Writes,Cancels,Aborts,Uncertain,Cancelled;
 uint64_t BeginUs,EndUs;
 uint32_t Values[2][3];
 G102_RESULT Before,After;
 G103_EVENT Trace[G103_TRACE];
}G103_RESULT;
typedef struct{
 void*Context;
 int(*Read)(void*,uint32_t,uint32_t*);
 int(*Write)(void*,uint32_t,uint32_t);
 int(*Available)(void*);
 uint64_t(*NowUs)(void*);
 void(*DelayUs)(void*,uint32_t);
}G103_IO;
enum{G103_OK,G103_ARGUMENT,G103_PREFLIGHT,G103_IO_ERROR,G103_LIMIT,G103_CANCELLED,
 G103_TIME_ERROR,G103_TIMEOUT,G103_BUS_ERROR,G103_FIFO_ERROR,G103_DIRTY,G103_RESTORE};
void G103Identify(const G103_IO*,G103_RESULT*);
#endif
