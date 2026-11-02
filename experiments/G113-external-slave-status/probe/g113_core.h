/* SPDX-License-Identifier: MIT */
#ifndef G113_CORE_H
#define G113_CORE_H
#include "g102_core.h"
#define G113_TRACE 16384u
#define G113_OWNED_IRQ 0x7fc07e7fu
#define G113_ERROR_IRQ 0x33007e0eu
typedef struct{uint32_t Kind,Address,Value,Command;}G113_EVENT;
typedef struct{
 uint32_t Size,Code,Stage,Commands,Completed,QueryMask,CleanMask,RestoredMask;
 uint32_t TraceCount,TraceDropped,Reads,Writes,Cancels,Aborts,Uncertain,Cancelled;
 uint64_t BeginUs,EndUs;
 uint32_t Values[2][10];
 G102_RESULT Before,After;
 G113_EVENT Trace[G113_TRACE];
}G113_RESULT;
typedef struct{
 void*Context;
 int(*Read)(void*,uint32_t,uint32_t*);
 int(*Write)(void*,uint32_t,uint32_t);
 int(*Available)(void*);
 uint64_t(*NowUs)(void*);
 void(*DelayUs)(void*,uint32_t);
}G113_IO;
enum{G113_OK,G113_ARGUMENT,G113_PREFLIGHT,G113_IO_ERROR,G113_LIMIT,G113_CANCELLED,
 G113_TIME_ERROR,G113_TIMEOUT,G113_BUS_ERROR,G113_FIFO_ERROR,G113_DIRTY,G113_RESTORE,G113_IDENTITY};
void G113Identify(const G113_IO*,G113_RESULT*);
#endif
