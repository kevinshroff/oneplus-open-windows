/* SPDX-License-Identifier: MIT */
#ifndef G98_ENGINE_H
#define G98_ENGINE_H
#include <stdint.h>
#define G98_ENGINE_FIELDS 24u
#define G98_ENGINE_TRACE 384u
typedef struct {uint32_t Kind,Address,Value;} G98_ENGINE_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,Dirty;
 uint32_t Before[24],During[24],After[24],DfsBefore[25],DfsAfter[25];
 uint32_t Index,SourceHz,BusHz,GuardBefore[10],GuardAfter[10];
 G98_ENGINE_EVENT Trace[G98_ENGINE_TRACE];
} G98_ENGINE_RESULT;
typedef struct {
 void *Context;int (*Read)(void*,uint32_t,uint32_t*);
 int (*Write)(void*,uint32_t,uint32_t);void (*WaitMicrosecond)(void*);int (*Transfer)(void*);
} G98_ENGINE_IO;
/* No commands, FIFO access, IRQ clears, power votes or GPIO writes. */
void G98ConfigureEngine(const G98_ENGINE_IO*,G98_ENGINE_RESULT*);
int G98EngineWriteAddress(uint32_t);
#endif
