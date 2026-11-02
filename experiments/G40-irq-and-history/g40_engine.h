/* SPDX-License-Identifier: MIT */
#ifndef G40_ENGINE_H
#define G40_ENGINE_H
#include <stdint.h>
#define G40_ENGINE_FIELDS 24u
#define G40_ENGINE_TRACE 384u
typedef struct {uint32_t Kind,Address,Value;} G40_ENGINE_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,Dirty;
 uint32_t Before[24],During[24],After[24],DfsBefore[25],DfsAfter[25];
 uint32_t Index,SourceHz,BusHz,GuardBefore[10],GuardAfter[10];
 G40_ENGINE_EVENT Trace[G40_ENGINE_TRACE];
} G40_ENGINE_RESULT;
typedef struct {
 void *Context;int (*Read)(void*,uint32_t,uint32_t*);
 int (*Write)(void*,uint32_t,uint32_t);void (*WaitMicrosecond)(void*);int (*Transfer)(void*);
} G40_ENGINE_IO;
/* No commands, FIFO access, IRQ clears, power votes or GPIO writes. */
void G40ConfigureEngine(const G40_ENGINE_IO*,G40_ENGINE_RESULT*);
int G40EngineWriteAddress(uint32_t);
#endif
