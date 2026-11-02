/* SPDX-License-Identifier: MIT */
#ifndef G41_ENGINE_H
#define G41_ENGINE_H
#include <stdint.h>
#define G41_ENGINE_FIELDS 24u
#define G41_ENGINE_TRACE 384u
typedef struct {uint32_t Kind,Address,Value;} G41_ENGINE_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,Dirty;
 uint32_t Before[24],During[24],After[24],DfsBefore[25],DfsAfter[25];
 uint32_t Index,SourceHz,BusHz,GuardBefore[10],GuardAfter[10];
 G41_ENGINE_EVENT Trace[G41_ENGINE_TRACE];
} G41_ENGINE_RESULT;
typedef struct {
 void *Context;int (*Read)(void*,uint32_t,uint32_t*);
 int (*Write)(void*,uint32_t,uint32_t);void (*WaitMicrosecond)(void*);int (*Transfer)(void*);
} G41_ENGINE_IO;
/* No commands, FIFO access, IRQ clears, power votes or GPIO writes. */
void G41ConfigureEngine(const G41_ENGINE_IO*,G41_ENGINE_RESULT*);
int G41EngineWriteAddress(uint32_t);
#endif
