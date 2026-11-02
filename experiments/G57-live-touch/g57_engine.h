/* SPDX-License-Identifier: MIT */
#ifndef G57_ENGINE_H
#define G57_ENGINE_H
#include <stdint.h>
#define G57_ENGINE_FIELDS 24u
#define G57_ENGINE_TRACE 384u
typedef struct {uint32_t Kind,Address,Value;} G57_ENGINE_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,Dirty;
 uint32_t Before[24],During[24],After[24],DfsBefore[25],DfsAfter[25];
 uint32_t Index,SourceHz,BusHz,GuardBefore[10],GuardAfter[10];
 G57_ENGINE_EVENT Trace[G57_ENGINE_TRACE];
} G57_ENGINE_RESULT;
typedef struct {
 void *Context;int (*Read)(void*,uint32_t,uint32_t*);
 int (*Write)(void*,uint32_t,uint32_t);void (*WaitMicrosecond)(void*);int (*Transfer)(void*);
} G57_ENGINE_IO;
/* No commands, FIFO access, IRQ clears, power votes or GPIO writes. */
void G57ConfigureEngine(const G57_ENGINE_IO*,G57_ENGINE_RESULT*);
int G57EngineWriteAddress(uint32_t);
#endif
