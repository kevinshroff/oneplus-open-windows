/* SPDX-License-Identifier: MIT */
#ifndef G45_ENGINE_H
#define G45_ENGINE_H
#include <stdint.h>
#define G45_ENGINE_FIELDS 24u
#define G45_ENGINE_TRACE 384u
typedef struct {uint32_t Kind,Address,Value;} G45_ENGINE_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,Dirty;
 uint32_t Before[24],During[24],After[24],DfsBefore[25],DfsAfter[25];
 uint32_t Index,SourceHz,BusHz,GuardBefore[10],GuardAfter[10];
 G45_ENGINE_EVENT Trace[G45_ENGINE_TRACE];
} G45_ENGINE_RESULT;
typedef struct {
 void *Context;int (*Read)(void*,uint32_t,uint32_t*);
 int (*Write)(void*,uint32_t,uint32_t);void (*WaitMicrosecond)(void*);int (*Transfer)(void*);
} G45_ENGINE_IO;
/* No commands, FIFO access, IRQ clears, power votes or GPIO writes. */
void G45ConfigureEngine(const G45_ENGINE_IO*,G45_ENGINE_RESULT*);
int G45EngineWriteAddress(uint32_t);
int G45CheckEngineHeld(const G45_ENGINE_IO*,G45_ENGINE_RESULT*,const uint32_t*);
int G45RestoreEngineHeld(const G45_ENGINE_IO*,G45_ENGINE_RESULT*);
#endif
