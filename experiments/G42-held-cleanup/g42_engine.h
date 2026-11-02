/* SPDX-License-Identifier: MIT */
#ifndef G42_ENGINE_H
#define G42_ENGINE_H
#include <stdint.h>
#define G42_ENGINE_FIELDS 24u
#define G42_ENGINE_TRACE 384u
typedef struct {uint32_t Kind,Address,Value;} G42_ENGINE_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,Dirty;
 uint32_t Before[24],During[24],After[24],DfsBefore[25],DfsAfter[25];
 uint32_t Index,SourceHz,BusHz,GuardBefore[10],GuardAfter[10];
 G42_ENGINE_EVENT Trace[G42_ENGINE_TRACE];
} G42_ENGINE_RESULT;
typedef struct {
 void *Context;int (*Read)(void*,uint32_t,uint32_t*);
 int (*Write)(void*,uint32_t,uint32_t);void (*WaitMicrosecond)(void*);int (*Transfer)(void*);
} G42_ENGINE_IO;
/* No commands, FIFO access, IRQ clears, power votes or GPIO writes. */
void G42ConfigureEngine(const G42_ENGINE_IO*,G42_ENGINE_RESULT*);
int G42EngineWriteAddress(uint32_t);
int G42CheckEngineHeld(const G42_ENGINE_IO*,G42_ENGINE_RESULT*,const uint32_t*);
int G42RestoreEngineHeld(const G42_ENGINE_IO*,G42_ENGINE_RESULT*);
#endif
