/* SPDX-License-Identifier: MIT */
#ifndef G96_ENGINE_H
#define G96_ENGINE_H
#include <stdint.h>
#define G96_ENGINE_FIELDS 24u
#define G96_ENGINE_TRACE 384u
typedef struct {uint32_t Kind,Address,Value;} G96_ENGINE_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,Dirty;
 uint32_t Before[24],During[24],After[24],DfsBefore[25],DfsAfter[25];
 uint32_t Index,SourceHz,BusHz,GuardBefore[10],GuardAfter[10];
 G96_ENGINE_EVENT Trace[G96_ENGINE_TRACE];
} G96_ENGINE_RESULT;
typedef struct {
 void *Context;int (*Read)(void*,uint32_t,uint32_t*);
 int (*Write)(void*,uint32_t,uint32_t);void (*WaitMicrosecond)(void*);int (*Transfer)(void*);
} G96_ENGINE_IO;
/* No commands, FIFO access, IRQ clears, power votes or GPIO writes. */
void G96ConfigureEngine(const G96_ENGINE_IO*,G96_ENGINE_RESULT*);
int G96EngineWriteAddress(uint32_t);
#endif
