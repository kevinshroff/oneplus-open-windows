/* SPDX-License-Identifier: MIT */
#ifndef G39_SPI_H
#define G39_SPI_H
#include <stdint.h>
#include "g39_engine.h"
typedef struct {uint32_t Kind,Address,Value;} G39_SPI_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,DirtyPins,VoteDirty;
 uint32_t BeforeClock[6],AfterClock[6],BeforePins[16],DuringPins[16],AfterPins[16],Identity[8],VoteEnabled;
 G39_SPI_EVENT Trace[128];
 G39_ENGINE_RESULT Engine;
} G39_SPI_RESULT;
typedef struct {
 void *Context;int (*Read)(void*,uint32_t,uint32_t*);
 int (*Write)(void*,uint32_t,uint32_t);void (*WaitMicrosecond)(void*);int (*Transfer)(void*);
} G39_SPI_IO;
/* Caller zeroes result. No supply/reset/FIFO/command/interrupt writes exist. */
void G39PrepareSpi(const G39_SPI_IO*,G39_SPI_RESULT*);
#endif
