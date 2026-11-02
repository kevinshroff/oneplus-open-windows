/* SPDX-License-Identifier: MIT */
#ifndef G41_SPI_H
#define G41_SPI_H
#include <stdint.h>
#include "g41_engine.h"
typedef struct {uint32_t Kind,Address,Value;} G41_SPI_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,DirtyPins,VoteDirty;
 uint32_t BeforeClock[6],AfterClock[6],BeforePins[16],DuringPins[16],AfterPins[16],Identity[8],VoteEnabled;
 G41_SPI_EVENT Trace[128];
 G41_ENGINE_RESULT Engine;
} G41_SPI_RESULT;
typedef struct {
 void *Context;int (*Read)(void*,uint32_t,uint32_t*);
 int (*Write)(void*,uint32_t,uint32_t);void (*WaitMicrosecond)(void*);int (*Transfer)(void*);
} G41_SPI_IO;
/* Caller zeroes result. No supply/reset/FIFO/command/interrupt writes exist. */
void G41PrepareSpi(const G41_SPI_IO*,G41_SPI_RESULT*);
#endif
