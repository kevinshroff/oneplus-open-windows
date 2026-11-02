/* SPDX-License-Identifier: MIT */
#ifndef G49_SPI_H
#define G49_SPI_H
#include <stdint.h>
#include "g49_engine.h"
typedef struct {uint32_t Kind,Address,Value;} G49_SPI_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,DirtyPins,VoteDirty;
 uint32_t BeforeClock[6],AfterClock[6],BeforePins[16],DuringPins[16],AfterPins[16],Identity[8],VoteEnabled;
 G49_SPI_EVENT Trace[128];
 G49_ENGINE_RESULT Engine;
} G49_SPI_RESULT;
typedef struct {
 void *Context;int (*Read)(void*,uint32_t,uint32_t*);
 int (*Write)(void*,uint32_t,uint32_t);void (*WaitMicrosecond)(void*);int (*Transfer)(void*);
} G49_SPI_IO;
/* Caller zeroes result. No supply/reset/FIFO/command/interrupt writes exist. */
void G49PrepareSpi(const G49_SPI_IO*,G49_SPI_RESULT*);
#endif
