/* SPDX-License-Identifier: MIT */
#ifndef G44_SPI_H
#define G44_SPI_H
#include <stdint.h>
#include "g44_engine.h"
typedef struct {uint32_t Kind,Address,Value;} G44_SPI_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,DirtyPins,VoteDirty;
 uint32_t BeforeClock[6],AfterClock[6],BeforePins[16],DuringPins[16],AfterPins[16],Identity[8],VoteEnabled;
 G44_SPI_EVENT Trace[128];
 G44_ENGINE_RESULT Engine;
} G44_SPI_RESULT;
typedef struct {
 void *Context;int (*Read)(void*,uint32_t,uint32_t*);
 int (*Write)(void*,uint32_t,uint32_t);void (*WaitMicrosecond)(void*);int (*Transfer)(void*);
} G44_SPI_IO;
/* Caller zeroes result. No supply/reset/FIFO/command/interrupt writes exist. */
void G44PrepareSpi(const G44_SPI_IO*,G44_SPI_RESULT*);
int G44CheckSpiHeld(const G44_SPI_IO*,G44_SPI_RESULT*,const uint32_t*,const uint32_t*);
int G44RestoreSpiHeld(const G44_SPI_IO*,G44_SPI_RESULT*);
#endif
