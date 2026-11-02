/* SPDX-License-Identifier: MIT */
#ifndef G45_OBSERVER_H
#define G45_OBSERVER_H
#include <stdint.h>
#define G45_TRACE_LIMIT 128u
typedef struct { uint32_t Kind, Address, Value; } G45_OBS_EVENT;
typedef struct {
 uint32_t Code, Stage, Reads, Writes, Polls, Commands, Completion[5];
 uint8_t Revision[8], Anchor[8], Identity[8], Status, Configuration[8], Reserved[3];
 uint32_t TraceCount;
 G45_OBS_EVENT Trace[G45_TRACE_LIMIT];
} G45_OBS_RESULT;
typedef struct {
 void *Context;
 int (*Read)(void *, uint32_t, uint32_t *);
 int (*Write)(void *, uint32_t, uint32_t);
 void (*WaitMicrosecond)(void *);
} G45_OBS_IO;
enum { G45_OBS_OK=0, G45_OBS_IO_ERROR=1, G45_OBS_BUDGET=2,
 G45_OBS_ARBITER=3, G45_OBS_ROUTE=4, G45_OBS_PENDING=5,
 G45_OBS_TIMEOUT=6, G45_OBS_COMPLETION_ERROR=7, G45_OBS_IDENTITY=8 };
/* Output must be zeroed by caller. All addresses and commands are fixed. */
void G45Observe(const G45_OBS_IO *io, G45_OBS_RESULT *out);
#endif
