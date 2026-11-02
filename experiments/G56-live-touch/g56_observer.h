/* SPDX-License-Identifier: MIT */
#ifndef G56_OBSERVER_H
#define G56_OBSERVER_H
#include <stdint.h>
#define G56_TRACE_LIMIT 128u
typedef struct { uint32_t Kind, Address, Value; } G56_OBS_EVENT;
typedef struct {
 uint32_t Code, Stage, Reads, Writes, Polls, Commands, Completion[5];
 uint8_t Revision[8], Anchor[8], Identity[8], Status, Configuration[8], Reserved[3];
 uint32_t TraceCount;
 G56_OBS_EVENT Trace[G56_TRACE_LIMIT];
} G56_OBS_RESULT;
typedef struct {
 void *Context;
 int (*Read)(void *, uint32_t, uint32_t *);
 int (*Write)(void *, uint32_t, uint32_t);
 void (*WaitMicrosecond)(void *);
} G56_OBS_IO;
enum { G56_OBS_OK=0, G56_OBS_IO_ERROR=1, G56_OBS_BUDGET=2,
 G56_OBS_ARBITER=3, G56_OBS_ROUTE=4, G56_OBS_PENDING=5,
 G56_OBS_TIMEOUT=6, G56_OBS_COMPLETION_ERROR=7, G56_OBS_IDENTITY=8 };
/* Output must be zeroed by caller. All addresses and commands are fixed. */
void G56Observe(const G56_OBS_IO *io, G56_OBS_RESULT *out);
#endif
