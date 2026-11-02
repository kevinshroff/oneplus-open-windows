/* SPDX-License-Identifier: MIT */
#ifndef G93_OBSERVER_H
#define G93_OBSERVER_H
#include <stdint.h>
#define G93_TRACE_LIMIT 128u
typedef struct { uint32_t Kind, Address, Value; } G93_OBS_EVENT;
typedef struct {
 uint32_t Code, Stage, Reads, Writes, Polls, Commands, Completion[5];
 uint8_t Revision[8], Anchor[8], Identity[8], Status, Configuration[8], Reserved[3];
 uint32_t TraceCount;
 G93_OBS_EVENT Trace[G93_TRACE_LIMIT];
} G93_OBS_RESULT;
typedef struct {
 void *Context;
 int (*Read)(void *, uint32_t, uint32_t *);
 int (*Write)(void *, uint32_t, uint32_t);
 void (*WaitMicrosecond)(void *);
} G93_OBS_IO;
enum { G93_OBS_OK=0, G93_OBS_IO_ERROR=1, G93_OBS_BUDGET=2,
 G93_OBS_ARBITER=3, G93_OBS_ROUTE=4, G93_OBS_PENDING=5,
 G93_OBS_TIMEOUT=6, G93_OBS_COMPLETION_ERROR=7, G93_OBS_IDENTITY=8 };
/* Output must be zeroed by caller. All addresses and commands are fixed. */
void G93Observe(const G93_OBS_IO *io, G93_OBS_RESULT *out);
#endif
