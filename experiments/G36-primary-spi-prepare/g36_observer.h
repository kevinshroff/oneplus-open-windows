/* SPDX-License-Identifier: MIT */
#ifndef G36_OBSERVER_H
#define G36_OBSERVER_H
#include <stdint.h>
#define G36_TRACE_LIMIT 128u
typedef struct { uint32_t Kind, Address, Value; } G36_OBS_EVENT;
typedef struct {
 uint32_t Code, Stage, Reads, Writes, Polls, Commands, Completion[5];
 uint8_t Revision[8], Anchor[8], Identity[8], Status, Configuration[8], Reserved[3];
 uint32_t TraceCount;
 G36_OBS_EVENT Trace[G36_TRACE_LIMIT];
} G36_OBS_RESULT;
typedef struct {
 void *Context;
 int (*Read)(void *, uint32_t, uint32_t *);
 int (*Write)(void *, uint32_t, uint32_t);
 void (*WaitMicrosecond)(void *);
} G36_OBS_IO;
enum { G36_OBS_OK=0, G36_OBS_IO_ERROR=1, G36_OBS_BUDGET=2,
 G36_OBS_ARBITER=3, G36_OBS_ROUTE=4, G36_OBS_PENDING=5,
 G36_OBS_TIMEOUT=6, G36_OBS_COMPLETION_ERROR=7, G36_OBS_IDENTITY=8 };
/* Output must be zeroed by caller. All addresses and commands are fixed. */
void G36Observe(const G36_OBS_IO *io, G36_OBS_RESULT *out);
#endif
