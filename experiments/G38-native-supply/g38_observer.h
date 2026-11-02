/* SPDX-License-Identifier: MIT */
#ifndef G38_OBSERVER_H
#define G38_OBSERVER_H
#include <stdint.h>
#define G38_TRACE_LIMIT 128u
typedef struct { uint32_t Kind, Address, Value; } G38_OBS_EVENT;
typedef struct {
 uint32_t Code, Stage, Reads, Writes, Polls, Commands, Completion[5];
 uint8_t Revision[8], Anchor[8], Identity[8], Status, Configuration[8], Reserved[3];
 uint32_t TraceCount;
 G38_OBS_EVENT Trace[G38_TRACE_LIMIT];
} G38_OBS_RESULT;
typedef struct {
 void *Context;
 int (*Read)(void *, uint32_t, uint32_t *);
 int (*Write)(void *, uint32_t, uint32_t);
 void (*WaitMicrosecond)(void *);
} G38_OBS_IO;
enum { G38_OBS_OK=0, G38_OBS_IO_ERROR=1, G38_OBS_BUDGET=2,
 G38_OBS_ARBITER=3, G38_OBS_ROUTE=4, G38_OBS_PENDING=5,
 G38_OBS_TIMEOUT=6, G38_OBS_COMPLETION_ERROR=7, G38_OBS_IDENTITY=8 };
/* Output must be zeroed by caller. All addresses and commands are fixed. */
void G38Observe(const G38_OBS_IO *io, G38_OBS_RESULT *out);
#endif
