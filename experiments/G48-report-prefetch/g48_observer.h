/* SPDX-License-Identifier: MIT */
#ifndef G48_OBSERVER_H
#define G48_OBSERVER_H
#include <stdint.h>
#define G48_TRACE_LIMIT 128u
typedef struct { uint32_t Kind, Address, Value; } G48_OBS_EVENT;
typedef struct {
 uint32_t Code, Stage, Reads, Writes, Polls, Commands, Completion[5];
 uint8_t Revision[8], Anchor[8], Identity[8], Status, Configuration[8], Reserved[3];
 uint32_t TraceCount;
 G48_OBS_EVENT Trace[G48_TRACE_LIMIT];
} G48_OBS_RESULT;
typedef struct {
 void *Context;
 int (*Read)(void *, uint32_t, uint32_t *);
 int (*Write)(void *, uint32_t, uint32_t);
 void (*WaitMicrosecond)(void *);
} G48_OBS_IO;
enum { G48_OBS_OK=0, G48_OBS_IO_ERROR=1, G48_OBS_BUDGET=2,
 G48_OBS_ARBITER=3, G48_OBS_ROUTE=4, G48_OBS_PENDING=5,
 G48_OBS_TIMEOUT=6, G48_OBS_COMPLETION_ERROR=7, G48_OBS_IDENTITY=8 };
/* Output must be zeroed by caller. All addresses and commands are fixed. */
void G48Observe(const G48_OBS_IO *io, G48_OBS_RESULT *out);
#endif
