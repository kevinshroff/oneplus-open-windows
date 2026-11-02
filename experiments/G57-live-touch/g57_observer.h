/* SPDX-License-Identifier: MIT */
#ifndef G57_OBSERVER_H
#define G57_OBSERVER_H
#include <stdint.h>
#define G57_TRACE_LIMIT 128u
typedef struct { uint32_t Kind, Address, Value; } G57_OBS_EVENT;
typedef struct {
 uint32_t Code, Stage, Reads, Writes, Polls, Commands, Completion[5];
 uint8_t Revision[8], Anchor[8], Identity[8], Status, Configuration[8], Reserved[3];
 uint32_t TraceCount;
 G57_OBS_EVENT Trace[G57_TRACE_LIMIT];
} G57_OBS_RESULT;
typedef struct {
 void *Context;
 int (*Read)(void *, uint32_t, uint32_t *);
 int (*Write)(void *, uint32_t, uint32_t);
 void (*WaitMicrosecond)(void *);
} G57_OBS_IO;
enum { G57_OBS_OK=0, G57_OBS_IO_ERROR=1, G57_OBS_BUDGET=2,
 G57_OBS_ARBITER=3, G57_OBS_ROUTE=4, G57_OBS_PENDING=5,
 G57_OBS_TIMEOUT=6, G57_OBS_COMPLETION_ERROR=7, G57_OBS_IDENTITY=8 };
/* Output must be zeroed by caller. All addresses and commands are fixed. */
void G57Observe(const G57_OBS_IO *io, G57_OBS_RESULT *out);
#endif
