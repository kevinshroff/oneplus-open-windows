/* SPDX-License-Identifier: MIT */
#ifndef G59_OBSERVER_H
#define G59_OBSERVER_H
#include <stdint.h>
#define G59_TRACE_LIMIT 128u
typedef struct { uint32_t Kind, Address, Value; } G59_OBS_EVENT;
typedef struct {
 uint32_t Code, Stage, Reads, Writes, Polls, Commands, Completion[5];
 uint8_t Revision[8], Anchor[8], Identity[8], Status, Configuration[8], Reserved[3];
 uint32_t TraceCount;
 G59_OBS_EVENT Trace[G59_TRACE_LIMIT];
} G59_OBS_RESULT;
typedef struct {
 void *Context;
 int (*Read)(void *, uint32_t, uint32_t *);
 int (*Write)(void *, uint32_t, uint32_t);
 void (*WaitMicrosecond)(void *);
} G59_OBS_IO;
enum { G59_OBS_OK=0, G59_OBS_IO_ERROR=1, G59_OBS_BUDGET=2,
 G59_OBS_ARBITER=3, G59_OBS_ROUTE=4, G59_OBS_PENDING=5,
 G59_OBS_TIMEOUT=6, G59_OBS_COMPLETION_ERROR=7, G59_OBS_IDENTITY=8 };
/* Output must be zeroed by caller. All addresses and commands are fixed. */
void G59Observe(const G59_OBS_IO *io, G59_OBS_RESULT *out);
#endif
