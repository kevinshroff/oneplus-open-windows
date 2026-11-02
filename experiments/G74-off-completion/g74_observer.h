/* SPDX-License-Identifier: MIT */
#ifndef G74_OBSERVER_H
#define G74_OBSERVER_H
#include <stdint.h>
#define G74_TRACE_LIMIT 128u
typedef struct { uint32_t Kind, Address, Value; } G74_OBS_EVENT;
typedef struct {
 uint32_t Code, Stage, Reads, Writes, Polls, Commands, Completion[5];
 uint8_t Revision[8], Anchor[8], Identity[8], Status, Configuration[8], Reserved[3];
 uint32_t TraceCount;
 G74_OBS_EVENT Trace[G74_TRACE_LIMIT];
} G74_OBS_RESULT;
typedef struct {
 void *Context;
 int (*Read)(void *, uint32_t, uint32_t *);
 int (*Write)(void *, uint32_t, uint32_t);
 void (*WaitMicrosecond)(void *);
} G74_OBS_IO;
enum { G74_OBS_OK=0, G74_OBS_IO_ERROR=1, G74_OBS_BUDGET=2,
 G74_OBS_ARBITER=3, G74_OBS_ROUTE=4, G74_OBS_PENDING=5,
 G74_OBS_TIMEOUT=6, G74_OBS_COMPLETION_ERROR=7, G74_OBS_IDENTITY=8 };
/* Output must be zeroed by caller. All addresses and commands are fixed. */
void G74Observe(const G74_OBS_IO *io, G74_OBS_RESULT *out);
#endif
