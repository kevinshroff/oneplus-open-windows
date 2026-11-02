/* SPDX-License-Identifier: MIT */
#ifndef G98_OBSERVER_H
#define G98_OBSERVER_H
#include <stdint.h>
#define G98_TRACE_LIMIT 128u
typedef struct { uint32_t Kind, Address, Value; } G98_OBS_EVENT;
typedef struct {
 uint32_t Code, Stage, Reads, Writes, Polls, Commands, Completion[5];
 uint8_t Revision[8], Anchor[8], Identity[8], Status, Configuration[8], Reserved[3];
 uint32_t TraceCount;
 G98_OBS_EVENT Trace[G98_TRACE_LIMIT];
} G98_OBS_RESULT;
typedef struct {
 void *Context;
 int (*Read)(void *, uint32_t, uint32_t *);
 int (*Write)(void *, uint32_t, uint32_t);
 void (*WaitMicrosecond)(void *);
 int (*Acquire)(void *);
 void (*Release)(void *, int uncertain);
} G98_OBS_IO;
enum { G98_OBS_OK=0, G98_OBS_IO_ERROR=1, G98_OBS_BUDGET=2,
 G98_OBS_ARBITER=3, G98_OBS_ROUTE=4, G98_OBS_PENDING=5,
 G98_OBS_GATE=9, G98_OBS_TIMEOUT=6, G98_OBS_COMPLETION_ERROR=7, G98_OBS_IDENTITY=8 };
/* Output must be zeroed by caller. All addresses and commands are fixed. */
void G98Observe(const G98_OBS_IO *io, G98_OBS_RESULT *out);
#endif
