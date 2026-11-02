/* SPDX-License-Identifier: MIT */
#ifndef G69_CLOCK_H
#define G69_CLOCK_H
#include "g69_protocol.h"
typedef struct {
 void *Context;
 int (*Available)(void *);
 int (*Read)(void *,uint32_t,uint32_t *);
 int (*Write)(void *,uint32_t,uint32_t);
 void (*WaitOneUs)(void *);
} G69_CLOCK_IO;
extern const uint32_t G69PageBase[3],G69RegisterPage[6],G69RegisterOffset[6];
/* Lists contain exact 20-byte ARM64 CM descriptors; paired indices may reorder.
 * No mapping or register access is performed by resource validation. */
int G69ValidateResources(const uint8_t raw[3][20],const uint8_t translated[3][20],uint32_t index[3]);
/* Caller serializes one owner and zeroes a fresh result. No arbitrary register,
 * rate, GPIO, engine or supply operation is exposed by this clock component. */
int G69ClockAcquire(const G69_CLOCK_IO *,G69_CLOCK_RESULT *,uint64_t nonce);
int G69ClockRelease(const G69_CLOCK_IO *,G69_CLOCK_RESULT *,uint64_t nonce);
#endif
