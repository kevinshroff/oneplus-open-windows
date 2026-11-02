/* SPDX-License-Identifier: MIT */
#ifndef G70_CONSUMER_H
#define G70_CONSUMER_H
#include "g70_clock.h"
extern const uint32_t G70MapBase[4],G70MapBytes[4];
extern const uint32_t G70EngineOffset[10],G70EngineExpected[10];
typedef struct {
 G70_CLOCK_IO Clock;
 int (*ReadEngine)(void *,uint32_t,uint32_t *);
} G70_CONSUMER_IO;
/* Exact paired ARM64 CM descriptors; IRQ is recorded but not connected.
 * The translated vector is assigned by Windows and is never programmed here. */
int G70ValidateControllerResources(const uint8_t raw[5][20],const uint8_t translated[5][20],uint32_t index[4]);
/* One bounded clock lease, two fixed side-effect-free status/identity passes,
 * mandatory release on every path after acquisition. No engine writes. */
int G70Consume(const G70_CONSUMER_IO *,G70_CLOCK_RESULT *,G70_PROBE_RESULT *,uint64_t nonce);
#endif
