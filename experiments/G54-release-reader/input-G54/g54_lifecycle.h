/* SPDX-License-Identifier: MIT */
#ifndef G54_LIFECYCLE_H
#define G54_LIFECYCLE_H
#include <stdint.h>
#define G54_MAX_X 22680u
#define G54_MAX_Y 24400u
#define G54_REPORT_BYTES 64u
typedef struct {uint32_t X,Y;}G54_POSITION;
typedef struct {uint32_t Generation,Mask;G54_POSITION Last[10];}G54_STATE;
typedef struct {uint32_t FromGeneration,HaveReport,Error;G54_STATE Next;uint8_t Report[G54_REPORT_BYTES];}G54_PLAN;
/* Prepare never mutates accepted state. Apply only after a successful submit.
 * scan is the low16 bits of the caller's monotonic100-microsecond time. */
int G54Prepare(const G54_STATE*,const uint8_t*raw,uint32_t n,uint16_t scan,G54_PLAN*);
int G54ReleaseAll(const G54_STATE*,uint16_t scan,G54_PLAN*);
int G54Commit(G54_STATE*,const G54_PLAN*);
#endif
