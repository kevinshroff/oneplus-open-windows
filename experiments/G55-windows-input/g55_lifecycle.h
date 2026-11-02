/* SPDX-License-Identifier: MIT */
#ifndef G55_LIFECYCLE_H
#define G55_LIFECYCLE_H
#include <stdint.h>
#define G55_MAX_X 22680u
#define G55_MAX_Y 24400u
#define G55_REPORT_BYTES 64u
typedef struct {uint32_t X,Y;}G55_POSITION;
typedef struct {uint32_t Generation,Mask;G55_POSITION Last[10];}G55_STATE;
typedef struct {uint32_t FromGeneration,HaveReport,Error;G55_STATE Next;uint8_t Report[G55_REPORT_BYTES];}G55_PLAN;
/* Prepare never mutates accepted state. Apply only after a successful submit.
 * scan is the low16 bits of the caller's monotonic100-microsecond time. */
int G55Prepare(const G55_STATE*,const uint8_t*raw,uint32_t n,uint16_t scan,G55_PLAN*);
int G55ReleaseAll(const G55_STATE*,uint16_t scan,G55_PLAN*);
int G55Commit(G55_STATE*,const G55_PLAN*);
#endif
