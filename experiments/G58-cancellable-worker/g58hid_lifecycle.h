/* SPDX-License-Identifier: MIT */
#ifndef G58HID_LIFECYCLE_H
#define G58HID_LIFECYCLE_H
#include <stdint.h>
#define G58HID_MAX_X 22680u
#define G58HID_MAX_Y 24400u
#define G58HID_REPORT_BYTES 64u
typedef struct {uint32_t X,Y;}G58HID_POSITION;
typedef struct {uint32_t Generation,Mask;G58HID_POSITION Last[10];}G58HID_STATE;
typedef struct {uint32_t FromGeneration,HaveReport,Error;G58HID_STATE Next;uint8_t Report[G58HID_REPORT_BYTES];}G58HID_PLAN;
/* Prepare never mutates accepted state. Apply only after a successful submit.
 * scan is the low16 bits of the caller's monotonic100-microsecond time. */
int G58HIDPrepare(const G58HID_STATE*,const uint8_t*raw,uint32_t n,uint16_t scan,G58HID_PLAN*);
int G58HIDReleaseAll(const G58HID_STATE*,uint16_t scan,G58HID_PLAN*);
int G58HIDCommit(G58HID_STATE*,const G58HID_PLAN*);
#endif
