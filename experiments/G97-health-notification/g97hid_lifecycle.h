/* SPDX-License-Identifier: MIT */
#ifndef G97HID_LIFECYCLE_H
#define G97HID_LIFECYCLE_H
#include <stdint.h>
#define G97HID_MAX_X 22680u
#define G97HID_MAX_Y 24400u
#define G97HID_REPORT_BYTES 64u
typedef struct {uint32_t X,Y;}G97HID_POSITION;
typedef struct {uint32_t Generation,Mask;G97HID_POSITION Last[10];}G97HID_STATE;
typedef struct {uint32_t FromGeneration,HaveReport,Error;G97HID_STATE Next;uint8_t Report[G97HID_REPORT_BYTES];}G97HID_PLAN;
/* Prepare never mutates accepted state. Apply only after a successful submit.
 * scan is the low16 bits of the caller's monotonic100-microsecond time. */
int G97HIDPrepare(const G97HID_STATE*,const uint8_t*raw,uint32_t n,uint16_t scan,G97HID_PLAN*);
int G97HIDReleaseAll(const G97HID_STATE*,uint16_t scan,G97HID_PLAN*);
int G97HIDCommit(G97HID_STATE*,const G97HID_PLAN*);
#endif
