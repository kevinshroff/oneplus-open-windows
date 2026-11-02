/* SPDX-License-Identifier: MIT */
#ifndef G95HID_LIFECYCLE_H
#define G95HID_LIFECYCLE_H
#include <stdint.h>
#define G95HID_MAX_X 22680u
#define G95HID_MAX_Y 24400u
#define G95HID_REPORT_BYTES 64u
typedef struct {uint32_t X,Y;}G95HID_POSITION;
typedef struct {uint32_t Generation,Mask;G95HID_POSITION Last[10];}G95HID_STATE;
typedef struct {uint32_t FromGeneration,HaveReport,Error;G95HID_STATE Next;uint8_t Report[G95HID_REPORT_BYTES];}G95HID_PLAN;
/* Prepare never mutates accepted state. Apply only after a successful submit.
 * scan is the low16 bits of the caller's monotonic100-microsecond time. */
int G95HIDPrepare(const G95HID_STATE*,const uint8_t*raw,uint32_t n,uint16_t scan,G95HID_PLAN*);
int G95HIDReleaseAll(const G95HID_STATE*,uint16_t scan,G95HID_PLAN*);
int G95HIDCommit(G95HID_STATE*,const G95HID_PLAN*);
#endif
