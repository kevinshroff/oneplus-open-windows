/* SPDX-License-Identifier: MIT */
#ifndef G57HID_LIFECYCLE_H
#define G57HID_LIFECYCLE_H
#include <stdint.h>
#define G57HID_MAX_X 22680u
#define G57HID_MAX_Y 24400u
#define G57HID_REPORT_BYTES 64u
typedef struct {uint32_t X,Y;}G57HID_POSITION;
typedef struct {uint32_t Generation,Mask;G57HID_POSITION Last[10];}G57HID_STATE;
typedef struct {uint32_t FromGeneration,HaveReport,Error;G57HID_STATE Next;uint8_t Report[G57HID_REPORT_BYTES];}G57HID_PLAN;
/* Prepare never mutates accepted state. Apply only after a successful submit.
 * scan is the low16 bits of the caller's monotonic100-microsecond time. */
int G57HIDPrepare(const G57HID_STATE*,const uint8_t*raw,uint32_t n,uint16_t scan,G57HID_PLAN*);
int G57HIDReleaseAll(const G57HID_STATE*,uint16_t scan,G57HID_PLAN*);
int G57HIDCommit(G57HID_STATE*,const G57HID_PLAN*);
#endif
