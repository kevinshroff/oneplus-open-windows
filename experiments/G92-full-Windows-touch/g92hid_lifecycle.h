/* SPDX-License-Identifier: MIT */
#ifndef G92HID_LIFECYCLE_H
#define G92HID_LIFECYCLE_H
#include <stdint.h>
#define G92HID_MAX_X 22680u
#define G92HID_MAX_Y 24400u
#define G92HID_REPORT_BYTES 64u
typedef struct {uint32_t X,Y;}G92HID_POSITION;
typedef struct {uint32_t Generation,Mask;G92HID_POSITION Last[10];}G92HID_STATE;
typedef struct {uint32_t FromGeneration,HaveReport,Error;G92HID_STATE Next;uint8_t Report[G92HID_REPORT_BYTES];}G92HID_PLAN;
/* Prepare never mutates accepted state. Apply only after a successful submit.
 * scan is the low16 bits of the caller's monotonic100-microsecond time. */
int G92HIDPrepare(const G92HID_STATE*,const uint8_t*raw,uint32_t n,uint16_t scan,G92HID_PLAN*);
int G92HIDReleaseAll(const G92HID_STATE*,uint16_t scan,G92HID_PLAN*);
int G92HIDCommit(G92HID_STATE*,const G92HID_PLAN*);
#endif
