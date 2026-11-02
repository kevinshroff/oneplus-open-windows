/* SPDX-License-Identifier: MIT */
#ifndef G98HID_LIFECYCLE_H
#define G98HID_LIFECYCLE_H
#include <stdint.h>
#define G98HID_MAX_X 22680u
#define G98HID_MAX_Y 24400u
#define G98HID_REPORT_BYTES 64u
typedef struct {uint32_t X,Y;}G98HID_POSITION;
typedef struct {uint32_t Generation,Mask;G98HID_POSITION Last[10];}G98HID_STATE;
typedef struct {uint32_t FromGeneration,HaveReport,Error;G98HID_STATE Next;uint8_t Report[G98HID_REPORT_BYTES];}G98HID_PLAN;
/* Prepare never mutates accepted state. Apply only after a successful submit.
 * scan is the low16 bits of the caller's monotonic100-microsecond time. */
int G98HIDPrepare(const G98HID_STATE*,const uint8_t*raw,uint32_t n,uint16_t scan,G98HID_PLAN*);
int G98HIDReleaseAll(const G98HID_STATE*,uint16_t scan,G98HID_PLAN*);
int G98HIDCommit(G98HID_STATE*,const G98HID_PLAN*);
#endif
