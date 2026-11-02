/* SPDX-License-Identifier: MIT */
#ifndef G59HID_LIFECYCLE_H
#define G59HID_LIFECYCLE_H
#include <stdint.h>
#define G59HID_MAX_X 22680u
#define G59HID_MAX_Y 24400u
#define G59HID_REPORT_BYTES 64u
typedef struct {uint32_t X,Y;}G59HID_POSITION;
typedef struct {uint32_t Generation,Mask;G59HID_POSITION Last[10];}G59HID_STATE;
typedef struct {uint32_t FromGeneration,HaveReport,Error;G59HID_STATE Next;uint8_t Report[G59HID_REPORT_BYTES];}G59HID_PLAN;
/* Prepare never mutates accepted state. Apply only after a successful submit.
 * scan is the low16 bits of the caller's monotonic100-microsecond time. */
int G59HIDPrepare(const G59HID_STATE*,const uint8_t*raw,uint32_t n,uint16_t scan,G59HID_PLAN*);
int G59HIDReleaseAll(const G59HID_STATE*,uint16_t scan,G59HID_PLAN*);
int G59HIDCommit(G59HID_STATE*,const G59HID_PLAN*);
#endif
