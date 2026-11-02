/* SPDX-License-Identifier: MIT */
#ifndef G56HID_LIFECYCLE_H
#define G56HID_LIFECYCLE_H
#include <stdint.h>
#define G56HID_MAX_X 22680u
#define G56HID_MAX_Y 24400u
#define G56HID_REPORT_BYTES 64u
typedef struct {uint32_t X,Y;}G56HID_POSITION;
typedef struct {uint32_t Generation,Mask;G56HID_POSITION Last[10];}G56HID_STATE;
typedef struct {uint32_t FromGeneration,HaveReport,Error;G56HID_STATE Next;uint8_t Report[G56HID_REPORT_BYTES];}G56HID_PLAN;
/* Prepare never mutates accepted state. Apply only after a successful submit.
 * scan is the low16 bits of the caller's monotonic100-microsecond time. */
int G56HIDPrepare(const G56HID_STATE*,const uint8_t*raw,uint32_t n,uint16_t scan,G56HID_PLAN*);
int G56HIDReleaseAll(const G56HID_STATE*,uint16_t scan,G56HID_PLAN*);
int G56HIDCommit(G56HID_STATE*,const G56HID_PLAN*);
#endif
