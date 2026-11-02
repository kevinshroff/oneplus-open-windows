/* SPDX-License-Identifier: MIT */
#ifndef G96HID_LIFECYCLE_H
#define G96HID_LIFECYCLE_H
#include <stdint.h>
#define G96HID_MAX_X 22680u
#define G96HID_MAX_Y 24400u
#define G96HID_REPORT_BYTES 64u
typedef struct {uint32_t X,Y;}G96HID_POSITION;
typedef struct {uint32_t Generation,Mask;G96HID_POSITION Last[10];}G96HID_STATE;
typedef struct {uint32_t FromGeneration,HaveReport,Error;G96HID_STATE Next;uint8_t Report[G96HID_REPORT_BYTES];}G96HID_PLAN;
/* Prepare never mutates accepted state. Apply only after a successful submit.
 * scan is the low16 bits of the caller's monotonic100-microsecond time. */
int G96HIDPrepare(const G96HID_STATE*,const uint8_t*raw,uint32_t n,uint16_t scan,G96HID_PLAN*);
int G96HIDReleaseAll(const G96HID_STATE*,uint16_t scan,G96HID_PLAN*);
int G96HIDCommit(G96HID_STATE*,const G96HID_PLAN*);
#endif
