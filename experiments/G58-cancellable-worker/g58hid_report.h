/* SPDX-License-Identifier: MIT */
#ifndef OPEN_G58HID_REPORT_H
#define OPEN_G58HID_REPORT_H
#include <stdint.h>
#define G58HID_CONTACTS 10u
#define G58HID_RAW_X_MAX 22680u
#define G58HID_RAW_Y_MAX 24400u
#define G58HID_REPORT_BYTES 64u
extern uint8_t G58HIDDescriptor[];
extern const uint32_t G58HIDDescriptorBytes;
void G58HIDEmptyReport(uint8_t out[G58HID_REPORT_BYTES],uint16_t scan);
int G58HIDIsEmptyReport(const uint8_t*,uint32_t);
int G58HIDGetFeature(uint8_t id,uint8_t*out,uint32_t capacity,uint32_t*written);
#endif
