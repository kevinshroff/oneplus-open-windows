/* SPDX-License-Identifier: MIT */
#ifndef OPEN_G97HID_REPORT_H
#define OPEN_G97HID_REPORT_H
#include <stdint.h>
#define G97HID_CONTACTS 10u
#define G97HID_RAW_X_MAX 22680u
#define G97HID_RAW_Y_MAX 24400u
#define G97HID_REPORT_BYTES 64u
extern uint8_t G97HIDDescriptor[];
extern const uint32_t G97HIDDescriptorBytes;
void G97HIDEmptyReport(uint8_t out[G97HID_REPORT_BYTES],uint16_t scan);
int G97HIDIsEmptyReport(const uint8_t*,uint32_t);
int G97HIDGetFeature(uint8_t id,uint8_t*out,uint32_t capacity,uint32_t*written);
#endif
