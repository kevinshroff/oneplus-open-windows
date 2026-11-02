/* SPDX-License-Identifier: MIT */
#ifndef OPEN_G95HID_REPORT_H
#define OPEN_G95HID_REPORT_H
#include <stdint.h>
#define G95HID_CONTACTS 10u
#define G95HID_RAW_X_MAX 22680u
#define G95HID_RAW_Y_MAX 24400u
#define G95HID_REPORT_BYTES 64u
extern uint8_t G95HIDDescriptor[];
extern const uint32_t G95HIDDescriptorBytes;
void G95HIDEmptyReport(uint8_t out[G95HID_REPORT_BYTES],uint16_t scan);
int G95HIDIsEmptyReport(const uint8_t*,uint32_t);
int G95HIDGetFeature(uint8_t id,uint8_t*out,uint32_t capacity,uint32_t*written);
#endif
