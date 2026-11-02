/* SPDX-License-Identifier: MIT */
#ifndef OPEN_G57HID_REPORT_H
#define OPEN_G57HID_REPORT_H
#include <stdint.h>
#define G57HID_CONTACTS 10u
#define G57HID_RAW_X_MAX 22680u
#define G57HID_RAW_Y_MAX 24400u
#define G57HID_REPORT_BYTES 64u
extern uint8_t G57HIDDescriptor[];
extern const uint32_t G57HIDDescriptorBytes;
void G57HIDEmptyReport(uint8_t out[G57HID_REPORT_BYTES],uint16_t scan);
int G57HIDIsEmptyReport(const uint8_t*,uint32_t);
int G57HIDGetFeature(uint8_t id,uint8_t*out,uint32_t capacity,uint32_t*written);
#endif
