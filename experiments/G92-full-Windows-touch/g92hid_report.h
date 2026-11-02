/* SPDX-License-Identifier: MIT */
#ifndef OPEN_G92HID_REPORT_H
#define OPEN_G92HID_REPORT_H
#include <stdint.h>
#define G92HID_CONTACTS 10u
#define G92HID_RAW_X_MAX 22680u
#define G92HID_RAW_Y_MAX 24400u
#define G92HID_REPORT_BYTES 64u
extern uint8_t G92HIDDescriptor[];
extern const uint32_t G92HIDDescriptorBytes;
void G92HIDEmptyReport(uint8_t out[G92HID_REPORT_BYTES],uint16_t scan);
int G92HIDIsEmptyReport(const uint8_t*,uint32_t);
int G92HIDGetFeature(uint8_t id,uint8_t*out,uint32_t capacity,uint32_t*written);
#endif
