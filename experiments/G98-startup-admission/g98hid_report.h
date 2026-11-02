/* SPDX-License-Identifier: MIT */
#ifndef OPEN_G98HID_REPORT_H
#define OPEN_G98HID_REPORT_H
#include <stdint.h>
#define G98HID_CONTACTS 10u
#define G98HID_RAW_X_MAX 22680u
#define G98HID_RAW_Y_MAX 24400u
#define G98HID_REPORT_BYTES 64u
extern uint8_t G98HIDDescriptor[];
extern const uint32_t G98HIDDescriptorBytes;
void G98HIDEmptyReport(uint8_t out[G98HID_REPORT_BYTES],uint16_t scan);
int G98HIDIsEmptyReport(const uint8_t*,uint32_t);
int G98HIDGetFeature(uint8_t id,uint8_t*out,uint32_t capacity,uint32_t*written);
#endif
