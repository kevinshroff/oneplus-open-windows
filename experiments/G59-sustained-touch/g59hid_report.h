/* SPDX-License-Identifier: MIT */
#ifndef OPEN_G59HID_REPORT_H
#define OPEN_G59HID_REPORT_H
#include <stdint.h>
#define G59HID_CONTACTS 10u
#define G59HID_RAW_X_MAX 22680u
#define G59HID_RAW_Y_MAX 24400u
#define G59HID_REPORT_BYTES 64u
extern uint8_t G59HIDDescriptor[];
extern const uint32_t G59HIDDescriptorBytes;
void G59HIDEmptyReport(uint8_t out[G59HID_REPORT_BYTES],uint16_t scan);
int G59HIDIsEmptyReport(const uint8_t*,uint32_t);
int G59HIDGetFeature(uint8_t id,uint8_t*out,uint32_t capacity,uint32_t*written);
#endif
