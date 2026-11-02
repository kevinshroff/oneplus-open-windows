/* SPDX-License-Identifier: MIT */
#ifndef OPEN_G56HID_REPORT_H
#define OPEN_G56HID_REPORT_H
#include <stdint.h>
#define G56HID_CONTACTS 10u
#define G56HID_RAW_X_MAX 22680u
#define G56HID_RAW_Y_MAX 24400u
#define G56HID_REPORT_BYTES 64u
extern uint8_t G56HIDDescriptor[];
extern const uint32_t G56HIDDescriptorBytes;
void G56HIDEmptyReport(uint8_t out[G56HID_REPORT_BYTES],uint16_t scan);
int G56HIDIsEmptyReport(const uint8_t*,uint32_t);
int G56HIDGetFeature(uint8_t id,uint8_t*out,uint32_t capacity,uint32_t*written);
#endif
