/* SPDX-License-Identifier: MIT */
#ifndef OPEN_G96HID_REPORT_H
#define OPEN_G96HID_REPORT_H
#include <stdint.h>
#define G96HID_CONTACTS 10u
#define G96HID_RAW_X_MAX 22680u
#define G96HID_RAW_Y_MAX 24400u
#define G96HID_REPORT_BYTES 64u
extern uint8_t G96HIDDescriptor[];
extern const uint32_t G96HIDDescriptorBytes;
void G96HIDEmptyReport(uint8_t out[G96HID_REPORT_BYTES],uint16_t scan);
int G96HIDIsEmptyReport(const uint8_t*,uint32_t);
int G96HIDGetFeature(uint8_t id,uint8_t*out,uint32_t capacity,uint32_t*written);
#endif
