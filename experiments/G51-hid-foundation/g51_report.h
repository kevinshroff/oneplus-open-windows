/* SPDX-License-Identifier: MIT */
#ifndef OPEN_G51_REPORT_H
#define OPEN_G51_REPORT_H
#include <stdint.h>
#define G51_CONTACTS 10u
#define G51_RAW_X_MAX 22680u
#define G51_RAW_Y_MAX 24400u
#define G51_REPORT_BYTES 64u
extern uint8_t G51Descriptor[];
extern const uint32_t G51DescriptorBytes;
void G51EmptyReport(uint8_t out[G51_REPORT_BYTES],uint16_t scan);
int G51IsEmptyReport(const uint8_t*,uint32_t);
int G51GetFeature(uint8_t id,uint8_t*out,uint32_t capacity,uint32_t*written);
#endif
