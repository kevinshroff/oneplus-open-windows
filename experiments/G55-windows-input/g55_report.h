/* SPDX-License-Identifier: MIT */
#ifndef OPEN_G55_REPORT_H
#define OPEN_G55_REPORT_H
#include <stdint.h>
#define G55_CONTACTS 10u
#define G55_RAW_X_MAX 22680u
#define G55_RAW_Y_MAX 24400u
#define G55_REPORT_BYTES 64u
extern uint8_t G55Descriptor[];
extern const uint32_t G55DescriptorBytes;
void G55EmptyReport(uint8_t out[G55_REPORT_BYTES],uint16_t scan);
int G55IsEmptyReport(const uint8_t*,uint32_t);
int G55GetFeature(uint8_t id,uint8_t*out,uint32_t capacity,uint32_t*written);
#endif
