/* SPDX-License-Identifier: MIT */
#ifndef G67_CLIENT_POLICY_H
#define G67_CLIENT_POLICY_H
#include "g67_clock.h"
int G67ClientParse(const uint16_t *,uint32_t *cycle,char nonce[33],uint64_t *value);
int G67ClientReportShape(const G67_REPORT *,uint32_t firmwareBytes);
int G67ClientReadyForCycle(const G67_REPORT *,uint32_t firmwareBytes);
int G67ClientCycleComplete(const G67_REPORT *,uint32_t firmwareBytes,uint64_t nonce);
#endif
