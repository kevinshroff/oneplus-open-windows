/* SPDX-License-Identifier: MIT */
#ifndef G70_CLIENT_POLICY_H
#define G70_CLIENT_POLICY_H
#include "g70_consumer.h"
int G70ClientParse(const uint16_t *,uint32_t *cycle,char nonce[33],uint64_t *value);
int G70ClientReportShape(const G70_REPORT *,uint32_t firmwareBytes);
int G70ClientReadyForCycle(const G70_REPORT *,uint32_t firmwareBytes);
int G70ClientCycleComplete(const G70_REPORT *,uint32_t firmwareBytes,uint64_t nonce);
#endif
