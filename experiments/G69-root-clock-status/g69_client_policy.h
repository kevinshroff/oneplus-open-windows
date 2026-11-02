/* SPDX-License-Identifier: MIT */
#ifndef G69_CLIENT_POLICY_H
#define G69_CLIENT_POLICY_H
#include "g69_clock.h"
int G69ClientParse(const uint16_t *,uint32_t *cycle,char nonce[33],uint64_t *value);
int G69ClientReportShape(const G69_REPORT *,uint32_t firmwareBytes);
int G69ClientReadyForCycle(const G69_REPORT *,uint32_t firmwareBytes);
int G69ClientCycleComplete(const G69_REPORT *,uint32_t firmwareBytes,uint64_t nonce);
#endif
