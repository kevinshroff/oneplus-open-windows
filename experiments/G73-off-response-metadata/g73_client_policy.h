/* SPDX-License-Identifier: MIT */
#ifndef G73_CLIENT_POLICY_H
#define G73_CLIENT_POLICY_H
#include "g73_protocol.h"
enum {G73_CLIENT_STATUS=0,G73_CLIENT_SNAPSHOT=1,G73_CLIENT_PMIC=2,G73_CLIENT_RUN=3,G73_CLIENT_RESULT=4,G73_CLIENT_ABSENT=5};
int G73ClientParse(const uint16_t*,uint32_t*,char[33],uint64_t*);
const char*G73ClientMode(uint32_t);
int G73ClientStatus(const G73_STATUS*);
int G73ClientReady(const G73_STATUS*);
int G73ClientSnapshot(const G73_SNAPSHOT*,const uint32_t[50]);
int G73ClientPmic(const G73_PMIC*);
int G73ClientRun(const G73_RUN*,const uint32_t[50],uint64_t);
#endif
