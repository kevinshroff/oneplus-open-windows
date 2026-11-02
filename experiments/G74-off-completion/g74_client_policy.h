/* SPDX-License-Identifier: MIT */
#ifndef G74_CLIENT_POLICY_H
#define G74_CLIENT_POLICY_H
#include "g74_protocol.h"
enum {G74_CLIENT_STATUS=0,G74_CLIENT_SNAPSHOT=1,G74_CLIENT_PMIC=2,G74_CLIENT_RUN=3,G74_CLIENT_RESULT=4,G74_CLIENT_ABSENT=5};
int G74ClientParse(const uint16_t*,uint32_t*,char[33],uint64_t*);
const char*G74ClientMode(uint32_t);
int G74ClientStatus(const G74_STATUS*);
int G74ClientReady(const G74_STATUS*);
int G74ClientSnapshot(const G74_SNAPSHOT*,const uint32_t[50]);
int G74ClientPmic(const G74_PMIC*);
int G74ClientRun(const G74_RUN*,const uint32_t[50],uint64_t);
#endif
