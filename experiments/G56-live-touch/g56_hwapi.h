/* SPDX-License-Identifier: MIT */
#ifndef G56_HWAPI_H
#define G56_HWAPI_H
#include "g56_binding.h"
#include "g56_trial.h"
#include "g56_protocol.h"
typedef struct {
 void*Context;
 int(*Stage)(void*,const uint8_t*,uint32_t,uint64_t);
 int(*Publish)(void*,const uint8_t*,uint32_t);
}G56_STREAM_IO;
uint64_t G56HardwareTimeUs(void);
void G56HardwareStatus(G56_STATUS*);
NTSTATUS G56HardwareSnapshot(G56_SNAPSHOT*);
void G56HardwarePmic(G56_PMIC*);
void G56HardwareTrial(G56_TRIAL*,const G56_STREAM_IO*);
#endif
