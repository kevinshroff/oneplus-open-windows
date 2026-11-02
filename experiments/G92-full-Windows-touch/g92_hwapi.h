/* SPDX-License-Identifier: MIT */
#ifndef G92_HWAPI_H
#define G92_HWAPI_H
#include "g92_binding.h"
#include "g92_trial.h"
#include "g92_protocol.h"
typedef struct {
 void*Context;
 int(*Stage)(void*,const uint8_t*,uint32_t,uint64_t);
 int(*Publish)(void*,const uint8_t*,uint32_t);
 int(*StopRequested)(void*);
 int(*Available)(void*);
}G92_STREAM_IO;
uint64_t G92HardwareTimeUs(void);
void G92HardwareStatus(G92_STATUS*);
NTSTATUS G92HardwareSnapshot(G92_SNAPSHOT*,const G92_STREAM_IO*);
void G92HardwarePmic(G92_PMIC*,const G92_STREAM_IO*);
void G92HardwareTrial(G92_TRIAL*,const G92_STREAM_IO*);
#endif
