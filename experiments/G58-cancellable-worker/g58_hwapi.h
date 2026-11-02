/* SPDX-License-Identifier: MIT */
#ifndef G58_HWAPI_H
#define G58_HWAPI_H
#include "g58_binding.h"
#include "g58_trial.h"
#include "g58_protocol.h"
typedef struct {
 void*Context;
 int(*Stage)(void*,const uint8_t*,uint32_t,uint64_t);
 int(*Publish)(void*,const uint8_t*,uint32_t);
 int(*StopRequested)(void*);
 int(*Available)(void*);
}G58_STREAM_IO;
uint64_t G58HardwareTimeUs(void);
void G58HardwareStatus(G58_STATUS*);
NTSTATUS G58HardwareSnapshot(G58_SNAPSHOT*,const G58_STREAM_IO*);
void G58HardwarePmic(G58_PMIC*,const G58_STREAM_IO*);
void G58HardwareTrial(G58_TRIAL*,const G58_STREAM_IO*);
#endif
