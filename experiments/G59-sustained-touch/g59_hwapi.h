/* SPDX-License-Identifier: MIT */
#ifndef G59_HWAPI_H
#define G59_HWAPI_H
#include "g59_binding.h"
#include "g59_trial.h"
#include "g59_protocol.h"
typedef struct {
 void*Context;
 int(*Stage)(void*,const uint8_t*,uint32_t,uint64_t);
 int(*Publish)(void*,const uint8_t*,uint32_t);
 int(*StopRequested)(void*);
 int(*Available)(void*);
}G59_STREAM_IO;
uint64_t G59HardwareTimeUs(void);
void G59HardwareStatus(G59_STATUS*);
NTSTATUS G59HardwareSnapshot(G59_SNAPSHOT*,const G59_STREAM_IO*);
void G59HardwarePmic(G59_PMIC*,const G59_STREAM_IO*);
void G59HardwareTrial(G59_TRIAL*,const G59_STREAM_IO*);
#endif
