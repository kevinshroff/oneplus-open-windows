/* SPDX-License-Identifier: MIT */
#ifndef G97_HWAPI_H
#define G97_HWAPI_H
#include "g97_binding.h"
#include "g97_trial.h"
#include "g97_protocol.h"
typedef struct {
 void*Context;
 int(*Stage)(void*,const uint8_t*,uint32_t,uint64_t);
 int(*Publish)(void*,const uint8_t*,uint32_t);
 int(*StopRequested)(void*);
 int(*Available)(void*);
 uint32_t CycleLimit;
}G97_STREAM_IO;
uint64_t G97HardwareTimeUs(void);
void G97HardwareStatus(G97_STATUS*);
NTSTATUS G97HardwareSnapshot(G97_SNAPSHOT*,const G97_STREAM_IO*);
void G97HardwarePmic(G97_PMIC*,const G97_STREAM_IO*);
void G97HardwareTrial(G97_TRIAL*,const G97_STREAM_IO*);
#endif
