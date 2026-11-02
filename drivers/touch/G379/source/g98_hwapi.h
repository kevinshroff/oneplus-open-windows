/* SPDX-License-Identifier: MIT */
#ifndef G98_HWAPI_H
#define G98_HWAPI_H
#include "g98_binding.h"
#include "g98_trial.h"
#include "g98_protocol.h"
typedef struct {
 void*Context;
 int(*Stage)(void*,const uint8_t*,uint32_t,uint64_t);
 int(*Publish)(void*,const uint8_t*,uint32_t);
 int(*StopRequested)(void*);
 int(*Available)(void*);
 uint32_t CycleLimit;
 uint32_t Persistent;
 void(*CycleComplete)(void*);
 void(*EpochComplete)(void*,uint32_t,uint32_t,uint32_t);
}G98_STREAM_IO;
int G98HardwareAdmit(const G98_STREAM_IO*,G98_TRIAL*);
uint64_t G98HardwareTimeUs(void);
void G98HardwareStatus(G98_STATUS*);
NTSTATUS G98HardwareSnapshot(G98_SNAPSHOT*,const G98_STREAM_IO*);
void G98HardwarePmic(G98_PMIC*,const G98_STREAM_IO*);
void G98HardwareTrial(G98_TRIAL*,const G98_STREAM_IO*);
#endif
