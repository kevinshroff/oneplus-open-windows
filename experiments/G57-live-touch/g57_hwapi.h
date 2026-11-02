/* SPDX-License-Identifier: MIT */
#ifndef G57_HWAPI_H
#define G57_HWAPI_H
#include "g57_binding.h"
#include "g57_trial.h"
#include "g57_protocol.h"
typedef struct {
 void*Context;
 int(*Stage)(void*,const uint8_t*,uint32_t,uint64_t);
 int(*Publish)(void*,const uint8_t*,uint32_t);
}G57_STREAM_IO;
uint64_t G57HardwareTimeUs(void);
void G57HardwareStatus(G57_STATUS*);
NTSTATUS G57HardwareSnapshot(G57_SNAPSHOT*);
void G57HardwarePmic(G57_PMIC*);
void G57HardwareTrial(G57_TRIAL*,const G57_STREAM_IO*);
#endif
