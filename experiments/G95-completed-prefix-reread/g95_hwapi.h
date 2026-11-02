/* SPDX-License-Identifier: MIT */
#ifndef G95_HWAPI_H
#define G95_HWAPI_H
#include "g95_binding.h"
#include "g95_trial.h"
#include "g95_protocol.h"
typedef struct {
 void*Context;
 int(*Stage)(void*,const uint8_t*,uint32_t,uint64_t);
 int(*Publish)(void*,const uint8_t*,uint32_t);
 int(*StopRequested)(void*);
 int(*Available)(void*);
}G95_STREAM_IO;
uint64_t G95HardwareTimeUs(void);
void G95HardwareStatus(G95_STATUS*);
NTSTATUS G95HardwareSnapshot(G95_SNAPSHOT*,const G95_STREAM_IO*);
void G95HardwarePmic(G95_PMIC*,const G95_STREAM_IO*);
void G95HardwareTrial(G95_TRIAL*,const G95_STREAM_IO*);
#endif
