/* SPDX-License-Identifier: MIT */
#ifndef G96_HWAPI_H
#define G96_HWAPI_H
#include "g96_binding.h"
#include "g96_trial.h"
#include "g96_protocol.h"
typedef struct {
 void*Context;
 int(*Stage)(void*,const uint8_t*,uint32_t,uint64_t);
 int(*Publish)(void*,const uint8_t*,uint32_t);
 int(*StopRequested)(void*);
 int(*Available)(void*);
 uint32_t CycleLimit;
}G96_STREAM_IO;
uint64_t G96HardwareTimeUs(void);
void G96HardwareStatus(G96_STATUS*);
NTSTATUS G96HardwareSnapshot(G96_SNAPSHOT*,const G96_STREAM_IO*);
void G96HardwarePmic(G96_PMIC*,const G96_STREAM_IO*);
void G96HardwareTrial(G96_TRIAL*,const G96_STREAM_IO*);
#endif
