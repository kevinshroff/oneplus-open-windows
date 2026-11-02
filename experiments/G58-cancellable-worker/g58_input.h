/* SPDX-License-Identifier: MIT */
#ifndef G58_INPUT_H
#define G58_INPUT_H
#include "g58hid_lifecycle.h"
#include "g58_report.h"
typedef struct {void*Context;int(*Submit)(void*,const uint8_t[64]);}G58_INPUT_IO;
typedef struct {
 G58HID_STATE Accepted;G58HID_PLAN Pending;
 uint8_t Raw[G58_REPORT_MAX];uint32_t RawBytes,PendingValid;
 uint32_t Staged,Published,NoReport,SubmitAttempts,SubmitAccepted,StopAttempts,StopAccepted,Error;
 uint16_t Scan;
}G58_INPUT;
/* These calls do not own the transport. Stage validates before its one clear;
 * Publish is called only after clear completion and explicit bus quiescence.
 * Stop emits at most one release of last accepted IDs/coordinates. */
int G58InputStage(G58_INPUT*,const uint8_t*,uint32_t,uint16_t);
int G58InputPublish(G58_INPUT*,const G58_INPUT_IO*,const uint8_t*,uint32_t);
int G58InputStop(G58_INPUT*,const G58_INPUT_IO*,uint16_t);
#endif
