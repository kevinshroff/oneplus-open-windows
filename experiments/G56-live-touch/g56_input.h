/* SPDX-License-Identifier: MIT */
#ifndef G56_INPUT_H
#define G56_INPUT_H
#include "g56hid_lifecycle.h"
#include "g56_report.h"
typedef struct {void*Context;int(*Submit)(void*,const uint8_t[64]);}G56_INPUT_IO;
typedef struct {
 G56HID_STATE Accepted;G56HID_PLAN Pending;
 uint8_t Raw[G56_REPORT_MAX];uint32_t RawBytes,PendingValid;
 uint32_t Staged,Published,NoReport,SubmitAttempts,SubmitAccepted,StopAttempts,StopAccepted,Error;
 uint16_t Scan;
}G56_INPUT;
/* These calls do not own the transport. Stage validates before its one clear;
 * Publish is called only after clear completion and explicit bus quiescence.
 * Stop emits at most one release of last accepted IDs/coordinates. */
int G56InputStage(G56_INPUT*,const uint8_t*,uint32_t,uint16_t);
int G56InputPublish(G56_INPUT*,const G56_INPUT_IO*,const uint8_t*,uint32_t);
int G56InputStop(G56_INPUT*,const G56_INPUT_IO*,uint16_t);
#endif
