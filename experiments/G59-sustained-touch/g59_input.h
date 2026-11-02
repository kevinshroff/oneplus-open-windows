/* SPDX-License-Identifier: MIT */
#ifndef G59_INPUT_H
#define G59_INPUT_H
#include "g59hid_lifecycle.h"
#include "g59_report.h"
typedef struct {void*Context;int(*Submit)(void*,const uint8_t[64]);}G59_INPUT_IO;
typedef struct {
 G59HID_STATE Accepted;G59HID_PLAN Pending;
 uint8_t Raw[G59_REPORT_MAX];uint32_t RawBytes,PendingValid;
 uint32_t Staged,Published,NoReport,SubmitAttempts,SubmitAccepted,StopAttempts,StopAccepted,Error;
 uint16_t Scan;
}G59_INPUT;
/* These calls do not own the transport. Stage validates before its one clear;
 * Publish is called only after clear completion and explicit bus quiescence.
 * Stop emits at most one release of last accepted IDs/coordinates. */
int G59InputStage(G59_INPUT*,const uint8_t*,uint32_t,uint16_t);
int G59InputPublish(G59_INPUT*,const G59_INPUT_IO*,const uint8_t*,uint32_t);
int G59InputStop(G59_INPUT*,const G59_INPUT_IO*,uint16_t);
#endif
