/* SPDX-License-Identifier: MIT */
#ifndef G92_INPUT_H
#define G92_INPUT_H
#include "g92hid_lifecycle.h"
#include "g92_report.h"
typedef struct {void*Context;int(*Submit)(void*,const uint8_t[64]);}G92_INPUT_IO;
typedef struct {
 G92HID_STATE Accepted;G92HID_PLAN Pending;
 uint8_t Raw[G92_REPORT_MAX];uint32_t RawBytes,PendingValid;
 uint32_t Staged,Published,NoReport,SubmitAttempts,SubmitAccepted,StopAttempts,StopAccepted,Error;
 uint16_t Scan;
}G92_INPUT;
/* These calls do not own the transport. Stage validates before its one clear;
 * Publish is called only after clear completion and explicit bus quiescence.
 * Stop emits at most one release of last accepted IDs/coordinates. */
int G92InputStage(G92_INPUT*,const uint8_t*,uint32_t,uint16_t);
int G92InputPublish(G92_INPUT*,const G92_INPUT_IO*,const uint8_t*,uint32_t);
int G92InputStop(G92_INPUT*,const G92_INPUT_IO*,uint16_t);
#endif
