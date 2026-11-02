/* SPDX-License-Identifier: MIT */
#ifndef G57_INPUT_H
#define G57_INPUT_H
#include "g57hid_lifecycle.h"
#include "g57_report.h"
typedef struct {void*Context;int(*Submit)(void*,const uint8_t[64]);}G57_INPUT_IO;
typedef struct {
 G57HID_STATE Accepted;G57HID_PLAN Pending;
 uint8_t Raw[G57_REPORT_MAX];uint32_t RawBytes,PendingValid;
 uint32_t Staged,Published,NoReport,SubmitAttempts,SubmitAccepted,StopAttempts,StopAccepted,Error;
 uint16_t Scan;
}G57_INPUT;
/* These calls do not own the transport. Stage validates before its one clear;
 * Publish is called only after clear completion and explicit bus quiescence.
 * Stop emits at most one release of last accepted IDs/coordinates. */
int G57InputStage(G57_INPUT*,const uint8_t*,uint32_t,uint16_t);
int G57InputPublish(G57_INPUT*,const G57_INPUT_IO*,const uint8_t*,uint32_t);
int G57InputStop(G57_INPUT*,const G57_INPUT_IO*,uint16_t);
#endif
