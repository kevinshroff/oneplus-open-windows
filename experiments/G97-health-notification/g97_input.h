/* SPDX-License-Identifier: MIT */
#ifndef G97_INPUT_H
#define G97_INPUT_H
#include "g97hid_lifecycle.h"
#include "g97_report.h"
typedef struct {void*Context;int(*Submit)(void*,const uint8_t[64]);}G97_INPUT_IO;
typedef struct {
 G97HID_STATE Accepted;G97HID_PLAN Pending;
 uint8_t Raw[G97_REPORT_MAX];uint32_t RawBytes,PendingValid;
 uint32_t Staged,Published,NoReport,SubmitAttempts,SubmitAccepted,StopAttempts,StopAccepted,Error;
 uint16_t Scan;
}G97_INPUT;
/* These calls do not own the transport. Stage validates before its one clear;
 * Publish is called only after clear completion and explicit bus quiescence.
 * Stop emits at most one release of last accepted IDs/coordinates. */
int G97InputStage(G97_INPUT*,const uint8_t*,uint32_t,uint16_t);
int G97InputPublish(G97_INPUT*,const G97_INPUT_IO*,const uint8_t*,uint32_t);
int G97InputStop(G97_INPUT*,const G97_INPUT_IO*,uint16_t);
#endif
