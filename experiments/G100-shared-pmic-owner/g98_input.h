/* SPDX-License-Identifier: MIT */
#ifndef G98_INPUT_H
#define G98_INPUT_H
#include "g98hid_lifecycle.h"
#include "g98_report.h"
typedef struct {void*Context;int(*Submit)(void*,const uint8_t[64]);}G98_INPUT_IO;
typedef struct {
 G98HID_STATE Accepted;G98HID_PLAN Pending;
 uint8_t Raw[G98_REPORT_MAX];uint32_t RawBytes,PendingValid;
 uint32_t Staged,Published,NoReport,SubmitAttempts,SubmitAccepted,StopAttempts,StopAccepted,Error;
 uint16_t Scan;
}G98_INPUT;
/* These calls do not own the transport. Stage validates before its one clear;
 * Publish is called only after clear completion and explicit bus quiescence.
 * Stop emits at most one release of last accepted IDs/coordinates. */
int G98InputStage(G98_INPUT*,const uint8_t*,uint32_t,uint16_t);
int G98InputPublish(G98_INPUT*,const G98_INPUT_IO*,const uint8_t*,uint32_t);
int G98InputStop(G98_INPUT*,const G98_INPUT_IO*,uint16_t);
#endif
