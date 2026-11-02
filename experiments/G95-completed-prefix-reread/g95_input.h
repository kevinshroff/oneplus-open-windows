/* SPDX-License-Identifier: MIT */
#ifndef G95_INPUT_H
#define G95_INPUT_H
#include "g95hid_lifecycle.h"
#include "g95_report.h"
typedef struct {void*Context;int(*Submit)(void*,const uint8_t[64]);}G95_INPUT_IO;
typedef struct {
 G95HID_STATE Accepted;G95HID_PLAN Pending;
 uint8_t Raw[G95_REPORT_MAX];uint32_t RawBytes,PendingValid;
 uint32_t Staged,Published,NoReport,SubmitAttempts,SubmitAccepted,StopAttempts,StopAccepted,Error;
 uint16_t Scan;
}G95_INPUT;
/* These calls do not own the transport. Stage validates before its one clear;
 * Publish is called only after clear completion and explicit bus quiescence.
 * Stop emits at most one release of last accepted IDs/coordinates. */
int G95InputStage(G95_INPUT*,const uint8_t*,uint32_t,uint16_t);
int G95InputPublish(G95_INPUT*,const G95_INPUT_IO*,const uint8_t*,uint32_t);
int G95InputStop(G95_INPUT*,const G95_INPUT_IO*,uint16_t);
#endif
