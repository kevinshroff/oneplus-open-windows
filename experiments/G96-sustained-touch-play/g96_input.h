/* SPDX-License-Identifier: MIT */
#ifndef G96_INPUT_H
#define G96_INPUT_H
#include "g96hid_lifecycle.h"
#include "g96_report.h"
typedef struct {void*Context;int(*Submit)(void*,const uint8_t[64]);}G96_INPUT_IO;
typedef struct {
 G96HID_STATE Accepted;G96HID_PLAN Pending;
 uint8_t Raw[G96_REPORT_MAX];uint32_t RawBytes,PendingValid;
 uint32_t Staged,Published,NoReport,SubmitAttempts,SubmitAccepted,StopAttempts,StopAccepted,Error;
 uint16_t Scan;
}G96_INPUT;
/* These calls do not own the transport. Stage validates before its one clear;
 * Publish is called only after clear completion and explicit bus quiescence.
 * Stop emits at most one release of last accepted IDs/coordinates. */
int G96InputStage(G96_INPUT*,const uint8_t*,uint32_t,uint16_t);
int G96InputPublish(G96_INPUT*,const G96_INPUT_IO*,const uint8_t*,uint32_t);
int G96InputStop(G96_INPUT*,const G96_INPUT_IO*,uint16_t);
#endif
