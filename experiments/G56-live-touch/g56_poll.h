/* SPDX-License-Identifier: MIT */
#ifndef G56_POLL_H
#define G56_POLL_H
#include "g56_report.h"
#define G56_POLL_CYCLES 100u
#define G56_POLL_DEADLINE_US 2500000u
enum {G56_POLL_OK=0,G56_POLL_ARGUMENT=1,G56_POLL_CLOCK=2,G56_POLL_READ=3,G56_POLL_DECODE=4,G56_POLL_CLEAR=5,G56_POLL_QUIET=6,G56_POLL_STAGE=7,G56_POLL_PUBLISH=8};
typedef struct {uint32_t ReadBytes,TailRead,ClearAttempted,ClearCompleted,ElapsedUs;uint8_t Bytes[G56_REPORT_MAX];G56_FRAME Frame;}G56_POLL_RECORD;
typedef struct {uint32_t Code,Limit,Cycles,ReadAttempts,TailReads,ClearAttempts,ClearCompleted,IdleRecords,ContactRecords,RequestRecords,BusQuiescent,ElapsedUs;G56_POLL_RECORD Records[G56_POLL_CYCLES];}G56_POLL_RESULT;
typedef struct {
 void*Context;uint32_t Limit;
 /* Read returns1 only after a complete transfer. Clear is the fixed F0 event
  * zero write; its API intentionally has no address, value or payload argument. */
 int(*Read)(void*,uint32_t,uint8_t*,uint32_t);int(*Clear)(void*);int(*Quiet)(void*);
 void(*WaitTenMs)(void*);uint64_t(*NowUs)(void*);
 int(*Stage)(void*,const uint8_t*,uint32_t,uint64_t);int(*Publish)(void*,const uint8_t*,uint32_t);
}G56_POLL_IO;
/* Caller owns the powered controller/engine and remains responsible for undo.
 * A live consumer stages before one clear, then publishes after proven completion.
 * Limit is a trusted caller bound in1..100; no caller supplies write payloads. */
int G56Poll(const G56_POLL_IO*,G56_POLL_RESULT*);
#endif
