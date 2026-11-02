/* SPDX-License-Identifier: MIT */
#ifndef G53_POLL_H
#define G53_POLL_H
#include "g53_report.h"
#define G53_POLL_CYCLES 8u
#define G53_POLL_DEADLINE_US 250000u
enum {G53_POLL_OK=0,G53_POLL_ARGUMENT=1,G53_POLL_CLOCK=2,G53_POLL_READ=3,G53_POLL_DECODE=4,G53_POLL_CLEAR=5,G53_POLL_QUIET=6};
typedef struct {uint32_t ReadBytes,TailRead,ClearAttempted,ClearCompleted,ElapsedUs;uint8_t Bytes[G53_REPORT_MAX];G53_FRAME Frame;}G53_POLL_RECORD;
typedef struct {uint32_t Code,Cycles,ReadAttempts,TailReads,ClearAttempts,ClearCompleted,IdleRecords,ContactRecords,RequestRecords,BusQuiescent,ElapsedUs;G53_POLL_RECORD Records[G53_POLL_CYCLES];}G53_POLL_RESULT;
typedef struct {
 void*Context;
 /* Read returns1 only after a complete transfer. Clear is the fixed F0 event
  * zero write; its API intentionally has no address, value or payload argument. */
 int(*Read)(void*,uint32_t,uint8_t*,uint32_t);int(*Clear)(void*);int(*Quiet)(void*);
 void(*WaitTenMs)(void*);uint64_t(*NowUs)(void*);
}G53_POLL_IO;
/* Caller owns the powered controller/engine and remains responsible for undo.
 * This bounded diagnostic collects raw contacts; it never injects Windows input. */
int G53Poll(const G53_POLL_IO*,G53_POLL_RESULT*);
#endif
