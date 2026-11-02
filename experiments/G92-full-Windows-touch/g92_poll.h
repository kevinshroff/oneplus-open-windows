/* SPDX-License-Identifier: MIT */
#ifndef G92_POLL_H
#define G92_POLL_H
#include "g92_report.h"
#define G92_POLL_CYCLES 3000u
#define G92_NATIVE_CYCLES 2500u
#define G92_POLL_RECORDS 100u
#define G92_POLL_DEADLINE_US 45000000u
#define G92_READ_PREFETCH 1u
#define G92_READ_TAIL 2u
#define G92_READ_RETRY 4u
enum {G92_POLL_OK=0,G92_POLL_ARGUMENT=1,G92_POLL_CLOCK=2,G92_POLL_READ=3,G92_POLL_DECODE=4,G92_POLL_CLEAR=5,G92_POLL_QUIET=6,G92_POLL_STAGE=7,G92_POLL_PUBLISH=8,G92_POLL_IRQ_ERROR=9};
#define G92_POLL_CANCELLED 10u
#define G92_POLL_ADVANCE_ERROR 11u
typedef struct {uint32_t Control,Input,Config,Status;}G92_POLL_IRQ;
typedef struct {
 uint32_t ReadBytes,TailRead,ClearAttempted,ClearCompleted,ElapsedUs,IrqMask;
 G92_POLL_IRQ Irq[4];uint32_t HeaderRetry,FirstReadBytes;
 uint8_t First[26],Bytes[G92_REPORT_MAX];G92_FRAME Frame;
}G92_POLL_RECORD;
typedef struct {
 uint32_t Code,Limit,Cycles,ReadAttempts,TailReads,ClearAttempts,ClearCompleted,IdleRecords,ContactRecords,RequestRecords,BusQuiescent,ElapsedUs,HeaderRetries,HeadersRecovered,IrqReadAttempts;
 G92_POLL_RECORD Records[G92_POLL_RECORDS];
}G92_POLL_RESULT;
typedef struct {
 void*Context;uint32_t Limit;
 /* A retry is one exact26-byte read after proven transport completion and
  * bad header integrity. No uncertain transfer or write is ever retried. */
 int(*Read)(void*,uint32_t,uint32_t,uint8_t*,uint32_t);int(*Clear)(void*);int(*Quiet)(void*);
 void(*WaitTenMs)(void*);uint64_t(*NowUs)(void*);
 int(*Stage)(void*,const uint8_t*,uint32_t,uint64_t);int(*Publish)(void*,const uint8_t*,uint32_t);
 int(*SampleIrq)(void*,G92_POLL_IRQ*);
 int(*StopRequested)(void*);
 int(*Advance)(void*);
}G92_POLL_IO;
/* Caller owns the powered controller/engine and exact undo. GPIO observations
 * diagnose readiness, not IRQ delivery and do not gate or synthesize packets. */
int G92Poll(const G92_POLL_IO*,G92_POLL_RESULT*);
#endif
