/* SPDX-License-Identifier: MIT */
#ifndef G58_POLL_H
#define G58_POLL_H
#include "g58_report.h"
#define G58_POLL_CYCLES 100u
#define G58_POLL_DEADLINE_US 2500000u
#define G58_READ_PREFETCH 1u
#define G58_READ_TAIL 2u
#define G58_READ_RETRY 4u
enum {G58_POLL_OK=0,G58_POLL_ARGUMENT=1,G58_POLL_CLOCK=2,G58_POLL_READ=3,G58_POLL_DECODE=4,G58_POLL_CLEAR=5,G58_POLL_QUIET=6,G58_POLL_STAGE=7,G58_POLL_PUBLISH=8,G58_POLL_IRQ_ERROR=9};
#define G58_POLL_CANCELLED 10u
typedef struct {uint32_t Control,Input,Config,Status;}G58_POLL_IRQ;
typedef struct {
 uint32_t ReadBytes,TailRead,ClearAttempted,ClearCompleted,ElapsedUs,IrqMask;
 G58_POLL_IRQ Irq[4];uint32_t HeaderRetry,FirstReadBytes;
 uint8_t First[26],Bytes[G58_REPORT_MAX];G58_FRAME Frame;
}G58_POLL_RECORD;
typedef struct {
 uint32_t Code,Limit,Cycles,ReadAttempts,TailReads,ClearAttempts,ClearCompleted,IdleRecords,ContactRecords,RequestRecords,BusQuiescent,ElapsedUs,HeaderRetries,HeadersRecovered,IrqReadAttempts;
 G58_POLL_RECORD Records[G58_POLL_CYCLES];
}G58_POLL_RESULT;
typedef struct {
 void*Context;uint32_t Limit;
 /* A retry is one exact26-byte read after proven transport completion and
  * bad header integrity. No uncertain transfer or write is ever retried. */
 int(*Read)(void*,uint32_t,uint32_t,uint8_t*,uint32_t);int(*Clear)(void*);int(*Quiet)(void*);
 void(*WaitTenMs)(void*);uint64_t(*NowUs)(void*);
 int(*Stage)(void*,const uint8_t*,uint32_t,uint64_t);int(*Publish)(void*,const uint8_t*,uint32_t);
 int(*SampleIrq)(void*,G58_POLL_IRQ*);
 int(*StopRequested)(void*);
}G58_POLL_IO;
/* Caller owns the powered controller/engine and exact undo. GPIO observations
 * diagnose readiness, not IRQ delivery and do not gate or synthesize packets. */
int G58Poll(const G58_POLL_IO*,G58_POLL_RESULT*);
#endif
