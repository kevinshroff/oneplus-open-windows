/* SPDX-License-Identifier: MIT */
#ifndef G57_POLL_H
#define G57_POLL_H
#include "g57_report.h"
#define G57_POLL_CYCLES 100u
#define G57_POLL_DEADLINE_US 2500000u
#define G57_READ_PREFETCH 1u
#define G57_READ_TAIL 2u
#define G57_READ_RETRY 4u
enum {G57_POLL_OK=0,G57_POLL_ARGUMENT=1,G57_POLL_CLOCK=2,G57_POLL_READ=3,G57_POLL_DECODE=4,G57_POLL_CLEAR=5,G57_POLL_QUIET=6,G57_POLL_STAGE=7,G57_POLL_PUBLISH=8,G57_POLL_IRQ_ERROR=9};
typedef struct {uint32_t Control,Input,Config,Status;}G57_POLL_IRQ;
typedef struct {
 uint32_t ReadBytes,TailRead,ClearAttempted,ClearCompleted,ElapsedUs,IrqMask;
 G57_POLL_IRQ Irq[4];uint32_t HeaderRetry,FirstReadBytes;
 uint8_t First[26],Bytes[G57_REPORT_MAX];G57_FRAME Frame;
}G57_POLL_RECORD;
typedef struct {
 uint32_t Code,Limit,Cycles,ReadAttempts,TailReads,ClearAttempts,ClearCompleted,IdleRecords,ContactRecords,RequestRecords,BusQuiescent,ElapsedUs,HeaderRetries,HeadersRecovered,IrqReadAttempts;
 G57_POLL_RECORD Records[G57_POLL_CYCLES];
}G57_POLL_RESULT;
typedef struct {
 void*Context;uint32_t Limit;
 /* A retry is one exact26-byte read after proven transport completion and
  * bad header integrity. No uncertain transfer or write is ever retried. */
 int(*Read)(void*,uint32_t,uint32_t,uint8_t*,uint32_t);int(*Clear)(void*);int(*Quiet)(void*);
 void(*WaitTenMs)(void*);uint64_t(*NowUs)(void*);
 int(*Stage)(void*,const uint8_t*,uint32_t,uint64_t);int(*Publish)(void*,const uint8_t*,uint32_t);
 int(*SampleIrq)(void*,G57_POLL_IRQ*);
}G57_POLL_IO;
/* Caller owns the powered controller/engine and exact undo. GPIO observations
 * diagnose readiness, not IRQ delivery and do not gate or synthesize packets. */
int G57Poll(const G57_POLL_IO*,G57_POLL_RESULT*);
#endif
