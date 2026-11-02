/* SPDX-License-Identifier: MIT */
#ifndef G95_POLL_H
#define G95_POLL_H
#include "g95_report.h"
#define G95_POLL_CYCLES 3000u
#define G95_NATIVE_CYCLES 2500u
#define G95_POLL_RECORDS 100u
#define G95_POLL_DEADLINE_US 45000000u
#define G95_READ_PREFETCH 1u
#define G95_READ_TAIL 2u
#define G95_READ_RETRY 4u
enum {G95_POLL_OK=0,G95_POLL_ARGUMENT=1,G95_POLL_CLOCK=2,G95_POLL_READ=3,G95_POLL_DECODE=4,G95_POLL_CLEAR=5,G95_POLL_QUIET=6,G95_POLL_STAGE=7,G95_POLL_PUBLISH=8,G95_POLL_IRQ_ERROR=9};
#define G95_POLL_CANCELLED 10u
#define G95_POLL_ADVANCE_ERROR 11u
typedef struct {uint32_t Control,Input,Config,Status;}G95_POLL_IRQ;
typedef struct {
 uint32_t ReadBytes,TailRead,ClearAttempted,ClearCompleted,ElapsedUs,IrqMask;
 G95_POLL_IRQ Irq[4];uint32_t RetryKind,FirstReadBytes;
 uint8_t First[26],Bytes[G95_REPORT_MAX];G95_FRAME Frame;
}G95_POLL_RECORD;
typedef struct {
 uint32_t Code,Limit,Cycles,ReadAttempts,TailReads,ClearAttempts,ClearCompleted,IdleRecords,ContactRecords,RequestRecords,BusQuiescent,ElapsedUs,ReadRetries,PrefixesRecovered,IrqReadAttempts;
 G95_POLL_RECORD Records[G95_POLL_RECORDS];
}G95_POLL_RESULT;
typedef struct {
 void*Context;uint32_t Limit;
 /* A retry is one exact26-byte read after proven transport completion and
  * bad header integrity or a bad body contained completely in that prefix.
  * No uncertain transfer, tail read, or write is ever retried. */
 int(*Read)(void*,uint32_t,uint32_t,uint8_t*,uint32_t);int(*Clear)(void*);int(*Quiet)(void*);
 void(*WaitTenMs)(void*);uint64_t(*NowUs)(void*);
 int(*Stage)(void*,const uint8_t*,uint32_t,uint64_t);int(*Publish)(void*,const uint8_t*,uint32_t);
 int(*SampleIrq)(void*,G95_POLL_IRQ*);
 int(*StopRequested)(void*);
 int(*Advance)(void*);
}G95_POLL_IO;
/* Caller owns the powered controller/engine and exact undo. GPIO observations
 * diagnose readiness, not IRQ delivery and do not gate or synthesize packets. */
int G95Poll(const G95_POLL_IO*,G95_POLL_RESULT*);
#endif
