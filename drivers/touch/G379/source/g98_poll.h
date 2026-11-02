/* SPDX-License-Identifier: MIT */
#ifndef G98_POLL_H
#define G98_POLL_H
#include "g98_report.h"
#define G98_POLL_CYCLES 300000u
#define G98_PLAY_CYCLES 300000u
#define G98_PLAY_DEADLINE_US 3600000000u
#define G98_NATIVE_CYCLES 2500u
#define G98_EPOCH_CYCLES 2048u
#define G98_POLL_RECORDS 100u
#define G98_POLL_DEADLINE_US 45000000u
#define G98_READ_PREFETCH 1u
#define G98_READ_TAIL 2u
#define G98_READ_RETRY 4u
enum {G98_POLL_OK=0,G98_POLL_ARGUMENT=1,G98_POLL_CLOCK=2,G98_POLL_READ=3,G98_POLL_DECODE=4,G98_POLL_CLEAR=5,G98_POLL_QUIET=6,G98_POLL_STAGE=7,G98_POLL_PUBLISH=8,G98_POLL_IRQ_ERROR=9};
#define G98_POLL_CANCELLED 10u
#define G98_POLL_ADVANCE_ERROR 11u
typedef struct {uint32_t Control,Input,Config,Status;}G98_POLL_IRQ;
typedef struct {
 uint32_t ReadBytes,TailRead,ClearAttempted,ClearCompleted,ElapsedUs,IrqMask;
 G98_POLL_IRQ Irq[4];uint32_t RetryKind,FirstReadBytes;
 uint8_t First[26],Bytes[G98_REPORT_MAX];G98_FRAME Frame;
}G98_POLL_RECORD;
typedef struct {
 uint32_t Code,Limit,Cycles,ReadAttempts,TailReads,ClearAttempts,ClearCompleted,IdleRecords,ContactRecords,ControlRecords,BusQuiescent,ElapsedUs,ReadRetries,PrefixesRecovered,IrqReadAttempts;
 G98_POLL_RECORD Records[G98_POLL_RECORDS];
}G98_POLL_RESULT;
typedef struct {
 void*Context;uint32_t Limit;
 /* A retry is one exact26-byte read after proven transport completion and
  * bad header integrity or a bad body contained completely in that prefix.
  * No uncertain transfer, tail read, or write is ever retried. */
 int(*Read)(void*,uint32_t,uint32_t,uint8_t*,uint32_t);int(*Clear)(void*);int(*Quiet)(void*);
 void(*WaitTenMs)(void*);uint64_t(*NowUs)(void*);
 int(*Stage)(void*,const uint8_t*,uint32_t,uint64_t);int(*Publish)(void*,const uint8_t*,uint32_t);
 int(*SampleIrq)(void*,G98_POLL_IRQ*);
 int(*StopRequested)(void*);
 int(*Advance)(void*);
}G98_POLL_IO;
/* Caller owns the powered controller/engine and exact undo. GPIO observations
 * diagnose readiness, not IRQ delivery and do not gate or synthesize packets. */
int G98Poll(const G98_POLL_IO*,G98_POLL_RESULT*);
#endif
