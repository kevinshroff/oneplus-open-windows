/* SPDX-License-Identifier: MIT */
#ifndef G96_POLL_H
#define G96_POLL_H
#include "g96_report.h"
#define G96_POLL_CYCLES 300000u
#define G96_PLAY_CYCLES 300000u
#define G96_PLAY_DEADLINE_US 3600000000u
#define G96_NATIVE_CYCLES 2500u
#define G96_POLL_RECORDS 100u
#define G96_POLL_DEADLINE_US 45000000u
#define G96_READ_PREFETCH 1u
#define G96_READ_TAIL 2u
#define G96_READ_RETRY 4u
enum {G96_POLL_OK=0,G96_POLL_ARGUMENT=1,G96_POLL_CLOCK=2,G96_POLL_READ=3,G96_POLL_DECODE=4,G96_POLL_CLEAR=5,G96_POLL_QUIET=6,G96_POLL_STAGE=7,G96_POLL_PUBLISH=8,G96_POLL_IRQ_ERROR=9};
#define G96_POLL_CANCELLED 10u
#define G96_POLL_ADVANCE_ERROR 11u
typedef struct {uint32_t Control,Input,Config,Status;}G96_POLL_IRQ;
typedef struct {
 uint32_t ReadBytes,TailRead,ClearAttempted,ClearCompleted,ElapsedUs,IrqMask;
 G96_POLL_IRQ Irq[4];uint32_t RetryKind,FirstReadBytes;
 uint8_t First[26],Bytes[G96_REPORT_MAX];G96_FRAME Frame;
}G96_POLL_RECORD;
typedef struct {
 uint32_t Code,Limit,Cycles,ReadAttempts,TailReads,ClearAttempts,ClearCompleted,IdleRecords,ContactRecords,RequestRecords,BusQuiescent,ElapsedUs,ReadRetries,PrefixesRecovered,IrqReadAttempts;
 G96_POLL_RECORD Records[G96_POLL_RECORDS];
}G96_POLL_RESULT;
typedef struct {
 void*Context;uint32_t Limit;
 /* A retry is one exact26-byte read after proven transport completion and
  * bad header integrity or a bad body contained completely in that prefix.
  * No uncertain transfer, tail read, or write is ever retried. */
 int(*Read)(void*,uint32_t,uint32_t,uint8_t*,uint32_t);int(*Clear)(void*);int(*Quiet)(void*);
 void(*WaitTenMs)(void*);uint64_t(*NowUs)(void*);
 int(*Stage)(void*,const uint8_t*,uint32_t,uint64_t);int(*Publish)(void*,const uint8_t*,uint32_t);
 int(*SampleIrq)(void*,G96_POLL_IRQ*);
 int(*StopRequested)(void*);
 int(*Advance)(void*);
}G96_POLL_IO;
/* Caller owns the powered controller/engine and exact undo. GPIO observations
 * diagnose readiness, not IRQ delivery and do not gate or synthesize packets. */
int G96Poll(const G96_POLL_IO*,G96_POLL_RESULT*);
#endif
