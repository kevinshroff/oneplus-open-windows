/* SPDX-License-Identifier: MIT */
#ifndef G92_TOUCH_H
#define G92_TOUCH_H
#include "geni_fifo.h"
#include "g92_observer.h"
#include "g92_contract.h"
#include "g92_poll.h"
#define G92_POLL_WIRES 400u
#define G92_TOUCH_TRACE_SLOTS 65536u
#define G92_TOUCH_READ_BUDGET 2000000u
#define G92_TOUCH_WRITE_BUDGET 1000000u
#define G92_TOUCH_EVENT_BUDGET 3000000u
enum {G92_WIRE_PREFETCH=1,G92_WIRE_TAIL=2,G92_WIRE_CLEAR=3,G92_WIRE_RETRY=4};
typedef struct {
 uint32_t Kind,Address,Payload,Attempted,TransportOk;int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;uint8_t Tx[72],Rx[72];
} G92_WIRE_RESULT;
typedef struct {uint32_t Kind,Address,Value;} G92_TOUCH_EVENT;
typedef struct {uint32_t ElapsedUs,Control,Input,Config,Status;} G92_IRQ_SAMPLE;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,AnalogDirty,ResetDirty,CommandAttempted,TransportOk,IdentityOk,BusQuiescent,LengthsSaved,LengthsRestored,LengthsDirty,IrqAcked;
 int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;
 uint32_t BeforePins[12],OnPins[12],AfterPins[12],LengthsBefore[2],LengthsAfter[2],CommandHistory[2],WaitCounts[5];
 uint8_t Tx[252],Rx[252];struct g27_goodix_version Version;
 G92_TOUCH_EVENT Trace[65536];G92_OBS_RESULT PoweredPmic;uint32_t InfoLength,HeaderLengthValid,FullBlockChecksumValid;G92_REPORT_RESULT Report,Ack,Post;uint32_t IrqSamples,ReportIrq[2],PostIrq[2];uint32_t SettleCount;G92_IRQ_SAMPLE Settle[6];
 G92_POLL_RESULT Poll;uint32_t PollFrameCount;G92_WIRE_RESULT PollFrames[G92_POLL_WIRES];
} G92_TOUCH_RESULT;
typedef struct {
 void*Context;uint32_t PollLimit;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);
 int(*Barrier)(void*);int(*Ready)(void*);void(*WaitMs)(void*,uint32_t);void(*WaitPoll)(void*);uint64_t(*NowUs)(void*);
 int(*StageInput)(void*,const uint8_t*,uint32_t,uint64_t);int(*PublishInput)(void*,const uint8_t*,uint32_t);
 int(*StopRequested)(void*);
 int(*Advance)(void*);
} G92_TOUCH_IO;
#define G92_TOUCH_CANCELLED 21u
/* Caller already owns/configures the primary engine and supplies digital power. */
int G92TouchRead(const G92_TOUCH_IO*,G92_TOUCH_RESULT*);
int G92VerifyTouchOff(const G92_TOUCH_IO*,G92_TOUCH_RESULT*);
#endif

/* Recompute the next wire permission from complete raw packet history. */
int G92PollPlan(const G92_TOUCH_RESULT*,uint32_t,uint32_t);
int G92CycleComplete(const G92_TOUCH_RESULT*,uint32_t,uint32_t);
