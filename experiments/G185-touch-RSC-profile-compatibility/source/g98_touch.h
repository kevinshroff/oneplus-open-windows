/* SPDX-License-Identifier: MIT */
#ifndef G98_TOUCH_H
#define G98_TOUCH_H
#include "geni_fifo.h"
#include "g98_observer.h"
#include "g98_contract.h"
#include "g98_poll.h"
#define G98_POLL_WIRES 400u
#define G98_TOUCH_TRACE_SLOTS 65536u
#define G98_TOUCH_READ_BUDGET 250000000u
#define G98_TOUCH_WRITE_BUDGET 100000000u
#define G98_TOUCH_EVENT_BUDGET 350000000u
enum {G98_WIRE_PREFETCH=1,G98_WIRE_TAIL=2,G98_WIRE_CLEAR=3,G98_WIRE_RETRY=4};
typedef struct {
 uint32_t Kind,Address,Payload,Attempted,TransportOk;int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;uint8_t Tx[72],Rx[72];
} G98_WIRE_RESULT;
typedef struct {uint32_t Kind,Address,Value;} G98_TOUCH_EVENT;
typedef struct {uint32_t ElapsedUs,Control,Input,Config,Status;} G98_IRQ_SAMPLE;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,AnalogDirty,ResetDirty,CommandAttempted,TransportOk,IdentityOk,BusQuiescent,LengthsSaved,LengthsRestored,LengthsDirty,IrqAcked;
 int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;
 uint32_t BeforePins[12],OnPins[12],AfterPins[12],LengthsBefore[2],LengthsAfter[2],CommandHistory[2],WaitCounts[5];
 uint8_t Tx[252],Rx[252];struct g27_goodix_version Version;
 G98_TOUCH_EVENT Trace[65536];G98_OBS_RESULT PoweredPmic;uint32_t InfoLength,HeaderLengthValid,FullBlockChecksumValid;G98_REPORT_RESULT Report,Ack,Post;uint32_t IrqSamples,ReportIrq[2],PostIrq[2];uint32_t SettleCount;G98_IRQ_SAMPLE Settle[6];
 G98_POLL_RESULT Poll;uint32_t PollFrameCount;G98_WIRE_RESULT PollFrames[G98_POLL_WIRES];
} G98_TOUCH_RESULT;
typedef struct {
 void*Context;uint32_t PollLimit;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);
 int(*Barrier)(void*);int(*Ready)(void*);void(*WaitMs)(void*,uint32_t);void(*WaitPoll)(void*);uint64_t(*NowUs)(void*);
 int(*StageInput)(void*,const uint8_t*,uint32_t,uint64_t);int(*PublishInput)(void*,const uint8_t*,uint32_t);
 int(*StopRequested)(void*);
 int(*Advance)(void*);
 /* Non-NULL only for the persistent owner. Retire one fully completed epoch
  * after independent native terminal/quiescence proof. No power or input
  * state is reset at this boundary. Failure ends the powered session. */
 int(*Retire)(void*);
} G98_TOUCH_IO;
#define G98_TOUCH_CANCELLED 21u
/* Caller already owns/configures the primary engine and supplies digital power. */
int G98TouchRead(const G98_TOUCH_IO*,G98_TOUCH_RESULT*);
int G98VerifyTouchOff(const G98_TOUCH_IO*,G98_TOUCH_RESULT*);
#endif

/* Recompute the next wire permission from complete raw packet history. */
int G98PollPlan(const G98_TOUCH_RESULT*,uint32_t,uint32_t);
int G98CycleComplete(const G98_TOUCH_RESULT*,uint32_t,uint32_t);
