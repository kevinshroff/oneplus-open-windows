/* SPDX-License-Identifier: MIT */
#ifndef G56_TOUCH_H
#define G56_TOUCH_H
#include "geni_fifo.h"
#include "g56_observer.h"
#include "g56_contract.h"
#include "g56_poll.h"
#define G56_POLL_WIRES 300u
enum {G56_WIRE_PREFETCH=1,G56_WIRE_TAIL=2,G56_WIRE_CLEAR=3};
typedef struct {
 uint32_t Kind,Address,Payload,Attempted,TransportOk;int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;uint8_t Tx[72],Rx[72];
} G56_WIRE_RESULT;
typedef struct {uint32_t Kind,Address,Value;} G56_TOUCH_EVENT;
typedef struct {uint32_t ElapsedUs,Control,Input,Config,Status;} G56_IRQ_SAMPLE;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,AnalogDirty,ResetDirty,CommandAttempted,TransportOk,IdentityOk,BusQuiescent,LengthsSaved,LengthsRestored,LengthsDirty,IrqAcked;
 int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;
 uint32_t BeforePins[12],OnPins[12],AfterPins[12],LengthsBefore[2],LengthsAfter[2],CommandHistory[2],WaitCounts[5];
 uint8_t Tx[252],Rx[252];struct g27_goodix_version Version;
 G56_TOUCH_EVENT Trace[65536];G56_OBS_RESULT PoweredPmic;uint32_t InfoLength,HeaderLengthValid,FullBlockChecksumValid;G56_REPORT_RESULT Report,Ack,Post;uint32_t IrqSamples,ReportIrq[2],PostIrq[2];uint32_t SettleCount;G56_IRQ_SAMPLE Settle[6];
 G56_POLL_RESULT Poll;uint32_t PollFrameCount;G56_WIRE_RESULT PollFrames[G56_POLL_WIRES];
} G56_TOUCH_RESULT;
typedef struct {
 void*Context;uint32_t PollLimit;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);
 int(*Barrier)(void*);int(*Ready)(void*);void(*WaitMs)(void*,uint32_t);void(*WaitPoll)(void*);uint64_t(*NowUs)(void*);
 int(*StageInput)(void*,const uint8_t*,uint32_t,uint64_t);int(*PublishInput)(void*,const uint8_t*,uint32_t);
} G56_TOUCH_IO;
/* Caller already owns/configures the primary engine and supplies digital power. */
int G56TouchRead(const G56_TOUCH_IO*,G56_TOUCH_RESULT*);
int G56VerifyTouchOff(const G56_TOUCH_IO*,G56_TOUCH_RESULT*);
#endif

/* Recompute the next wire permission from complete raw packet history. */
int G56PollPlan(const G56_TOUCH_RESULT*,uint32_t);
