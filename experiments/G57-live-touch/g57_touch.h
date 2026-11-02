/* SPDX-License-Identifier: MIT */
#ifndef G57_TOUCH_H
#define G57_TOUCH_H
#include "geni_fifo.h"
#include "g57_observer.h"
#include "g57_contract.h"
#include "g57_poll.h"
#define G57_POLL_WIRES 400u
enum {G57_WIRE_PREFETCH=1,G57_WIRE_TAIL=2,G57_WIRE_CLEAR=3,G57_WIRE_RETRY=4};
typedef struct {
 uint32_t Kind,Address,Payload,Attempted,TransportOk;int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;uint8_t Tx[72],Rx[72];
} G57_WIRE_RESULT;
typedef struct {uint32_t Kind,Address,Value;} G57_TOUCH_EVENT;
typedef struct {uint32_t ElapsedUs,Control,Input,Config,Status;} G57_IRQ_SAMPLE;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,AnalogDirty,ResetDirty,CommandAttempted,TransportOk,IdentityOk,BusQuiescent,LengthsSaved,LengthsRestored,LengthsDirty,IrqAcked;
 int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;
 uint32_t BeforePins[12],OnPins[12],AfterPins[12],LengthsBefore[2],LengthsAfter[2],CommandHistory[2],WaitCounts[5];
 uint8_t Tx[252],Rx[252];struct g27_goodix_version Version;
 G57_TOUCH_EVENT Trace[65536];G57_OBS_RESULT PoweredPmic;uint32_t InfoLength,HeaderLengthValid,FullBlockChecksumValid;G57_REPORT_RESULT Report,Ack,Post;uint32_t IrqSamples,ReportIrq[2],PostIrq[2];uint32_t SettleCount;G57_IRQ_SAMPLE Settle[6];
 G57_POLL_RESULT Poll;uint32_t PollFrameCount;G57_WIRE_RESULT PollFrames[G57_POLL_WIRES];
} G57_TOUCH_RESULT;
typedef struct {
 void*Context;uint32_t PollLimit;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);
 int(*Barrier)(void*);int(*Ready)(void*);void(*WaitMs)(void*,uint32_t);void(*WaitPoll)(void*);uint64_t(*NowUs)(void*);
 int(*StageInput)(void*,const uint8_t*,uint32_t,uint64_t);int(*PublishInput)(void*,const uint8_t*,uint32_t);
} G57_TOUCH_IO;
/* Caller already owns/configures the primary engine and supplies digital power. */
int G57TouchRead(const G57_TOUCH_IO*,G57_TOUCH_RESULT*);
int G57VerifyTouchOff(const G57_TOUCH_IO*,G57_TOUCH_RESULT*);
#endif

/* Recompute the next wire permission from complete raw packet history. */
int G57PollPlan(const G57_TOUCH_RESULT*,uint32_t);
