/* SPDX-License-Identifier: MIT */
#ifndef G52_TOUCH_H
#define G52_TOUCH_H
#include "geni_fifo.h"
#include "g52_observer.h"
#include "g52_contract.h"
typedef struct {uint32_t Kind,Address,Value;} G52_TOUCH_EVENT;
typedef struct {uint32_t ElapsedUs,Control,Input,Config,Status;} G52_IRQ_SAMPLE;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,AnalogDirty,ResetDirty,CommandAttempted,TransportOk,IdentityOk,BusQuiescent,LengthsSaved,LengthsRestored,LengthsDirty,IrqAcked;
 int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;
 uint32_t BeforePins[12],OnPins[12],AfterPins[12],LengthsBefore[2],LengthsAfter[2],CommandHistory[2],WaitCounts[5];
 uint8_t Tx[252],Rx[252];struct g27_goodix_version Version;
 G52_TOUCH_EVENT Trace[2048];G52_OBS_RESULT PoweredPmic;uint32_t InfoLength,HeaderLengthValid,FullBlockChecksumValid;G52_REPORT_RESULT Report,Ack,Post;uint32_t IrqSamples,ReportIrq[2],PostIrq[2];uint32_t SettleCount;G52_IRQ_SAMPLE Settle[6];
} G52_TOUCH_RESULT;
typedef struct {
 void*Context;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);
 int(*Barrier)(void*);int(*Ready)(void*);void(*WaitMs)(void*,uint32_t);void(*WaitPoll)(void*);uint64_t(*NowUs)(void*);
} G52_TOUCH_IO;
/* Caller already owns/configures the primary engine and supplies digital power. */
int G52TouchRead(const G52_TOUCH_IO*,G52_TOUCH_RESULT*);
int G52VerifyTouchOff(const G52_TOUCH_IO*,G52_TOUCH_RESULT*);
#endif
