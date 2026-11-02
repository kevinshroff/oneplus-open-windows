/* SPDX-License-Identifier: MIT */
#ifndef G40_TOUCH_H
#define G40_TOUCH_H
#include "geni_fifo.h"
#include "g40_observer.h"
typedef struct {uint32_t Kind,Address,Value;} G40_TOUCH_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,AnalogDirty,ResetDirty,CommandAttempted,TransportOk,IdentityOk,BusQuiescent,LengthsSaved,LengthsRestored,LengthsDirty,IrqAcked;
 int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;
 uint32_t BeforePins[12],OnPins[12],AfterPins[12],LengthsBefore[2],LengthsAfter[2],CommandHistory[2],WaitCounts[5];
 uint8_t Tx[36],Rx[36];struct g27_goodix_version Version;
 G40_TOUCH_EVENT Trace[1024];G40_OBS_RESULT PoweredPmic;
} G40_TOUCH_RESULT;
typedef struct {
 void*Context;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);
 int(*Barrier)(void*);int(*Ready)(void*);void(*WaitMs)(void*,uint32_t);void(*WaitPoll)(void*);uint64_t(*NowUs)(void*);
} G40_TOUCH_IO;
/* Caller already owns/configures the primary engine and supplies digital power. */
int G40TouchRead(const G40_TOUCH_IO*,G40_TOUCH_RESULT*);
#endif
