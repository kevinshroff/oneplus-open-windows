/* SPDX-License-Identifier: MIT */
#ifndef G45_TOUCH_H
#define G45_TOUCH_H
#include "geni_fifo.h"
#include "g45_observer.h"
typedef struct {uint32_t Kind,Address,Value;} G45_TOUCH_EVENT;
typedef struct {
 uint32_t Code,RestoreError,Restored,Stage,Reads,Writes,TraceCount,AnalogDirty,ResetDirty,CommandAttempted,TransportOk,IdentityOk,BusQuiescent,LengthsSaved,LengthsRestored,LengthsDirty,IrqAcked;
 int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;
 uint32_t BeforePins[12],OnPins[12],AfterPins[12],LengthsBefore[2],LengthsAfter[2],CommandHistory[2],WaitCounts[5];
 uint8_t Tx[36],Rx[36];struct g27_goodix_version Version;
 G45_TOUCH_EVENT Trace[1024];G45_OBS_RESULT PoweredPmic;
} G45_TOUCH_RESULT;
typedef struct {
 void*Context;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);
 int(*Barrier)(void*);int(*Ready)(void*);void(*WaitMs)(void*,uint32_t);void(*WaitPoll)(void*);uint64_t(*NowUs)(void*);
} G45_TOUCH_IO;
/* Caller already owns/configures the primary engine and supplies digital power. */
int G45RestoreTouchHeld(const G45_TOUCH_IO*,G45_TOUCH_RESULT*,const uint32_t*);
int G45VerifyTouchOff(const G45_TOUCH_IO*,G45_TOUCH_RESULT*);
#endif
