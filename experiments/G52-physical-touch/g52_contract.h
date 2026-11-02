/* SPDX-License-Identifier: MIT */
#ifndef G52_CONTRACT_H
#define G52_CONTRACT_H
#include <stdint.h>
typedef struct {
 uint32_t Attempted,TransportOk,ContractVerified,HeaderPresent,HeaderChecksumValid,BodyComplete,BodyChecksumValid,EventFlags,PointCount,PointType;
 int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;
 uint8_t Tx[36],Rx[36];
} G52_REPORT_RESULT;
int G52InfoContract(const uint8_t*,uint32_t);
void G52AnalyzeReport(G52_REPORT_RESULT*);
void G52AnalyzeHeader(G52_REPORT_RESULT*);
int G52AckEligible(const G52_REPORT_RESULT*);
int G52EventClearFrame(uint8_t*,uint32_t);
#endif
