/* SPDX-License-Identifier: MIT */
#ifndef G54_CONTRACT_H
#define G54_CONTRACT_H
#include <stdint.h>
typedef struct {
 uint32_t Attempted,TransportOk,ContractVerified,HeaderPresent,HeaderChecksumValid,BodyComplete,BodyChecksumValid,EventFlags,PointCount,PointType;
 int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;
 uint8_t Tx[36],Rx[36];
} G54_REPORT_RESULT;
int G54InfoContract(const uint8_t*,uint32_t);
void G54AnalyzeReport(G54_REPORT_RESULT*);
void G54AnalyzeHeader(G54_REPORT_RESULT*);
int G54AckEligible(const G54_REPORT_RESULT*);
int G54EventClearFrame(uint8_t*,uint32_t);
#endif
