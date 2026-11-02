/* SPDX-License-Identifier: MIT */
#ifndef G92_CONTRACT_H
#define G92_CONTRACT_H
#include <stdint.h>
typedef struct {
 uint32_t Attempted,TransportOk,ContractVerified,HeaderPresent,HeaderChecksumValid,BodyComplete,BodyChecksumValid,EventFlags,PointCount,PointType;
 int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;
 uint8_t Tx[36],Rx[36];
} G92_REPORT_RESULT;
int G92InfoContract(const uint8_t*,uint32_t);
void G92AnalyzeReport(G92_REPORT_RESULT*);
void G92AnalyzeHeader(G92_REPORT_RESULT*);
int G92AckEligible(const G92_REPORT_RESULT*);
int G92EventClearFrame(uint8_t*,uint32_t);
#endif
