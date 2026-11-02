/* SPDX-License-Identifier: MIT */
#ifndef G57_CONTRACT_H
#define G57_CONTRACT_H
#include <stdint.h>
typedef struct {
 uint32_t Attempted,TransportOk,ContractVerified,HeaderPresent,HeaderChecksumValid,BodyComplete,BodyChecksumValid,EventFlags,PointCount,PointType;
 int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;
 uint8_t Tx[36],Rx[36];
} G57_REPORT_RESULT;
int G57InfoContract(const uint8_t*,uint32_t);
void G57AnalyzeReport(G57_REPORT_RESULT*);
void G57AnalyzeHeader(G57_REPORT_RESULT*);
int G57AckEligible(const G57_REPORT_RESULT*);
int G57EventClearFrame(uint8_t*,uint32_t);
#endif
