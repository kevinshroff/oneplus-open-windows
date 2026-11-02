/* SPDX-License-Identifier: MIT */
#ifndef G53_CONTRACT_H
#define G53_CONTRACT_H
#include <stdint.h>
typedef struct {
 uint32_t Attempted,TransportOk,ContractVerified,HeaderPresent,HeaderChecksumValid,BodyComplete,BodyChecksumValid,EventFlags,PointCount,PointType;
 int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;
 uint8_t Tx[36],Rx[36];
} G53_REPORT_RESULT;
int G53InfoContract(const uint8_t*,uint32_t);
void G53AnalyzeReport(G53_REPORT_RESULT*);
void G53AnalyzeHeader(G53_REPORT_RESULT*);
int G53AckEligible(const G53_REPORT_RESULT*);
int G53EventClearFrame(uint8_t*,uint32_t);
#endif
