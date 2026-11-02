/* SPDX-License-Identifier: MIT */
#ifndef G98_CONTRACT_H
#define G98_CONTRACT_H
#include <stdint.h>
typedef struct {
 uint32_t Attempted,TransportOk,ContractVerified,HeaderPresent,HeaderChecksumValid,BodyComplete,BodyChecksumValid,EventFlags,PointCount,PointType;
 int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;
 uint8_t Tx[36],Rx[36];
} G98_REPORT_RESULT;
int G98InfoContract(const uint8_t*,uint32_t);
void G98AnalyzeReport(G98_REPORT_RESULT*);
void G98AnalyzeHeader(G98_REPORT_RESULT*);
int G98AckEligible(const G98_REPORT_RESULT*);
int G98EventClearFrame(uint8_t*,uint32_t);
#endif
