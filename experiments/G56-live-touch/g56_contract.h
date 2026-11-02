/* SPDX-License-Identifier: MIT */
#ifndef G56_CONTRACT_H
#define G56_CONTRACT_H
#include <stdint.h>
typedef struct {
 uint32_t Attempted,TransportOk,ContractVerified,HeaderPresent,HeaderChecksumValid,BodyComplete,BodyChecksumValid,EventFlags,PointCount,PointType;
 int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;
 uint8_t Tx[36],Rx[36];
} G56_REPORT_RESULT;
int G56InfoContract(const uint8_t*,uint32_t);
void G56AnalyzeReport(G56_REPORT_RESULT*);
void G56AnalyzeHeader(G56_REPORT_RESULT*);
int G56AckEligible(const G56_REPORT_RESULT*);
int G56EventClearFrame(uint8_t*,uint32_t);
#endif
