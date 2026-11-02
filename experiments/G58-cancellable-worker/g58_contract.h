/* SPDX-License-Identifier: MIT */
#ifndef G58_CONTRACT_H
#define G58_CONTRACT_H
#include <stdint.h>
typedef struct {
 uint32_t Attempted,TransportOk,ContractVerified,HeaderPresent,HeaderChecksumValid,BodyComplete,BodyChecksumValid,EventFlags,PointCount,PointType;
 int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;
 uint8_t Tx[36],Rx[36];
} G58_REPORT_RESULT;
int G58InfoContract(const uint8_t*,uint32_t);
void G58AnalyzeReport(G58_REPORT_RESULT*);
void G58AnalyzeHeader(G58_REPORT_RESULT*);
int G58AckEligible(const G58_REPORT_RESULT*);
int G58EventClearFrame(uint8_t*,uint32_t);
#endif
