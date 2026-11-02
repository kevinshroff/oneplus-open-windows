/* SPDX-License-Identifier: MIT */
#ifndef G48_CONTRACT_H
#define G48_CONTRACT_H
#include <stdint.h>
typedef struct {
 uint32_t Attempted,TransportOk,ContractVerified,HeaderPresent,HeaderChecksumValid,BodyComplete,BodyChecksumValid,EventFlags,PointCount,PointType;
 int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;
 uint8_t Tx[36],Rx[36];
} G48_REPORT_RESULT;
int G48InfoContract(const uint8_t*,uint32_t);
void G48AnalyzeReport(G48_REPORT_RESULT*);
#endif
