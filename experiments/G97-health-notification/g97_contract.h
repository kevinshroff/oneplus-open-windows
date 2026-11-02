/* SPDX-License-Identifier: MIT */
#ifndef G97_CONTRACT_H
#define G97_CONTRACT_H
#include <stdint.h>
typedef struct {
 uint32_t Attempted,TransportOk,ContractVerified,HeaderPresent,HeaderChecksumValid,BodyComplete,BodyChecksumValid,EventFlags,PointCount,PointType;
 int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;
 uint8_t Tx[36],Rx[36];
} G97_REPORT_RESULT;
int G97InfoContract(const uint8_t*,uint32_t);
void G97AnalyzeReport(G97_REPORT_RESULT*);
void G97AnalyzeHeader(G97_REPORT_RESULT*);
int G97AckEligible(const G97_REPORT_RESULT*);
int G97EventClearFrame(uint8_t*,uint32_t);
#endif
