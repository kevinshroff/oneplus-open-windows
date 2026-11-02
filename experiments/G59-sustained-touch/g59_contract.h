/* SPDX-License-Identifier: MIT */
#ifndef G59_CONTRACT_H
#define G59_CONTRACT_H
#include <stdint.h>
typedef struct {
 uint32_t Attempted,TransportOk,ContractVerified,HeaderPresent,HeaderChecksumValid,BodyComplete,BodyChecksumValid,EventFlags,PointCount,PointType;
 int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;
 uint8_t Tx[36],Rx[36];
} G59_REPORT_RESULT;
int G59InfoContract(const uint8_t*,uint32_t);
void G59AnalyzeReport(G59_REPORT_RESULT*);
void G59AnalyzeHeader(G59_REPORT_RESULT*);
int G59AckEligible(const G59_REPORT_RESULT*);
int G59EventClearFrame(uint8_t*,uint32_t);
#endif
