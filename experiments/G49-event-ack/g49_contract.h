/* SPDX-License-Identifier: MIT */
#ifndef G49_CONTRACT_H
#define G49_CONTRACT_H
#include <stdint.h>
typedef struct {
 uint32_t Attempted,TransportOk,ContractVerified,HeaderPresent,HeaderChecksumValid,BodyComplete,BodyChecksumValid,EventFlags,PointCount,PointType;
 int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;
 uint8_t Tx[36],Rx[36];
} G49_REPORT_RESULT;
int G49InfoContract(const uint8_t*,uint32_t);
void G49AnalyzeReport(G49_REPORT_RESULT*);
void G49AnalyzeHeader(G49_REPORT_RESULT*);
int G49AckEligible(const G49_REPORT_RESULT*);
int G49EventClearFrame(uint8_t*,uint32_t);
#endif
