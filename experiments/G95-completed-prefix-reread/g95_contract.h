/* SPDX-License-Identifier: MIT */
#ifndef G95_CONTRACT_H
#define G95_CONTRACT_H
#include <stdint.h>
typedef struct {
 uint32_t Attempted,TransportOk,ContractVerified,HeaderPresent,HeaderChecksumValid,BodyComplete,BodyChecksumValid,EventFlags,PointCount,PointType;
 int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;
 uint8_t Tx[36],Rx[36];
} G95_REPORT_RESULT;
int G95InfoContract(const uint8_t*,uint32_t);
void G95AnalyzeReport(G95_REPORT_RESULT*);
void G95AnalyzeHeader(G95_REPORT_RESULT*);
int G95AckEligible(const G95_REPORT_RESULT*);
int G95EventClearFrame(uint8_t*,uint32_t);
#endif
