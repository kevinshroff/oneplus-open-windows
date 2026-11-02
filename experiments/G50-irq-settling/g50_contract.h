/* SPDX-License-Identifier: MIT */
#ifndef G50_CONTRACT_H
#define G50_CONTRACT_H
#include <stdint.h>
typedef struct {
 uint32_t Attempted,TransportOk,ContractVerified,HeaderPresent,HeaderChecksumValid,BodyComplete,BodyChecksumValid,EventFlags,PointCount,PointType;
 int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;
 uint8_t Tx[36],Rx[36];
} G50_REPORT_RESULT;
int G50InfoContract(const uint8_t*,uint32_t);
void G50AnalyzeReport(G50_REPORT_RESULT*);
void G50AnalyzeHeader(G50_REPORT_RESULT*);
int G50AckEligible(const G50_REPORT_RESULT*);
int G50EventClearFrame(uint8_t*,uint32_t);
#endif
