/* SPDX-License-Identifier: MIT */
#ifndef G96_CONTRACT_H
#define G96_CONTRACT_H
#include <stdint.h>
typedef struct {
 uint32_t Attempted,TransportOk,ContractVerified,HeaderPresent,HeaderChecksumValid,BodyComplete,BodyChecksumValid,EventFlags,PointCount,PointType;
 int32_t StartCode,StepCode;
 uint32_t State,Steps,TxDone,RxDone,CancelSent,AbortSent;
 uint8_t Tx[36],Rx[36];
} G96_REPORT_RESULT;
int G96InfoContract(const uint8_t*,uint32_t);
void G96AnalyzeReport(G96_REPORT_RESULT*);
void G96AnalyzeHeader(G96_REPORT_RESULT*);
int G96AckEligible(const G96_REPORT_RESULT*);
int G96EventClearFrame(uint8_t*,uint32_t);
#endif
