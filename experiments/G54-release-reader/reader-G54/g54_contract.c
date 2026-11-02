/* SPDX-License-Identifier: MIT
 * Bounded interpretation of the pinned Goodix v1 IC-info and report layouts.
 * No MMIO or allocation exists. The sole write frame clears the source-defined event flag.
 */
#include "g54_contract.h"
static uint32_t Le16(const uint8_t*p){return(uint32_t)p[0]|((uint32_t)p[1]<<8);}
static uint32_t Le32(const uint8_t*p){return Le16(p)|(Le16(p+2)<<16);}
static int Sum(const uint8_t*p,uint32_t n)
{
 uint32_t i,sum=0;if(n<2)return 0;for(i=0;i<n-2;i++)sum+=p[i];return(sum&0xffffu)==Le16(p+n-2);
}
int G54InfoContract(const uint8_t*b,uint32_t n)
{
 static const uint32_t caps[5]={5,5,5,5,8};uint32_t at=32,i,count;
 if(!b||n!=242||Le16(b)!=n||!Sum(b,n))return 0;
 if(b[2]!=1||b[3]!=1||b[13]!=1||b[14]!=0)return 0;
 for(i=0;i<5;i++){
  if(at>=n-2)return 0;count=b[at++];if(count>caps[i]||count*2>n-2-at)return 0;at+=count*2;
 }
 if(at>n-2||114>n-2-at)return 0;
 return Le32(b+at+44)==0x10274&&Le16(b+at+48)==8&&Le16(b+at+50)==8;
}
void G54AnalyzeReport(G54_REPORT_RESULT*r)
{
 const uint8_t*p=r->Rx+8;uint32_t bytes;
 if(!r->TransportOk)return;
 r->EventFlags=p[0];r->PointCount=p[2]&15;r->PointType=0;r->HeaderPresent=p[0]!=0;
 if(!r->HeaderPresent)return;
 r->HeaderChecksumValid=Sum(p,8);if(!r->HeaderChecksumValid||!(p[0]&0x80)||r->PointCount>10)return;
 if(!r->PointCount)return;r->PointType=p[8]&15;
 bytes=(r->PointType==1||r->PointType==3)?18:r->PointCount*8+2;
 r->BodyComplete=bytes<=18;if(r->BodyComplete)r->BodyChecksumValid=Sum(p+8,bytes);
}

int G54AckEligible(const G54_REPORT_RESULT*r)
{
 return r&&r->Attempted==1&&r->TransportOk&&r->ContractVerified&&r->HeaderPresent&&r->HeaderChecksumValid&&r->EventFlags==0x40&&r->Rx[8]==0x40&&r->Rx[10]==0&&Sum(r->Rx+8,8)&&r->TxDone==34&&r->RxDone==34&&r->StartCode==0&&r->StepCode==0&&r->State==4&&!r->CancelSent&&!r->AbortSent;
}
int G54EventClearFrame(uint8_t*tx,uint32_t capacity)
{
 static const uint8_t clear[6]={0xf0,0,1,2,0x74,0};uint32_t i;
 if(!tx||capacity<6)return 0;for(i=0;i<6;i++)tx[i]=clear[i];return 1;
}
void G54AnalyzeHeader(G54_REPORT_RESULT*r)
{
 const uint8_t*p=r->Rx+8;if(!r->TransportOk)return;
 r->EventFlags=p[0];r->PointCount=p[2]&15;r->HeaderPresent=p[0]!=0;
 if(r->HeaderPresent)r->HeaderChecksumValid=Sum(p,8);
}
