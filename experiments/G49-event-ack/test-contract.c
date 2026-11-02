/* SPDX-License-Identifier: MIT */
#include "g49_contract.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "contract-fixture.h"
static void Seal(uint8_t*p,unsigned n){unsigned i,sum=0;for(i=0;i<n-2;i++)sum+=p[i];p[n-2]=(uint8_t)sum;p[n-1]=(uint8_t)(sum>>8);}
static unsigned Cases;
int checksum_cmp(const uint8_t*,int,int);
static void Check(G49_REPORT_RESULT*r){G49AnalyzeReport(r);Cases++;
 if(r->TransportOk){const uint8_t*p=r->Rx+8;unsigned n=(r->PointType==1||r->PointType==3)?18:r->PointCount*8+2;int header=p[0]!=0&&!checksum_cmp(p,8,0),complete=header&&(p[0]&0x80)&&r->PointCount<=10&&n<=18;assert(r->HeaderChecksumValid==(uint32_t)header&&r->BodyComplete==(uint32_t)complete&&r->BodyChecksumValid==(uint32_t)(complete&&!checksum_cmp(p+8,(int)n,0)));}if(r->BodyChecksumValid)assert(r->HeaderChecksumValid&&r->HeaderPresent&&r->BodyComplete&&(r->EventFlags&0x80)&&r->PointCount<=10);}
static void Report(G49_REPORT_RESULT*r,unsigned flags,unsigned n,unsigned type){uint8_t*p;memset(r,0,sizeof(*r));r->TransportOk=r->ContractVerified=1;p=r->Rx+8;p[0]=(uint8_t)flags;p[2]=(uint8_t)n;p[8]=(uint8_t)type;Seal(p,8);if((type==1||type==3)||n==2)Seal(p+8,18);else if(n<=1)Seal(p+8,n*8+2);}
int main(void){uint8_t b[242];unsigned i,bit,n,type;G49_REPORT_RESULT r;
 assert(G49InfoContract(Actual,242));Cases++;
 for(i=0;i<242;i++)for(bit=0;bit<8;bit++){memcpy(b,Actual,242);b[i]^=(uint8_t)(1u<<bit);assert(!G49InfoContract(b,242));Cases++;}
 for(n=0;n<=256;n++)if(n!=242){assert(!G49InfoContract(Actual,n));Cases++;}assert(!G49InfoContract(NULL,242));Cases++;
 {const unsigned at[]={2,3,13,14,32,41,52,53,54,99,103,105};for(i=0;i<sizeof(at)/sizeof(at[0]);i++){memcpy(b,Actual,242);if(at[i]>=32&&at[i]<=54)b[at[i]]=9;else b[at[i]]^=1;Seal(b,242);assert(!G49InfoContract(b,242));Cases++;}}
 for(type=0;type<4;type++)for(n=0;n<=15;n++){Report(&r,0x80,n,type);Check(&r);assert(r.HeaderPresent&&r.HeaderChecksumValid);if(n>10)assert(!r.BodyComplete&&!r.BodyChecksumValid);else if(type==1||type==3||n<=2)assert(r.BodyComplete&&r.BodyChecksumValid);else assert(!r.BodyComplete&&!r.BodyChecksumValid);}
 Report(&r,0,0,0);Check(&r);assert(!r.HeaderPresent&&!r.HeaderChecksumValid&&!r.BodyChecksumValid);
 for(i=0;i<8;i++)for(bit=0;bit<8;bit++){Report(&r,0x80,1,0);r.Rx[8+i]^=(uint8_t)(1u<<bit);Check(&r);assert(!r.HeaderChecksumValid&&!r.BodyChecksumValid);}
 for(i=0;i<10;i++)for(bit=0;bit<8;bit++){Report(&r,0x80,1,0);r.Rx[16+i]^=(uint8_t)(1u<<bit);Check(&r);assert(r.HeaderChecksumValid&&r.BodyComplete&&!r.BodyChecksumValid);}
 for(i=0;i<18;i++)for(bit=0;bit<8;bit++){Report(&r,0x80,2,0);r.Rx[16+i]^=(uint8_t)(1u<<bit);Check(&r);assert(r.HeaderChecksumValid&&r.BodyComplete&&!r.BodyChecksumValid);}
 for(i=0;i<3;i++){Report(&r,(uint8_t[]){0x40,0x20,4}[i],0,0);Check(&r);assert(r.HeaderChecksumValid&&!r.BodyComplete&&!r.BodyChecksumValid);}
 memset(&r,0,sizeof(r));Check(&r);assert(!r.HeaderPresent&&!r.BodyChecksumValid);
 {uint8_t tx[36];for(i=0;i<6;i++){memset(tx,0xa5,sizeof(tx));assert(!G49EventClearFrame(tx,i)&&tx[0]==0xa5);Cases++;}assert(!G49EventClearFrame(NULL,36));Cases++;
  memset(tx,0xa5,sizeof(tx));assert(G49EventClearFrame(tx,36)&&!memcmp(tx,(uint8_t[]){0xf0,0,1,2,0x74,0},6)&&tx[6]==0xa5);Cases++;
 }
 Report(&r,0x40,0,0);r.Attempted=1;r.TxDone=r.RxDone=34;r.State=4;G49AnalyzeReport(&r);assert(G49AckEligible(&r));Cases++;
 for(i=0;i<8;i++)for(bit=0;bit<8;bit++){r.Rx[8+i]^=(uint8_t)(1u<<bit);assert(!G49AckEligible(&r));r.Rx[8+i]^=(uint8_t)(1u<<bit);Cases++;}
 assert(!G49AckEligible(NULL));Cases++;
 {uint32_t*fields[]={&r.Attempted,&r.TransportOk,&r.ContractVerified,&r.HeaderPresent,&r.HeaderChecksumValid,&r.EventFlags,&r.TxDone,&r.RxDone,&r.State};for(i=0;i<sizeof(fields)/sizeof(fields[0]);i++){uint32_t old=*fields[i];*fields[i]=0;assert(!G49AckEligible(&r));*fields[i]=old;Cases++;}}
 r.CancelSent=1;assert(!G49AckEligible(&r));r.CancelSent=0;r.AbortSent=1;assert(!G49AckEligible(&r));Cases+=2;
 for(n=0;n<=255;n++){memset(&r,0,sizeof(r));r.TransportOk=1;r.Rx[8]=(uint8_t)n;Seal(r.Rx+8,8);G49AnalyzeHeader(&r);assert(r.EventFlags==n&&r.HeaderPresent==(n!=0)&&r.HeaderChecksumValid==(n!=0)&&!r.BodyComplete&&!r.BodyChecksumValid);Cases++;}
 memset(&r,0,sizeof(r));r.TransportOk=1;r.Rx[8]=0x80;Seal(r.Rx+8,8);r.Rx[14]^=1;G49AnalyzeHeader(&r);assert(r.HeaderPresent&&!r.HeaderChecksumValid&&!r.BodyComplete&&!r.BodyChecksumValid);Cases++;
 printf("{\"passed\":true,\"cases\":%u,\"real_checksums_and_bounded_IC_contract\":true,\"idle_corrupt_and_incomplete_reports_not_valid_touches\":true,\"no_MMIO_or_native_commands\":true}\n",Cases);return 0;
}
