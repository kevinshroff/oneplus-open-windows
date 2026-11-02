/* SPDX-License-Identifier: MIT */
#include "OpenDspAdmission.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef struct{OP_U64 calls,bad;unsigned failure;} FIXTURE;
static OP_U64 Query(void *ctx,OP_U64 p,unsigned write){
 FIXTURE *f=ctx;f->calls++;OP_U64 par=(0xffULL<<56)|p;
 if(p!=f->bad)return par;
 if(f->failure==1&&!write)return 1;
 if(f->failure==2&&write)return 1;
 if(f->failure==3)return par+4096;
 if(f->failure==4)return par&~(0xffULL<<56);
 return par;
}
int main(void){
 OPEN_CPU_ADMISSION r;FIXTURE f;unsigned tests=0;
 memset(&r,0,sizeof r);memset(&f,0,sizeof f);
 assert(!OpenCheckCpuRange(&r,Query,&f,0xc50c5000,4096));
 assert(!OpenCheckCpuRange(&r,Query,&f,0xa9f80000,0x4900000));
 assert(r.Pages==18689&&r.Queries==37378&&f.calls==37378&&!r.Refusal);tests++;
 for(unsigned k=0;k<7;k++){
  memset(&r,0,sizeof r);memset(&f,0,sizeof f);
  OP_U64 base=0xa9f80000,bytes=4096;OPEN_AT_QUERY q=Query;
  if(k==0)base=0;if(k==1)base++;if(k==2)bytes=0;if(k==3)bytes++;
  if(k==4)base=~0ULL-4095;if(k==5)bytes=0x4901000;if(k==6)q=0;
  assert(OpenCheckCpuRange(&r,q,&f,base,bytes)==OPEN_CPU_ARGUMENT&&!f.calls);tests++;
 }
 for(unsigned failure=1;failure<=4;failure++)for(unsigned last=0;last<2;last++){
  memset(&r,0,sizeof r);memset(&f,0,sizeof f);f.failure=failure;f.bad=0xa9f80000+4096*last;
  unsigned expected[]={0,OPEN_CPU_READ_FAULT,OPEN_CPU_WRITE_FAULT,OPEN_CPU_ALIAS,OPEN_CPU_NOT_WB};
  assert(OpenCheckCpuRange(&r,Query,&f,0xa9f80000,8192)==expected[failure]);
  assert(r.FirstBad==f.bad&&r.Pages==last&&r.Queries==last*2+(failure==1?1:2));
  OP_U64 calls=f.calls;assert(OpenCheckCpuRange(&r,Query,&f,0xa9f80000,4096)==expected[failure]&&f.calls==calls);tests++;
 }
 memset(&r,0,sizeof r);memset(&f,0,sizeof f);r.Pages=18689;
 assert(OpenCheckCpuRange(&r,Query,&f,0xc50c5000,4096)==OPEN_CPU_BUDGET&&!f.calls);tests++;
 assert(OpenCheckCpuRange(0,Query,&f,4096,4096)==OPEN_CPU_ARGUMENT);tests++;
 printf("{\"passed\":true,\"cases\":%u,\"ASan_UBSan\":true,\"native_operations\":0,\"scope\":\"Actual admission C with explicit translation-result fixtures; no CPU AT or native data access\"}\n",tests);
}
