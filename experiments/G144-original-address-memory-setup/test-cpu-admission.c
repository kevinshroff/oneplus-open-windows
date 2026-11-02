/* Actual C admission functions, integer-only AT responses; no target access. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "OpenDspAdmission.h"
#define PIL 0x9e980000ULL
#define END 0xa3280000ULL
#define SLOT 0x40000000ULL
typedef struct { OP_U64 Bad,Calls; unsigned Kind; } MODEL;
static unsigned Cases;
static OP_U64 Query(void *context,OP_U64 address,unsigned write) {
 MODEL *m=context; assert(write<=1 && ((address>=PIL && address<END) || address==SLOT));
 m->Calls++; OP_U64 tag=address==SLOT?0xff:0x44;
 if(address==m->Bad) {
  if(m->Kind==1 && !write)return 1;
  if(m->Kind==2 && write)return 1;
  if((m->Kind==3&&!write)||(m->Kind==4&&write))address+=4096;
  if(m->Kind==5&&!write)tag=0xff;
  if(m->Kind==6&&write)tag=0;
  if(m->Kind==7)tag=0xff;
  if(m->Kind==8)tag=0x44;
 }
 return(tag<<56)|address;
}
static void Run(OP_U64 page,unsigned kind,unsigned expected) {
 OPEN_CPU_ADMISSION r={0}; MODEL m={PIL+page*4096,0,kind};
 assert(!OpenCheckCpuRange(&r,Query,&m,SLOT,4096));
 assert(r.Pages==1 && r.Queries==2 && m.Calls==2);
 unsigned result=OpenCheckPilCpuRange(&r,Query,&m);
 assert(result==expected && r.Refusal==expected && r.Queries==m.Calls);
 if(expected) {
  assert(r.FirstBad==PIL+page*4096 && r.Pages==page+1);
  assert(m.Calls==2+page*2+(kind==1?1:2));
  OP_U64 before=m.Calls;
  assert(OpenCheckPilCpuRange(&r,Query,&m)==expected && m.Calls==before);
 } else assert(r.Pages==18689 && r.Queries==37378 && !r.FirstBad);
 Cases++;
}
int main(void) {
 Run(0,0,0);
 unsigned refusal[]={0,OPEN_CPU_READ_FAULT,OPEN_CPU_WRITE_FAULT,OPEN_CPU_ALIAS,OPEN_CPU_ALIAS,
                     OPEN_CPU_NOT_PIL_NC,OPEN_CPU_NOT_PIL_NC,OPEN_CPU_NOT_PIL_NC};
 OP_U64 pages[]={0,9344,18687};
 for(unsigned k=1;k<=7;k++)for(unsigned p=0;p<3;p++)Run(pages[p],k,refusal[k]);
 OPEN_CPU_ADMISSION r={0}; MODEL m={SLOT,0,8};
 assert(OpenCheckCpuRange(&r,Query,&m,SLOT,4096)==OPEN_CPU_NOT_WB && m.Calls==2);Cases++;
 memset(&r,0,sizeof r);m=(MODEL){0,0,0};
 assert(OpenCheckCpuRange(&r,Query,&m,PIL,4096)==OPEN_CPU_NOT_WB && m.Calls==2);Cases++;
 memset(&r,0,sizeof r);m.Calls=0;
 assert(OpenCheckPilCpuRange(NULL,Query,&m)==OPEN_CPU_ARGUMENT && !m.Calls);Cases++;
 assert(OpenCheckPilCpuRange(&r,NULL,&m)==OPEN_CPU_ARGUMENT && !m.Calls);Cases++;
 memset(&r,0,sizeof r);r.Pages=2;
 assert(OpenCheckPilCpuRange(&r,Query,&m)==OPEN_CPU_BUDGET && !m.Calls);Cases++;
 memset(&r,0,sizeof r);r.Pages=18690;
 assert(OpenCheckPilCpuRange(&r,Query,&m)==OPEN_CPU_BUDGET && !m.Calls);Cases++;
 memset(&r,0,sizeof r);r.Refusal=OPEN_CPU_ALIAS;
 assert(OpenCheckPilCpuRange(&r,Query,&m)==OPEN_CPU_ALIAS && !m.Calls);Cases++;
 printf("{\"passed\":true,\"cases\":%u,\"actual_C\":true,\"native_operations\":0,\"fixed_PIL_pages\":18688,\"separate_WB_slot\":true}\n",Cases);
}
