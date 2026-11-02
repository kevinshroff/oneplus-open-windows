/* SPDX-License-Identifier: MIT */
#include "OpenPilCpuInventory.h"
#define PAR_ADDRESS 0x000ffffffffff000ULL
typedef char P139_width[(sizeof(P139_U64)==8)?1:-1];
unsigned OpenCollectPilCpu(P139_CPU_INVENTORY *r,P139_AT_QUERY at,void *context,P139_U64 el)
{
 if(!r)return 1;
 for(unsigned i=0;i<sizeof(*r);i++)((unsigned char *)r)[i]=0;
 r->El=el;
 if(!at || (el!=1 && el!=2)){r->Refusal=1;return 1;}
 for(P139_U64 p=P139_WINDOW_START;p<P139_WINDOW_END;p+=4096){
  P139_U64 a=at(context,p,0),b=at(context,p,1);
  unsigned rf=(unsigned)(a&1),wf=(unsigned)(b&1),ra=0,wa=0;
  r->Queries+=2;r->Pages++;
  if(rf)r->ReadFaults++;
  else{r->ReadTags[a>>56]++;ra=(a&PAR_ADDRESS)!=p;r->ReadAliases+=ra;}
  if(wf)r->WriteFaults++;
  else{r->WriteTags[b>>56]++;wa=(b&PAR_ADDRESS)!=p;r->WriteAliases+=wa;}
  if((rf||wf) && r->FirstFault==0){r->FirstFault=p;r->FaultReadPar=a;r->FaultWritePar=b;}
  if((ra||wa) && r->FirstAlias==0){r->FirstAlias=p;r->AliasReadPar=a;r->AliasWritePar=b;}
  if(!rf && !wf && (a>>56)!=(b>>56)){
   r->TagDifferences++;
   if(r->FirstTagDifference==0){r->FirstTagDifference=p;r->TagReadPar=a;r->TagWritePar=b;}
  }
 }
 r->Complete=r->Pages==P139_PAGE_COUNT && r->Queries==2*P139_PAGE_COUNT;
 if(!r->Complete)r->Refusal=2;
 return r->Refusal;
}
