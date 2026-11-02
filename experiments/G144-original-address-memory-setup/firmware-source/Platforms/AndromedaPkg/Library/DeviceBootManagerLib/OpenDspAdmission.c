/* SPDX-License-Identifier: MIT */
#include "OpenDspAdmission.h"
#define PAGE_BYTES 4096ULL
#define MAX_PAGES 18689ULL /* 73 MiB staging plus the SCM slot page. */
#define PAR_ADDRESS 0x000ffffffffff000ULL
unsigned OpenCheckCpuRange(OPEN_CPU_ADMISSION *r,OPEN_AT_QUERY at,void *context,
                          OP_U64 base,OP_U64 bytes)
{
 if(!r)return OPEN_CPU_ARGUMENT;
 if(r->Refusal)return r->Refusal;
 if(!at||!base||!bytes||(base&4095)||(bytes&4095)||
    bytes>73ULL*1024*1024||base>~0ULL-bytes){r->Refusal=OPEN_CPU_ARGUMENT;return r->Refusal;}
 if(r->Pages>MAX_PAGES||bytes/PAGE_BYTES>MAX_PAGES-r->Pages){r->Refusal=OPEN_CPU_BUDGET;return r->Refusal;}
 for(OP_U64 p=base;p<base+bytes;p+=PAGE_BYTES){
  unsigned why=0;r->ReadPar=at(context,p,0);r->Queries++;r->WritePar=0;
  if(r->ReadPar&1)why=OPEN_CPU_READ_FAULT;
  else{
   r->WritePar=at(context,p,1);r->Queries++;
   if(r->WritePar&1)why=OPEN_CPU_WRITE_FAULT;
   else if((r->ReadPar&PAR_ADDRESS)!=p||(r->WritePar&PAR_ADDRESS)!=p)why=OPEN_CPU_ALIAS;
   else if((r->ReadPar>>56)!=0xff||(r->WritePar>>56)!=0xff)why=OPEN_CPU_NOT_WB;
  }
  if(why){r->FirstBad=p;r->Refusal=why;return why;}
  r->Pages++;
 }
 return 0;
}

/* G144: translation qualification for a memory-setup-only request.
 * No payload access, remapping, cache operation or DMA ownership claim. */
unsigned OpenCheckPilCpuRange(OPEN_CPU_ADMISSION *r,OPEN_AT_QUERY at,void *context)
{
 const OP_U64 base=0x9e980000ULL,bytes=0x4900000ULL;
 if(!r)return OPEN_CPU_ARGUMENT;
 if(r->Refusal)return r->Refusal;
 if(!at||!base||!bytes||(base&4095)||(bytes&4095)||
    bytes>73ULL*1024*1024||base>~0ULL-bytes){r->Refusal=OPEN_CPU_ARGUMENT;return r->Refusal;}
 if(r->Pages>MAX_PAGES||bytes/PAGE_BYTES>MAX_PAGES-r->Pages){r->Refusal=OPEN_CPU_BUDGET;return r->Refusal;}
 for(OP_U64 p=base;p<base+bytes;p+=PAGE_BYTES){
  unsigned why=0;r->ReadPar=at(context,p,0);r->Queries++;r->WritePar=0;
  if(r->ReadPar&1)why=OPEN_CPU_READ_FAULT;
  else{
   r->WritePar=at(context,p,1);r->Queries++;
   if(r->WritePar&1)why=OPEN_CPU_WRITE_FAULT;
   else if((r->ReadPar&PAR_ADDRESS)!=p||(r->WritePar&PAR_ADDRESS)!=p)why=OPEN_CPU_ALIAS;
   else if((r->ReadPar>>56)!=0x44||(r->WritePar>>56)!=0x44)why=OPEN_CPU_NOT_PIL_NC;
  }
  if(why){r->FirstBad=p;r->Refusal=why;return why;}
  r->Pages++;
 }
 return 0;
}
