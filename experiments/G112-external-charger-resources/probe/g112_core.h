/* SPDX-License-Identifier: MIT */
#ifndef G112_CORE_H
#define G112_CORE_H
#include <stdint.h>
#include "g112_resources.h"
#define G112_TRACE 1024u
typedef struct{uint32_t Address,Value;}G112_EVENT;
typedef struct{
 uint32_t Size,Code,Stage,Reads,TraceCount,ReadyMask,PostClockMask,PinStableMask;
 uint64_t BeginUs,EndUs;
 uint32_t Before[2][8],After[2][8],PinsBefore[4][2],PinsAfter[4][2];
 uint32_t Controller[2][G112_OFFSETS],Wrapper[2];
 G112_EVENT Trace[G112_TRACE];
}G112_RESULT;
typedef struct{void*Context;int(*Read)(void*,uint32_t,uint32_t*);int(*Available)(void*);uint64_t(*NowUs)(void*);}G112_IO;
enum{G112_OK,G112_ARGUMENT,G112_IO_ERROR,G112_BUDGET,G112_CANCELLED,G112_TIME_ERROR,G112_CLOCK_CHANGED};
static inline int G112Peripheral(uint32_t at){
 for(unsigned i=0;i<2;i++){
  if(i==0&&at==G112Controllers[i].Wrapper+4)return(int)i;
  for(unsigned j=0;j<G112_OFFSETS;j++)if(G112Offset(i,j)!=G112_SKIPPED&&at==G112Controllers[i].Base+G112Offset(i,j))return(int)i;
 }
 return -1;
}
static inline int G112ReadAllowed(uint32_t at){
 if(at&3)return 0;if(G112Peripheral(at)>=0)return 1;
 for(unsigned i=0;i<2;i++){
  const G112_CONTROLLER*c=G112Controllers+i;
  if(at==c->Root||at==c->Root+4)return 1;
  for(unsigned j=0;j<3;j++)if(at==c->Clocks[j].Vote||at==c->Clocks[j].Cbcr)return 1;
  for(unsigned j=0;j<2;j++){uint32_t base=0xf100000+c->Pins[j]*0x1000;if(at==base||at==base+4)return 1;}
 }
 return 0;
}
static inline int G112ClockUsable(unsigned index,const uint32_t*v){
 if(index>=2)return 0;const G112_CONTROLLER*c=G112Controllers+index;
 for(unsigned j=0;j<3;j++){
  const G112_CLOCK*k=c->Clocks+j;
  if((v[2*j]&k->Mask)!=k->Mask)return 0;
  if((v[2*j+1]&0x80000000u)&&(!k->Hwcg||!(v[2*j+1]&2)))return 0;
 }
 return !(v[6]&1);
}
void G112Probe(const G112_IO*,G112_RESULT*);
#endif
