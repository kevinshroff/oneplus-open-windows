/* SPDX-License-Identifier: MIT */
#ifndef G102_CORE_H
#define G102_CORE_H
#include <stdint.h>
#include "g102_resources.h"
#define G102_TRACE 1024u
typedef struct{uint32_t Address,Value;}G102_EVENT;
typedef struct{
 uint32_t Size,Code,Stage,Reads,TraceCount,ReadyMask,PostClockMask,PinStableMask;
 uint64_t BeginUs,EndUs;
 uint32_t Before[2][8],After[2][8],PinsBefore[4][2],PinsAfter[4][2];
 uint32_t Controller[2][G102_OFFSETS],Wrapper[2];
 G102_EVENT Trace[G102_TRACE];
}G102_RESULT;
typedef struct{void*Context;int(*Read)(void*,uint32_t,uint32_t*);int(*Available)(void*);uint64_t(*NowUs)(void*);}G102_IO;
enum{G102_OK,G102_ARGUMENT,G102_IO_ERROR,G102_BUDGET,G102_CANCELLED,G102_TIME_ERROR,G102_CLOCK_CHANGED};
static inline int G102Peripheral(uint32_t at){
 for(unsigned i=0;i<1;i++){
  if(i==0&&at==G102Controllers[i].Wrapper+4)return(int)i;
  for(unsigned j=0;j<G102_OFFSETS;j++)if(G102Offset(i,j)!=G102_SKIPPED&&at==G102Controllers[i].Base+G102Offset(i,j))return(int)i;
 }
 return -1;
}
static inline int G102ReadAllowed(uint32_t at){
 if(at&3)return 0;if(G102Peripheral(at)>=0)return 1;
 for(unsigned i=0;i<1;i++){
  const G102_CONTROLLER*c=G102Controllers+i;
  if(at==c->Root||at==c->Root+4)return 1;
  for(unsigned j=0;j<3;j++)if(at==c->Clocks[j].Vote||at==c->Clocks[j].Cbcr)return 1;
  for(unsigned j=0;j<2;j++){uint32_t base=0xf100000+c->Pins[j]*0x1000;if(at==base||at==base+4)return 1;}
 }
 return 0;
}
static inline int G102ClockUsable(unsigned index,const uint32_t*v){
 if(index>=1)return 0;const G102_CONTROLLER*c=G102Controllers+index;
 for(unsigned j=0;j<3;j++){
  const G102_CLOCK*k=c->Clocks+j;
  if((v[2*j]&k->Mask)!=k->Mask)return 0;
  if((v[2*j+1]&0x80000000u)&&(!k->Hwcg||!(v[2*j+1]&2)))return 0;
 }
 return !(v[6]&1);
}
void G102Probe(const G102_IO*,G102_RESULT*);
#endif
