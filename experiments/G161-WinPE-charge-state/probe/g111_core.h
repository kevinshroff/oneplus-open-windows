/* SPDX-License-Identifier: MIT */
#ifndef G111_CORE_H
#define G111_CORE_H
#include <stdint.h>
#define G111_STEPS 17u
#define G111_TARGETS 5u
#define G111_READ_LIMIT 4096u
typedef struct{uint32_t Apid,Map,Owner;}G111_TARGET;
static const G111_TARGET G111Targets[G111_TARGETS]={
 {401,0x1070100,4}, /* SID7 revision; read observer need not own RW channel */
 {667,0x72500,0},   /* Candidate SCHG base2500, application observer aliases */
 {668,0x72600,0},{670,0x72800,0},{671,0x72900,0}
};
typedef struct{uint32_t Target,Offset,Bytes;}G111_QUERY;
static const G111_QUERY G111Queries[G111_STEPS]={
 {0,0,8},{1,0,8},{2,0,8},{3,0,8},{4,0,8},
 {2,6,8},{2,14,2},{2,0x40,8},{2,0x50,8},{2,0x58,8},{2,0x60,1},
 {3,0x10,1},{4,0x0a,2},{4,0x10,1},{4,0x40,8},{4,0x50,8},{2,6,8}
};
static inline uint32_t G111Base(unsigned target){return 0xc440000+G111Targets[target].Apid*0x20;}
static inline int G111ReadAllowed(uint32_t at){
 if(at==0xc400000||at==0xc400004||at==0xc400008)return 1;
 for(unsigned i=0;i<G111_TARGETS;i++){uint32_t b=G111Base(i);if(at==0xc402000+G111Targets[i].Apid*4||at==0xc42d000+G111Targets[i].Apid*4||at==b||at==b+8||at==b+0x18||at==b+0x1c)return 1;}return 0;
}
static inline int G111WriteAllowed(uint32_t at,uint32_t value){
 for(unsigned j=0;j<G111_STEPS;j++){const G111_QUERY*q=G111Queries+j;if(at==G111Base(q->Target)&&value==(0x08000000u|(q->Offset<<4)|(q->Bytes-1)))return 1;}return 0;
}
enum{G111_OK,G111_ARGUMENT,G111_IO_ERROR,G111_ARBITER,G111_ROUTE,G111_PENDING,G111_TIMEOUT,G111_COMPLETION,G111_IDENTITY,G111_BUDGET,G111_CANCELLED,G111_CLOCK,G111_DEADLINE};
enum{G111_ROUTE_OK=1,G111_PREVIOUS_IDLE=2,G111_ATTEMPTED=4,G111_WRITTEN=8,G111_DONE=16,G111_DATA=32};
typedef struct{uint32_t Target,Offset,Bytes,Flags,BeforeCommand,BeforeStatus,Completion,Data0,Data1,Reserved;}G111_TRACE;
typedef struct{uint32_t Size,Code,Stage,Reads,Writes,Commands,Polls,TraceCount,Cancelled,PostRoutesVerified,Reserved[2];uint64_t BeginUs,EndUs;uint8_t Values[G111_STEPS][8];G111_TRACE Trace[G111_STEPS];}G111_RESULT;
typedef struct{void*Context;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);void(*WaitUs)(void*);void(*WaitInterval)(void*);int(*Available)(void*);uint64_t(*NowUs)(void*);}G111_IO;
void G111Observe(const G111_IO*,G111_RESULT*);
#endif
