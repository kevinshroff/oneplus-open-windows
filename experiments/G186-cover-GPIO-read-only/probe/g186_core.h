/* SPDX-License-Identifier: MIT */
#ifndef G186_CORE_H
#define G186_CORE_H
#include <stdint.h>
#define G186_STEPS 9u
#define G186_TARGETS 3u
#define G186_READ_LIMIT 4096u
typedef struct{uint32_t Apid,Map,Owner;}G186_TARGET;
static const G186_TARGET G186Targets[G186_TARGETS]={{619,0x1058f00,0},{697,0x78e00,0},{698,0x78f00,0}};
typedef struct{uint32_t Target,Offset,Bytes;}G186_QUERY;
static const G186_QUERY G186Queries[G186_STEPS]={{0,0,8},{1,0,8},{2,0,8},{0,0x40,8},{1,0x40,8},{2,0x40,8},{0,0x10,1},{1,0x10,1},{2,0x10,1}};
static inline uint32_t G186Base(unsigned target){return 0xc440000+G186Targets[target].Apid*0x20;}
static inline int G186ReadAllowed(uint32_t at){
 if(at==0xc400000||at==0xc400004||at==0xc400008)return 1;
 for(unsigned i=0;i<G186_TARGETS;i++){uint32_t b=G186Base(i);if(at==0xc402000+G186Targets[i].Apid*4||at==0xc42d000+G186Targets[i].Apid*4||at==b||at==b+8||at==b+0x18||at==b+0x1c)return 1;}return 0;
}
static inline int G186WriteAllowed(uint32_t at,uint32_t value){
 for(unsigned j=0;j<G186_STEPS;j++){const G186_QUERY*q=G186Queries+j;if(at==G186Base(q->Target)&&value==(0x08000000u|(q->Offset<<4)|(q->Bytes-1)))return 1;}return 0;
}
enum{G186_OK,G186_ARGUMENT,G186_IO_ERROR,G186_ARBITER,G186_ROUTE,G186_PENDING,G186_TIMEOUT,G186_COMPLETION,G186_IDENTITY,G186_BUDGET,G186_CANCELLED,G186_CLOCK,G186_DEADLINE};
enum{G186_ROUTE_OK=1,G186_PREVIOUS_IDLE=2,G186_ATTEMPTED=4,G186_WRITTEN=8,G186_DONE=16,G186_DATA=32};
typedef struct{uint32_t Target,Offset,Bytes,Flags,BeforeCommand,BeforeStatus,Completion,Data0,Data1,Reserved;}G186_TRACE;
typedef struct{uint32_t Size,Code,Stage,Reads,Writes,Commands,Polls,TraceCount,Cancelled,PostRoutesVerified,Reserved[2];uint64_t BeginUs,EndUs;uint8_t Values[G186_STEPS][8];G186_TRACE Trace[G186_STEPS];}G186_RESULT;
typedef struct{void*Context;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);void(*WaitUs)(void*);void(*WaitInterval)(void*);int(*Available)(void*);uint64_t(*NowUs)(void*);}G186_IO;
void G186Observe(const G186_IO*,G186_RESULT*);
#endif
