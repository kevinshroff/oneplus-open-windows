/* SPDX-License-Identifier: MIT */
#ifndef G99_CORE_H
#define G99_CORE_H
#include <stdint.h>
#define G99_MAX_SAMPLES 1024u
#define G99_MAX_COMMANDS (6u+3u*G99_MAX_SAMPLES)
#define G99_MAX_READS 65000u
#define G99_INTERVAL_MS 20u
#define G99_DEADLINE_US 60000000ULL
enum {G99_OK,G99_ARGUMENT,G99_IO_ERROR,G99_ARBITER,G99_ROUTE,G99_PENDING,G99_TIMEOUT,G99_COMPLETION,G99_IDENTITY,G99_BUDGET,G99_CANCELLED,G99_CLOCK,G99_DEADLINE,G99_POST_ROUTE,G99_CONFIG_CHANGED,G99_GATE};
enum {G99_ROUTE_OK=1,G99_PREVIOUS_IDLE=2,G99_COMMAND_ATTEMPTED=4,G99_COMMAND_WRITTEN=8,G99_DONE=16,G99_DATA=32};
typedef struct {uint32_t Apid,Map,Owner;}G99_TARGET;
static const G99_TARGET G99Targets[4]={{0,0x1000100,4},{559,0x800,0},{560,0x1001300,0},{583,0x1018d00,0}};
static inline uint32_t G99Base(unsigned i){return 0xc440000u+G99Targets[i].Apid*0x20u;}
static inline int G99ReadAllowed(uint32_t at){
 if(at==0xc400000||at==0xc400004)return 1;
 for(unsigned i=0;i<4;i++){uint32_t b=G99Base(i);if(at==0xc402000+G99Targets[i].Apid*4||at==0xc42d000+G99Targets[i].Apid*4||at==b||at==b+8||at==b+0x18||at==b+0x1c)return 1;}return 0;
}
static inline int G99WriteAllowed(uint32_t at,uint32_t value){
 for(unsigned i=0;i<4;i++)if(at==G99Base(i))return value==0x08000007u||(i>0&&value==0x08000100u)||(i==3&&value==0x08000407u);
 return 0;
}
typedef struct {uint64_t AtUs;uint8_t Raw[3],Reserved[5];}G99_SAMPLE;
typedef struct {uint32_t Target,Offset,Length,Flags,BeforeCommand,BeforeStatus,Completion,Data0,Data1,Reserved;}G99_TRACE;
typedef struct {
 uint32_t Size,Code,Stage,Reads,Writes,Commands,Polls,TraceCount,SampleCount,IntervalMs,Cancelled,PostRoutesVerified;
 uint64_t BeginUs,EndUs;
 uint8_t Identity[4][8],GpioBefore[8],GpioAfter[8];
 G99_SAMPLE Samples[G99_MAX_SAMPLES];G99_TRACE Trace[G99_MAX_COMMANDS];
}G99_RESULT;
typedef struct {void*Context;int(*Read)(void*,uint32_t,uint32_t*);int(*Write)(void*,uint32_t,uint32_t);void(*WaitUs)(void*);void(*WaitInterval)(void*);int(*Available)(void*);uint64_t(*NowUs)(void*);int(*Acquire)(void*);void(*Release)(void*,int uncertain);}G99_IO;
void G99Sample(const G99_IO*,uint32_t,G99_RESULT*);
#endif
