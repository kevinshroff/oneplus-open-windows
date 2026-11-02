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
enum {G99_ROUTE_OK=1,G99_PREVIOUS_IDLE=2,G99_COMMAND_ATTEMPTED=4,G99_COMMAND_WRITTEN=8,G99_DONE=16,G99_DATA=32,G99_NOT_ISSUED=64,G99_NATIVE_STATUS_VALID=128,G99_NATIVE_COMMAND_VALID=256};
/* Write callbacks return2 only with valid native status0/nonzero-CMD proof,
 * strictly before any MMIO write. Other refusals remain uncertain failures. */
enum {G99_WRITE_FAILED=0,G99_WRITE_ISSUED=1,G99_WRITE_BUSY_UNISSUED=2};
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
/* Internal continuous reader. The caller owns scratch storage and lifecycle;
 * no one-shot capture state/attempts or user request is involved. */
typedef struct {uint32_t Started,Fault;uint64_t LastUs;} G293_KEY_STREAM;
int G293KeyStreamStart(const G99_IO*,G293_KEY_STREAM*,G99_RESULT*scratch);
enum { G293_STREAM_STOP=0, G293_STREAM_SAMPLE=1, G293_STREAM_DROPPED=2, G293_STREAM_BUSY=3 };
/* One shared bounded skip streak; a fresh validated sample alone resets it. */
static inline int G293StreamBudget(unsigned acquired,unsigned*streak)
{
 if(!streak)return 0;
 if(acquired==G293_STREAM_SAMPLE){*streak=0;return 1;}
 if(acquired!=G293_STREAM_DROPPED&&acquired!=G293_STREAM_BUSY)return 0;
 if(*streak>=3)return 0;(*streak)++;return 1;
}
int G293KeyStreamRead(const G99_IO*,G293_KEY_STREAM*,G99_RESULT*scratch,G99_SAMPLE*);
#endif
