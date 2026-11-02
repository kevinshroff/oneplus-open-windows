/* Actual portable core replays frozen native IO. Time/cancellation are models. */
#include "g104_core.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
typedef uint32_t ULONG;typedef uint64_t ULONGLONG;
#define C_ASSERT(x) _Static_assert(x,#x)
#define FIELD_OFFSET(t,f) offsetof(t,f)
#define CTL_CODE(d,f,m,a) (((d)<<16)|((a)<<14)|((f)<<2)|(m))
#define FILE_DEVICE_UNKNOWN 0x22
#define METHOD_BUFFERED 0
#define FILE_READ_ACCESS 1
#define FILE_WRITE_ACCESS 2
#include "g104_protocol.h"
typedef struct{G104_EVENT*Events;size_t Count,Cursor;G104_RESULT*Output;uint64_t Now;}Replay;
static G104_EVENT Next(Replay*c,uint32_t kind,uint32_t address){assert(c->Cursor<c->Count);G104_EVENT e=c->Events[c->Cursor++];assert(e.Kind==kind&&e.Address==address&&e.Command==c->Output->Commands);return e;}
static int Read(void*x,uint32_t at,uint32_t*v){*v=Next(x,1,at).Value;return 1;}
static int Write(void*x,uint32_t at,uint32_t v){assert(Next(x,2,at).Value==v);return 1;}
static int Available(void*x){(void)x;return 1;}
static uint64_t Now(void*x){return++((Replay*)x)->Now;}
static void Delay(void*x,uint32_t us){assert(us==20);((Replay*)x)->Now+=us;}
static void Normalize(G104_RESULT*r){r->BeginUs=r->EndUs=0;r->Before.BeginUs=r->Before.EndUs=0;r->After.BeginUs=r->After.EndUs=0;}
int main(int argc,char**argv){
 assert(argc==2);G104_CAPTURE*c=calloc(1,sizeof(*c));G104_RESULT*r=calloc(1,sizeof(*r));G104_EVENT*e=calloc(32768,sizeof(*e));assert(c&&r&&e);
 FILE*f=fopen(argv[1],"rb");assert(f&&fread(c,sizeof(*c),1,f)==1&&fgetc(f)==EOF&&!fclose(f));assert(c->Status.Magic==G104_MAGIC&&!c->Result.Code&&c->Result.QueryMask==0xfffff);
 size_t n=0;
 for(unsigned i=0;i<c->Result.Before.TraceCount;i++){G102_EVENT t=c->Result.Before.Trace[i];e[n++]=(G104_EVENT){1,t.Address,t.Value,0};}
 for(unsigned i=0;i<c->Result.TraceCount;i++)e[n++]=c->Result.Trace[i];
 for(unsigned i=0;i<c->Result.After.TraceCount;i++){G102_EVENT t=c->Result.After.Trace[i];e[n++]=(G104_EVENT){1,t.Address,t.Value,46};}
 Replay replay={e,n,0,r,0};G104_IO io={&replay,Read,Write,Available,Now,Delay};G104Identify(&io,r);assert(replay.Cursor==n&&!r->Code);
 Normalize(r);Normalize(&c->Result);assert(!memcmp(r,&c->Result,sizeof(*r)));
 printf("{\"passed\":true,\"actual_core_replayed\":true,\"IO_events\":%zu,\"all_result_bytes_match_except_six_time_fields\":true,\"modeled_time_and_no_cancellation\":true,\"native_operations\":0}\n",n);free(e);free(r);free(c);
}
