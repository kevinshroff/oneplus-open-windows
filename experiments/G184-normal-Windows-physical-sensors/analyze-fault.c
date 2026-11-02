#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
int main(int argc,char**argv){
 if(argc!=2)return 2;FILE*f=fopen(argv[1],"rb");OP184_SNAPSHOT*s=calloc(1,sizeof(*s));if(!f||!s)return 2;
 if(fread(s,1,sizeof(*s),f)!=sizeof(*s)||fgetc(f)!=EOF)return 3;fclose(f);
 if(s->Status.Magic!=UINT64_C(0x31534e333831474f)||s->Result.Size!=sizeof(s->Result)||s->Result.Gauge.TraceCount>G104_TRACE)return 4;
 const S183_RESULT*r=&s->Result;const G104_RESULT*g=&r->Gauge;
 printf("{\"sequence\":%"PRIu64",\"valid_count\":%"PRIu64",\"completed\":%"PRIu64",\"S183_code\":%u,\"G104_code\":%u,\"stage\":%u,\"native_reads\":%u,\"native_writes\":%u,\"gauge_guard\":%u,\"commands\":%u,\"completed_commands\":%u,\"policy_commands\":%u,\"policy_completed\":%u,\"policy_fault\":%u,\"cancels\":%u,\"aborts\":%u,\"uncertain\":%u,\"trace_count\":%u,\"trace_dropped\":%u,\"elapsed_us\":%"PRIu64",\"last_events\":[",r->Sequence,s->Status.ValidCount,s->Status.Completed,r->Code,g->Code,g->Stage,r->GaugeNativeReads,r->GaugeNativeWrites,r->GaugeGuard,g->Commands,g->Completed,r->PolicyCommands,r->PolicyCompleted,r->PolicyFault,g->Cancels,g->Aborts,r->Uncertain,g->TraceCount,g->TraceDropped,g->EndUs-g->BeginUs);
 unsigned first=g->TraceCount>32?g->TraceCount-32:0;
 for(unsigned i=first;i<g->TraceCount;i++){const G104_EVENT*e=g->Trace+i;printf("%s{\"index\":%u,\"kind\":%u,\"address\":\"0x%x\",\"value\":\"0x%x\",\"command\":%u}",i==first?"":",",i,e->Kind,e->Address,e->Value,e->Command);}
 printf("]}\n");free(s);return 0;
}
