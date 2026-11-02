/* SPDX-License-Identifier: MIT */
#include "g36_observer.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "native-fixture.h"
typedef struct {unsigned At,Waits;} Replay;
static const G36_OBS_EVENT *Next(Replay *r,unsigned kind,uint32_t at)
{
 const G36_OBS_EVENT *e;
 if(r->At>=sizeof(Tape)/sizeof(Tape[0]))exit(30);
 e=&Tape[r->At++];if(e->Kind!=kind||e->Address!=at)exit(31);return e;
}
static int Read(void *ctx,uint32_t at,uint32_t *out){*out=Next(ctx,1,at)->Value;return 1;}
static int Write(void *ctx,uint32_t at,uint32_t value){if(Next(ctx,2,at)->Value!=value)exit(32);return 1;}
static void Wait(void *ctx){((Replay*)ctx)->Waits++;}
int main(void)
{
 G36_OBS_RESULT r;Replay replay={0,0};G36_OBS_IO io={&replay,Read,Write,Wait};uint32_t counters[6];
 memset(&r,0,sizeof(r));G36Observe(&io,&r);
 counters[0]=r.Code;counters[1]=r.Stage;counters[2]=r.Reads;counters[3]=r.Writes;counters[4]=r.Polls;counters[5]=r.Commands;
 if(memcmp(counters,Counters,sizeof(counters))||memcmp(r.Completion,Completion,sizeof(Completion)))return 33;
 if(memcmp(r.Revision,Data,8)||memcmp(r.Anchor,Data+8,8)||memcmp(r.Identity,Data+16,8)||r.Status!=Data[24]||memcmp(r.Configuration,Data+25,8))return 34;
 if(replay.At!=sizeof(Tape)/sizeof(Tape[0])||r.TraceCount!=replay.At||replay.Waits!=r.Polls-5)return 35;
 if(memcmp(r.Trace,Tape,sizeof(Tape)))return 36;
 printf("{\"passed\":true,\"events\":%u,\"reads\":%u,\"writes\":%u,\"polls\":%u,\"waits\":%u}\n",r.TraceCount,r.Reads,r.Writes,r.Polls,replay.Waits);return 0;
}
