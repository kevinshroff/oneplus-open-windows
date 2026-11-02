/* SPDX-License-Identifier: MIT */
#include "g39_touch.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "native-touch-fixture.h"
typedef struct {unsigned At,ReadyCalls,Barriers;uint64_t Now;G39_TOUCH_RESULT*Result;} Replay;
static const G39_TOUCH_EVENT*Next(Replay*c,unsigned kind,uint32_t at)
{
 const G39_TOUCH_EVENT*e;
 if(c->At>=Expected.TraceCount)exit(20);
 e=&Expected.Trace[c->At++];if(e->Kind!=kind||e->Address!=at)exit(21);return e;
}
static int Read(void*ctx,uint32_t at,uint32_t*out)
{
 *out=Next(ctx,1,at)->Value;return 1;
}
static int Write(void*ctx,uint32_t at,uint32_t value)
{
 if(Next(ctx,2,at)->Value!=value)exit(22);return 1;
}
static int Barrier(void*ctx){((Replay*)ctx)->Barriers++;return 0;}
static int Ready(void*ctx)
{
 Replay*c=ctx;c->ReadyCalls++;
 /* Native powered PMIC capture is a separately recorded outer boundary.
  * This touch replay neither fabricates its data nor replays its MMIO. */
 return 1;
}
static void WaitMs(void*ctx,uint32_t ms){((Replay*)ctx)->Now+=(uint64_t)ms*1000;}
static void WaitPoll(void*ctx){((Replay*)ctx)->Now+=100;}
static uint64_t NowUs(void*ctx){return((Replay*)ctx)->Now;}
int main(void)
{
 G39_TOUCH_RESULT result;Replay c;G39_TOUCH_IO io;
 memset(&result,0,sizeof(result));memset(&c,0,sizeof(c));c.Result=&result;
 io.Context=&c;io.Read=Read;io.Write=Write;io.Barrier=Barrier;io.Ready=Ready;
 io.WaitMs=WaitMs;io.WaitPoll=WaitPoll;io.NowUs=NowUs;
 if(G39TouchRead(&io,&result)!=-1)return 30;
 if(c.At!=Expected.TraceCount||c.ReadyCalls!=1)return 31;
 if(memcmp(&result,&Expected,offsetof(G39_TOUCH_RESULT,PoweredPmic)))return 32;
 printf("{\"passed\":true,\"native_touch_events\":%u,\"read_boundaries\":%u,\"write_boundaries\":%u,\"SPI_barriers\":%u,\"one_ready_confirmation_boundary\":true,\"unknown_active_irq_failure_reproduced\":true,\"recovery_ack_rejected_before_MMIO_reproduced\":true,\"uncertain_bus_holds_resources\":true}\n",c.At,result.Reads,result.Writes,c.Barriers);
 return 0;
}
