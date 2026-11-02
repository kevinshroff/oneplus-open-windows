/* SPDX-License-Identifier: MIT */
#include "g37_spi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "spi-native-fixture.h"
typedef struct {unsigned OuterAt,EngineAt,Waits;G37_SPI_RESULT*Result;} Replay;
static const G37_SPI_EVENT *OuterNext(Replay*r,unsigned kind,uint32_t at)
{
 const G37_SPI_EVENT*e;if(r->OuterAt>=Expected.TraceCount)exit(30);
 e=&Expected.Trace[r->OuterAt++];if(e->Kind!=kind||e->Address!=at)exit(31);return e;
}
static uint32_t Next(Replay*r,unsigned kind,uint32_t at)
{
 if(r->Result->Stage==5&&r->Result->Engine.Stage!=0){
  const G37_ENGINE_EVENT*e;
  if(r->EngineAt>=Expected.Engine.TraceCount)exit(40);e=&Expected.Engine.Trace[r->EngineAt++];
  if(e->Kind!=kind||e->Address!=at)exit(41);return e->Value;
 }
 return OuterNext(r,kind,at)->Value;
}
static int Read(void*ctx,uint32_t at,uint32_t*out){*out=Next(ctx,1,at);return 1;}
static int Write(void*ctx,uint32_t at,uint32_t value){if(Next(ctx,2,at)!=value)exit(32);return 1;}
static void Wait(void*ctx){((Replay*)ctx)->Waits++;}
int main(void)
{
 G37_SPI_RESULT r;Replay replay={0,0,0,&r};G37_SPI_IO io={&replay,Read,Write,Wait};
 memset(&r,0,sizeof(r));G37PrepareSpi(&io,&r);
 if(memcmp(&r,&Expected,sizeof(r))||replay.OuterAt!=Expected.TraceCount||replay.EngineAt!=Expected.Engine.TraceCount)return 33;
 printf("{\"passed\":true,\"events\":%u,\"reads\":%u,\"writes\":%u,\"waits\":%u,\"both_actual_C_cores\":true}\n",r.TraceCount+r.Engine.TraceCount,r.Reads+r.Engine.Reads,r.Writes+r.Engine.Writes,replay.Waits);return 0;
}
