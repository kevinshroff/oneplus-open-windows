/* SPDX-License-Identifier: MIT */
#include "g36_spi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "spi-native-fixture.h"
typedef struct {unsigned At,Waits;} Replay;
static const G36_SPI_EVENT *Next(Replay*r,unsigned kind,uint32_t at)
{
 const G36_SPI_EVENT*e;if(r->At>=Expected.TraceCount)exit(30);e=&Expected.Trace[r->At++];if(e->Kind!=kind||e->Address!=at)exit(31);return e;
}
static int Read(void*ctx,uint32_t at,uint32_t*out){*out=Next(ctx,1,at)->Value;return 1;}
static int Write(void*ctx,uint32_t at,uint32_t value){if(Next(ctx,2,at)->Value!=value)exit(32);return 1;}
static void Wait(void*ctx){((Replay*)ctx)->Waits++;}
int main(void)
{
 G36_SPI_RESULT r;Replay replay={0,0};G36_SPI_IO io={&replay,Read,Write,Wait};memset(&r,0,sizeof(r));G36PrepareSpi(&io,&r);
 if(memcmp(&r,&Expected,sizeof(r))||replay.At!=Expected.TraceCount)return 33;
 printf("{\"passed\":true,\"events\":%u,\"reads\":%u,\"writes\":%u,\"waits\":%u}\n",r.TraceCount,r.Reads,r.Writes,replay.Waits);return 0;
}
