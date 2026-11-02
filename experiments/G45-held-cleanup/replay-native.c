/* SPDX-License-Identifier: MIT */
#include "g45_recovery.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "native-recovery-fixture.h"
typedef struct {uint32_t Kind,Address,Value;} Event;
typedef struct {G45_TRIAL_RESULT*Result;unsigned At[9],PinsAt,Waits10,WaitsMs[5],WaitsUs;} Replay;
static Event Next(Replay*c,unsigned kind,uint32_t at)
{
 G45_TRIAL_RESULT*r=c->Result;unsigned n=9,i,counts[9]={r->Spi.Reads+r->Spi.Writes,r->Spi.Engine.Reads+r->Spi.Engine.Writes,r->Touch.Reads+r->Touch.Writes,r->Touch.PoweredPmic.Reads+r->Touch.PoweredPmic.Writes,r->Power.Pmic[0].Reads+r->Power.Pmic[0].Writes,r->Power.Transactions[0].Reads+r->Power.Transactions[0].Writes,r->Power.Transactions[1].Reads+r->Power.Transactions[1].Writes,r->Power.Transactions[2].Reads+r->Power.Transactions[2].Writes,r->Power.Transactions[3].Reads+r->Power.Transactions[3].Writes};
 const void*traces[9]={Expected.Spi.Trace,Expected.Spi.Engine.Trace,Expected.Touch.Trace,Expected.Touch.PoweredPmic.Trace,Expected.Power.Pmic[0].Trace,Expected.Power.Transactions[0].Trace,Expected.Power.Transactions[1].Trace,Expected.Power.Transactions[2].Trace,Expected.Power.Transactions[3].Trace};
 const unsigned lengths[9]={Expected.Spi.TraceCount,Expected.Spi.Engine.TraceCount,Expected.Touch.TraceCount,Expected.Touch.PoweredPmic.TraceCount,Expected.Power.Pmic[0].TraceCount,Expected.Power.Transactions[0].TraceCount,Expected.Power.Transactions[1].TraceCount,Expected.Power.Transactions[2].TraceCount,Expected.Power.Transactions[3].TraceCount};Event e;
 for(i=0;i<9;i++)if(counts[i]>c->At[i]){if(n!=9||counts[i]!=c->At[i]+1)exit(20);n=i;}
 if(n==9){
  const uint32_t pins[8]={0xf10a000,0xf10a004,0xf118000,0xf118004,0xf119000,0xf119004,0xf119008,0xf11900c};unsigned p=c->PinsAt++;
  if(kind!=1||p>=16||at!=pins[p%8])exit(21);e.Kind=1;e.Address=at;e.Value=p<8?Expected.Power.GuardBefore[p]:Expected.Power.GuardAfter[p-8];return e;
 }
 if(c->At[n]>=lengths[n])exit(22);memcpy(&e,(const unsigned char*)traces[n]+sizeof(e)*c->At[n]++,sizeof(e));
 if(e.Kind!=kind||e.Address!=at){fprintf(stderr,"event mismatch stream%u addr%x expected%x kind%u/%u\n",n,at,e.Address,kind,e.Kind);exit(23);}return e;
}
static int Read(void*ctx,uint32_t at,uint32_t*out){*out=Next(ctx,1,at).Value;return 1;}
static int Write(void*ctx,uint32_t at,uint32_t v){if(Next(ctx,2,at).Value!=v)exit(24);return 1;}
static void Wait1(void*ctx){((Replay*)ctx)->Result->Power.Waits1ms++;}
static void Wait10(void*ctx){((Replay*)ctx)->Waits10++;}
static void WaitUs(void*ctx){((Replay*)ctx)->WaitsUs++;}
static void WaitMs(void*ctx,uint32_t ms){Replay*c=ctx;unsigned i=ms==10?0:ms==15?1:ms==50?2:ms==100?3:4;if(i==4)exit(25);c->WaitsMs[i]++;}
int main(void)
{
 G45_TRIAL_RESULT r;G45_POWER_IO p;G45_TOUCH_IO t;Replay c;unsigned i,events=0;
 memset(&r,0,sizeof(r));memset(&p,0,sizeof(p));memset(&t,0,sizeof(t));memset(&c,0,sizeof(c));c.Result=&r;
 p.Rsc.Context=&c;p.Rsc.Read=Read;p.Rsc.Write=Write;p.Rsc.WaitMillisecond=Wait1;p.Observer.Context=&c;p.Observer.Read=Read;p.Observer.Write=Write;p.Observer.WaitMicrosecond=WaitUs;p.WaitTenMilliseconds=Wait10;
 t.Context=&c;t.Read=Read;t.Write=Write;t.WaitMs=WaitMs;
 G45RecoverHeld(&p,&t,&r);
 if(memcmp(&r,&Expected,sizeof(r))){const unsigned char*a=(const unsigned char*)&r,*b=(const unsigned char*)&Expected;for(i=0;i<sizeof(r);i++)if(a[i]!=b[i]){fprintf(stderr,"result mismatch byte%u %u/%u\n",i,a[i],b[i]);break;}return 30;}
 if(c.PinsAt!=16||c.Waits10!=Expected.Power.Waits10ms||memcmp(c.WaitsMs,Expected.Touch.WaitCounts,sizeof(c.WaitsMs)))return 31;
 for(i=0;i<9;i++)events+=c.At[i];
 printf("{\"passed\":true,\"events\":%u,\"separate_pin_guard_reads\":16,\"all7_actual_C_cores_and_all_result_bytes\":true,\"new_SPI_commands\":0,\"supply_enable_commands\":0,\"supply_releases\":1,\"waits_1ms\":%u,\"waits_10ms\":%u,\"waits_us\":%u}\n",events,r.Power.Waits1ms,c.Waits10,c.WaitsUs);return 0;
}
