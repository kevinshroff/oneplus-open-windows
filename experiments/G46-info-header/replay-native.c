/* SPDX-License-Identifier: MIT */
#include "g46_trial.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "native-recovery-fixture.h"
typedef struct {uint32_t Kind,Address,Value;} Event;
typedef struct {G46_TRIAL_RESULT*Result;unsigned At[16],PinsAt,Waits10,WaitsMs[5],WaitsUs,Barriers;uint64_t Now;} Replay;
static Event Next(Replay*c,unsigned kind,uint32_t at)
{
 G46_TRIAL_RESULT*r=c->Result;unsigned n=16,i,counts[16],lengths[16];const void*traces[16];Event e;
#define STREAM(n,have,want) do{counts[n]=(have).Reads+(have).Writes;traces[n]=(want).Trace;lengths[n]=(want).TraceCount;}while(0)
 STREAM(0,r->Spi,Expected.Spi);STREAM(1,r->Spi.Engine,Expected.Spi.Engine);STREAM(2,r->Touch,Expected.Touch);STREAM(3,r->Touch.PoweredPmic,Expected.Touch.PoweredPmic);
 for(i=0;i<3;i++)STREAM(4+i,r->Power.Pmic[i],Expected.Power.Pmic[i]);
 for(i=0;i<9;i++)STREAM(7+i,r->Power.Transactions[i],Expected.Power.Transactions[i]);
#undef STREAM
 for(i=0;i<16;i++)if(counts[i]>c->At[i]){if(n!=16||counts[i]!=c->At[i]+1)exit(20);n=i;}
 if(n==16){const uint32_t pins[8]={0xf10a000,0xf10a004,0xf118000,0xf118004,0xf119000,0xf119004,0xf119008,0xf11900c};unsigned p=c->PinsAt++;if(kind!=1||p>=16||at!=pins[p%8])exit(21);e.Kind=1;e.Address=at;e.Value=p<8?Expected.Power.GuardBefore[p]:Expected.Power.GuardAfter[p-8];return e;}
 if(c->At[n]>=lengths[n])exit(22);memcpy(&e,(const unsigned char*)traces[n]+sizeof(e)*c->At[n]++,sizeof(e));
 if(e.Kind!=kind||e.Address!=at){fprintf(stderr,"event mismatch stream%u addr%x expected%x kind%u/%u\n",n,at,e.Address,kind,e.Kind);exit(23);}return e;
}
static int Read(void*ctx,uint32_t at,uint32_t*out){*out=Next(ctx,1,at).Value;return 1;}
static int Write(void*ctx,uint32_t at,uint32_t v){if(Next(ctx,2,at).Value!=v)exit(24);return 1;}
static void Wait1(void*ctx){Replay*c=ctx;c->Result->Power.Waits1ms++;c->Now+=1000;}
static void Wait10(void*ctx){Replay*c=ctx;c->Waits10++;c->Now+=10000;}
static void WaitUs(void*ctx){Replay*c=ctx;c->WaitsUs++;c->Now++;}
static void WaitMs(void*ctx,uint32_t ms){Replay*c=ctx;unsigned i=ms==10?0:ms==15?1:ms==50?2:ms==100?3:4;if(i==4)exit(25);c->WaitsMs[i]++;c->Now+=(uint64_t)ms*1000;}
static void Poll(void*ctx){Replay*c=ctx;c->WaitsMs[4]++;c->Now+=10;}
static uint64_t Now(void*ctx){return((Replay*)ctx)->Now;}
static int Barrier(void*ctx){((Replay*)ctx)->Barriers++;return 0;}
static int Ready(void*ctx){Replay*c=ctx;G46_OBS_IO io={ctx,Read,Write,WaitUs};G46_OBS_RESULT*p=&c->Result->Touch.PoweredPmic;const uint8_t cfg[8]={8,7,8,7,7,7,128,0};G46Observe(&io,p);return!p->Code&&p->Status==0xc7&&!memcmp(p->Configuration,cfg,8);}
static int Touch(void*ctx){Replay*c=ctx;G46_TOUCH_IO io={ctx,Read,Write,Barrier,Ready,WaitMs,Poll,Now};return G46TouchRead(&io,&c->Result->Touch);}
static int Powered(void*ctx){Replay*c=ctx;G46_TRIAL_RESULT*t=c->Result;G46_SPI_IO io={ctx,Read,Write,WaitUs,Touch};t->PoweredHookCalled++;t->Touch.BusQuiescent=1;G46PrepareSpi(&io,&t->Spi);t->SafeRelease=(!t->Spi.VoteDirty||t->Spi.Restored)&&(!t->Spi.Engine.Dirty||t->Spi.Engine.Restored)&&!t->Spi.RestoreError&&!t->Spi.Engine.RestoreError&&(!t->Touch.AnalogDirty||t->Touch.Restored)&&t->Touch.BusQuiescent;return!t->Spi.Code&&t->Spi.Restored&&t->Touch.TransportOk&&t->Touch.HeaderLengthValid&&t->Touch.Restored;}
static int Safe(void*ctx){return((Replay*)ctx)->Result->SafeRelease!=0;}
int main(void)
{
 G46_TRIAL_RESULT r;G46_POWER_IO p;G46_TOUCH_IO t;Replay c;unsigned i,events=0;
 memset(&r,0,sizeof(r));memset(&p,0,sizeof(p));memset(&t,0,sizeof(t));memset(&c,0,sizeof(c));c.Result=&r;r.SafeRelease=1;
 p.Rsc.Context=&c;p.Rsc.Read=Read;p.Rsc.Write=Write;p.Rsc.WaitMillisecond=Wait1;p.Observer.Context=&c;p.Observer.Read=Read;p.Observer.Write=Write;p.Observer.WaitMicrosecond=WaitUs;p.WaitTenMilliseconds=Wait10;p.Powered=Powered;p.SafeToRelease=Safe;
 t.Context=&c;t.Read=Read;t.Write=Write;t.WaitMs=WaitMs;
 G46PowerTrial(&p,&r.Power);if(r.Power.Restored&&r.Touch.Restored&&!G46VerifyTouchOff(&t,&r.Touch)){r.Power.Restored=0;if(!r.Power.Code)r.Power.Code=109;}
 if(memcmp(&r,&Expected,sizeof(r))){const unsigned char*a=(const unsigned char*)&r,*b=(const unsigned char*)&Expected;for(i=0;i<sizeof(r);i++)if(a[i]!=b[i]){fprintf(stderr,"result mismatch byte%u %u/%u\n",i,a[i],b[i]);break;}return 30;}
 if(c.PinsAt!=16||c.Waits10!=Expected.Power.Waits10ms||memcmp(c.WaitsMs,Expected.Touch.WaitCounts,sizeof(c.WaitsMs)))return 31;
 for(i=0;i<16;i++)events+=c.At[i];
 printf("{\"passed\":true,\"events\":%u,\"separate_pin_guard_reads\":16,\"all7_actual_C_cores_and_all_result_bytes\":true,\"SPI_commands\":1,\"payload_bytes\":28,\"advertised_length\":%u,\"complete_IC_info_checksum_verified\":false,\"supply_enable_commands\":1,\"supply_releases\":1,\"waits_1ms\":%u,\"waits_10ms\":%u,\"waits_us\":%u,\"replayed_FIFO_barriers\":%u}\n",events,r.Touch.InfoLength,r.Power.Waits1ms,c.Waits10,c.WaitsUs,c.Barriers);return 0;
}
