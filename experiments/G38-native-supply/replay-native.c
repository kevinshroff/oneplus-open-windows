/* SPDX-License-Identifier: MIT */
#include "g38_power.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "power-native-fixture.h"
typedef struct {G38_POWER_RESULT*Result;unsigned RscAt[9],ObsAt[3],PinsAt,Waits10,WaitsUs;} Replay;
static int Read(void*context,uint32_t at,uint32_t*out)
{
 Replay*c=context;G38_POWER_RESULT*r=c->Result;
 if(at>=0xf10a000&&at<=0xf11900c){
  static const uint32_t pins[8]={0xf10a000,0xf10a004,0xf118000,0xf118004,0xf119000,0xf119004,0xf119008,0xf11900c};
  unsigned index=c->PinsAt++;if(index>=16||pins[index%8]!=at)exit(30);
  *out=index<8?Expected.GuardBefore[index]:Expected.GuardAfter[index-8];return 1;
 }
 if(at>=0xc400000&&at<0xc446000){
  const G38_OBS_EVENT*e;unsigned n=r->PmicCount;if(!n||n>3)exit(31);n--;
  if(c->ObsAt[n]>=Expected.Pmic[n].TraceCount)exit(32);e=&Expected.Pmic[n].Trace[c->ObsAt[n]++];
  if(e->Kind!=1||e->Address!=at)exit(33);*out=e->Value;return 1;
 }
 {const G38_RSC_EVENT*e;unsigned n=r->TxnCount;if(!n||n>9)exit(34);n--;
 if(c->RscAt[n]>=Expected.Transactions[n].TraceCount)exit(35);e=&Expected.Transactions[n].Trace[c->RscAt[n]++];
 if(e->Kind!=1||e->Address!=at)exit(36);*out=e->Value;return 1;}
}
static int Write(void*context,uint32_t at,uint32_t v)
{
 Replay*c=context;G38_POWER_RESULT*r=c->Result;
 if(at>=0xc400000&&at<0xc446000){
  unsigned n=r->PmicCount-1;const G38_OBS_EVENT*e;if(n>=3||c->ObsAt[n]>=Expected.Pmic[n].TraceCount)exit(40);
  e=&Expected.Pmic[n].Trace[c->ObsAt[n]++];if(e->Kind!=2||e->Address!=at||e->Value!=v)exit(41);return 1;
 }
 {unsigned n=r->TxnCount-1;const G38_RSC_EVENT*e;if(n>=9||c->RscAt[n]>=Expected.Transactions[n].TraceCount)exit(42);
 e=&Expected.Transactions[n].Trace[c->RscAt[n]++];if(e->Kind!=2||e->Address!=at||e->Value!=v)exit(43);return 1;}
}
static void Wait1(void*context){Replay*c=context;c->Result->Waits1ms++;}
static void Wait10(void*context){((Replay*)context)->Waits10++;}
static void WaitUs(void*context){((Replay*)context)->WaitsUs++;}
int main(void)
{
 G38_POWER_RESULT r;Replay c;G38_POWER_IO io;unsigned i,events=0,reads=0,writes=0;
 memset(&r,0,sizeof(r));memset(&c,0,sizeof(c));c.Result=&r;
 io.Rsc.Context=&c;io.Rsc.Read=Read;io.Rsc.Write=Write;io.Rsc.WaitMillisecond=Wait1;
 io.Observer.Context=&c;io.Observer.Read=Read;io.Observer.Write=Write;io.Observer.WaitMicrosecond=WaitUs;io.WaitTenMilliseconds=Wait10;
 G38PowerTrial(&io,&r);
 if(memcmp(&r,&Expected,sizeof(r))||c.PinsAt!=16||c.Waits10!=Expected.Waits10ms)return 50;
 for(i=0;i<9;i++){if(c.RscAt[i]!=r.Transactions[i].TraceCount)return 51;events+=c.RscAt[i];reads+=r.Transactions[i].Reads;writes+=r.Transactions[i].Writes;}
 for(i=0;i<3;i++){if(c.ObsAt[i]!=r.Pmic[i].TraceCount)return 52;events+=c.ObsAt[i];reads+=r.Pmic[i].Reads;writes+=r.Pmic[i].Writes;}
 printf("{\"passed\":true,\"events\":%u,\"reads\":%u,\"writes\":%u,\"separate_pin_guard_reads\":16,\"waits_1ms\":%u,\"waits_10ms\":%u,\"observer_waits_us\":%u,\"all_actual_C_cores_and_output_fields\":true}\n",events,reads,writes,r.Waits1ms,c.Waits10,c.WaitsUs);return 0;
}
