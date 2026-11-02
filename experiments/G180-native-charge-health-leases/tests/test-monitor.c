/* Actual policy bridge and actual control core, explicit peer/clock models.
 * Sensor bytes are frozen native G177 data; mutations are simulated faults. */
#define main OriginalCoreTestMain
#include "test-link.c"
#undef main
#include "health_monitor.h"
static uint8_t Config[CH_CONFIG_BYTES],Gauge[CH_GAUGE_BYTES];
static uint64_t Word64(const uint8_t*p){return U32(p)|(uint64_t)U32(p+4)<<32;}
static void LoadBytes(const char*p,uint8_t*b,size_t n){FILE*f=fopen(p,"rb");assert(f&&fread(b,1,n,f)==n&&fgetc(f)==EOF&&!fclose(f));}
static MODEL*On(uint64_t now){MODEL*m=Create();m->Now=now/10-20000000;Open(m);Fv(m);Enabled(m);assert(m->Now<now/10&&m->State->PulseUntilUs>now/10);return m;}
static void Off(MODEL*m,uint64_t now){m->Now=now/10;for(unsigned i=0;i<1000&&m->State->BatchActive;i++)assert(Step(m)>=0);assert(m->State->PulseDisableAcked&&m->Disables==2&&m->Enables==1&&m->Sets==4);Close(m);Destroy(m);}
static void GaugeValue(unsigned word,uint32_t value){P32(Gauge+120+80+4*word,value);unsigned rx=0;for(unsigned i=0;i<U32(Gauge+120+32);i++){uint8_t*t=Gauge+120+17616+16*i;if(U32(t)==1&&(U32(t+4)&4095)==0x780){if(rx++==word){P32(t+8,value);return;}}}assert(0);}
int main(int argc,char**argv)
{
 assert(argc==3);LoadBytes(argv[1],Config,sizeof(Config));LoadBytes(argv[2],Gauge,sizeof(Gauge));
 uint64_t nonce=Word64(Gauge+80),now=Word64(Gauge+56)+100000;CH_MONITOR h;MODEL*m;
 /* A fresh physical pair can extend once; its replay forces early off and
  * latches the policy fault instead of extending from the same acquisition. */
 m=On(now);CHMonitorInitialize(&h);assert(CHMonitorRenew(&h,m->State,Config,sizeof(Config),Gauge,sizeof(Gauge),nonce,now)==CH_OK);
 assert(h.Accepted==1&&!h.Fault&&m->State->HealthLeaseRenewals==1&&m->State->PulseUntilUs==now/10+CL_PULSE_US);
 CH_HEALTH old=h.LastGood;
 assert(CHMonitorRenew(&h,m->State,Config,sizeof(Config),Gauge,sizeof(Gauge),nonce,now+10000)==CH_NONCE);
 assert(h.Fault==CH_NONCE&&h.Accepted==1&&!memcmp(&old,&h.LastGood,sizeof(old))&&m->State->StopPulseRequested);
 Off(m,now+10000);
 /* Fault-latched producer state never recovers simply because data becomes
  * valid again; the experiment needs a new qualified owner/boot. */
 m=On(now);CHMonitorInitialize(&h);uint32_t original=U32(Gauge+120+24);P32(Gauge+120+24,0);
 assert(CHMonitorRenew(&h,m->State,Config,sizeof(Config),Gauge,sizeof(Gauge),nonce,now)==CH_GAUGE_RESULT);
 P32(Gauge+120+24,original);
 assert(CHMonitorRenew(&h,m->State,Config,sizeof(Config),Gauge,sizeof(Gauge),nonce,now+10000)==CH_GAUGE_RESULT);
 assert(!h.Accepted&&h.Fault&&m->State->StopPulseRequested);Off(m,now+10000);
 for(unsigned which=0;which<5;which++){
  m=On(now);CHMonitorInitialize(&h);uint32_t code;
  if(which==0)code=CHMonitorRenew(&h,m->State,NULL,0,Gauge,sizeof(Gauge),nonce,now);
  else if(which==1)code=CHMonitorRenew(&h,m->State,Config,sizeof(Config),NULL,0,nonce,now);
  else if(which==2)code=CHMonitorRenew(&h,m->State,Config,sizeof(Config),Gauge,sizeof(Gauge),nonce^1,now);
  else if(which==3){m->State->PulseUntilUs=now/10;code=CHMonitorRenew(&h,m->State,Config,sizeof(Config),Gauge,sizeof(Gauge),nonce,now);}
  else{m->State->HealthLeaseRenewals=CL_HEALTH_RENEW_LIMIT;code=CHMonitorRenew(&h,m->State,Config,sizeof(Config),Gauge,sizeof(Gauge),nonce,now);}
  assert(code&&h.Fault&&!h.Accepted&&m->State->StopPulseRequested);Off(m,now);
 }
 m=On(now);CHMonitorInitialize(&h);uint64_t late=now+CH_FRESH_100NS;
 assert(CHMonitorRenew(&h,m->State,Config,sizeof(Config),Gauge,sizeof(Gauge),nonce,late)==CH_FRESHNESS);Off(m,late);
 /* Hardware-like overtemperature, overvoltage and excess current mutations
  * update their RX trace too, so the actual range policy causes early off. */
 const unsigned words[]={3,4,8};const uint32_t bad[]={3132,4301,501},codes[]={CH_TEMPERATURE,CH_VOLTAGE,CH_CURRENT};
 for(unsigned i=0;i<3;i++){
  m=On(now);CHMonitorInitialize(&h);uint32_t saved=U32(Gauge+120+80+4*words[i]);GaugeValue(words[i],bad[i]);
  assert(CHMonitorRenew(&h,m->State,Config,sizeof(Config),Gauge,sizeof(Gauge),nonce,now)==codes[i]);
  GaugeValue(words[i],saved);assert(h.Fault==codes[i]&&m->State->StopPulseRequested);Off(m,now);
 }
 /* An off reply can still be lost. That remains transport uncertainty and
  * never triggers an enable/off replay or claims verified disabled hardware. */
 m=On(now);CHMonitorInitialize(&h);assert(CHMonitorRenew(&h,m->State,NULL,0,NULL,0,nonce,now)==CH_ARGUMENT);m->Now=now/10;m->Silent=1;
 for(unsigned i=0;i<5000&&m->State->Phase!=CL_CLOSED&&m->State->Phase!=CL_FAILED;i++)Step(m);
 assert(m->State->RpcUncertain&&m->State->Fault==CL_F_TIMEOUT&&m->Disables==2&&m->Enables==1&&!m->State->PulseDisableAcked);
 uint32_t tx=m->TxWrites;assert(CHMonitorRenew(&h,m->State,Config,sizeof(Config),Gauge,sizeof(Gauge),nonce,now+50000000)==CH_ARGUMENT);assert(m->TxWrites==tx);Destroy(m);
 printf("{\"passed\":true,\"cases\":%u,\"native_operations\":0,\"actual_core_and_monitor\":true,\"model_peer_clock_and_faults\":true}\n",Cases);return 0;
}
