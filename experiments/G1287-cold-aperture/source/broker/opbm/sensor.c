#include "sensor.h"
#include "g104_policy.h"
#include <stddef.h>
#include <string.h>
typedef struct {
 const S183_IO *IO;
 S183_RESULT *R;
 G104_POLICY Policy;
 uint32_t CancelledBeforeConfigWrite;
} RUN;
static int Available(void *x){RUN*c=x;return c->IO->Available(c->IO->Context);}
static uint64_t NowUs(void*x){RUN*c=x;return c->IO->NowUs(c->IO->Context);}
static void Delay(void*x,uint32_t us){RUN*c=x;c->IO->DelayUs(c->IO->Context,us);}
static void WaitUs(void*x){Delay(x,1);}
static void WaitInterval(void*x){RUN*c=x;c->IO->WaitInterval(c->IO->Context);}
static int ConfigRead(void*x,uint32_t at,uint32_t*v){
 RUN*c=x;if(c->R->ConfigNativeReads>=G111_READ_LIMIT||!G111ReadAllowed(at)){c->R->ConfigGuard=1;return 0;}
 c->R->ConfigNativeReads++;return c->IO->Read(c->IO->Context,at,v);
}
static int ConfigWrite(void*x,uint32_t at,uint32_t value){
 RUN*c=x;uint32_t map,owner,status,previous;unsigned i;
 if(!Available(c)){c->CancelledBeforeConfigWrite=1;return 0;}
 if(c->R->ConfigNativeWrites>=G111_STEPS||!G111WriteAllowed(at,value)){c->R->ConfigGuard=2;return 0;}
 for(i=0;i<G111_TARGETS;i++)if(at==G111Base(i))break;
 if(i==G111_TARGETS){c->R->ConfigGuard=3;return 0;}
 if(!ConfigRead(c,0xc402000+G111Targets[i].Apid*4,&map)||!ConfigRead(c,0xc42d000+G111Targets[i].Apid*4,&owner)||map!=G111Targets[i].Map||owner!=G111Targets[i].Owner){c->R->ConfigGuard=4;return 0;}
 if(!ConfigRead(c,at+8,&status)||!ConfigRead(c,at,&previous)||(!(status&1)&&previous)){c->R->ConfigGuard=5;return 0;}
 c->R->ConfigNativeWrites++;return c->IO->Write(c->IO->Context,at,value);
}
static int GaugeSafeRead(RUN*c,uint32_t at,uint32_t*v){
 if(c->R->GaugeNativeReads>=200000||!G104ReadAllowed(at)){c->R->GaugeGuard=1;return 0;}
 c->R->GaugeNativeReads++;return c->IO->Read(c->IO->Context,at,v);
}
static int Clocks(RUN*c,unsigned i){
 uint32_t v[8],pin;const G102_CONTROLLER*k=G102Controllers+i;
 for(unsigned j=0;j<3;j++)if(!GaugeSafeRead(c,k->Clocks[j].Vote,v+2*j)||!GaugeSafeRead(c,k->Clocks[j].Cbcr,v+2*j+1))return 0;
 if(!GaugeSafeRead(c,k->Root,v+6)||!GaugeSafeRead(c,k->Root+4,v+7)||!G102ClockUsable(i,v)||v[7]!=(i?1u:0x100001u))return 0;
 for(unsigned j=0;j<2;j++)if(!GaugeSafeRead(c,0xf100000+k->Pins[j]*0x1000,&pin)||pin!=((k->Mux[j]<<2)|3))return 0;
 return 1;
}
static int GaugeRead(void*x,uint32_t at,uint32_t*v){
 RUN*c=x;int i=G102Peripheral(at);if(!G104ReadAllowed(at)){c->R->GaugeGuard=2;return 0;}
 if(i<0)i=G104Controller(at);if(i>=0&&!Clocks(c,(unsigned)i)){c->R->GaugeGuard=3;return 0;}
 int engine=G104Controller(at);
 if(engine>=0&&at-G102Controllers[engine].Base==0x780&&!G104ReceiveAllowed(&c->Policy,(unsigned)engine)){c->R->GaugeGuard=4;return 0;}
 if(!GaugeSafeRead(c,at,v))return 0;
 if(engine>=0)G104Observed(&c->Policy,(unsigned)engine,at-G102Controllers[engine].Base,*v);
 return 1;
}
static int WriteOffset(uint32_t o){return o==0x26c||o==0x270||o==0x600||o==0x604||o==0x618||o==0x700||o==0x80c;}
static int GaugeWrite(void*x,uint32_t at,uint32_t v){
 RUN*c=x;int i=G104Controller(at);
 if(i<0||!WriteOffset(at-G102Controllers[i].Base)||c->R->GaugeNativeWrites>=512){c->R->GaugeGuard=5;return 0;}
 if(!Clocks(c,(unsigned)i)){c->R->GaugeGuard=3;return 0;}
 if(!G104WriteAllowed(&c->Policy,(unsigned)i,at-G102Controllers[i].Base,v)){c->R->GaugeGuard=6;return 0;}
 c->R->GaugeNativeWrites++;return c->IO->Write(c->IO->Context,at,v);
}
void S183Capture(const S183_IO*io,uint64_t epoch,uint64_t sequence,S183_RESULT*r){
 if(!r)return;memset(r,0,sizeof(*r));r->Size=sizeof(*r);r->Version=1;r->Epoch=epoch;r->Sequence=sequence;
 if(!io||!io->Read||!io->Write||!io->Available||!io->NowUs||!io->Now100ns||!io->DelayUs||!io->WaitInterval||!epoch||!sequence){r->Code=S183_ARGUMENT;return;}
 RUN c={io,r,{0},0};r->Begin100ns=io->Now100ns(io->Context);
 G111_IO ci={&c,ConfigRead,ConfigWrite,WaitUs,WaitInterval,Available,NowUs};G111Observe(&ci,&r->Config);
 r->ConfigEnd100ns=io->Now100ns(io->Context);
 if(r->Config.Code||r->ConfigGuard){r->Code=S183_CONFIG;
  for(unsigned i=0;i<r->Config.TraceCount&&i<G111_STEPS;i++)if((r->Config.Trace[i].Flags&G111_WRITTEN)&&!(r->Config.Trace[i].Flags&G111_DONE))r->Uncertain=1;
  goto done;}
 if(!Available(&c)){r->Code=S183_CANCELLED;goto done;}
 G104_IO gi={&c,GaugeRead,GaugeWrite,Available,NowUs,Delay};G104Identify(&gi,&r->Gauge);
 r->GaugeEnd100ns=io->Now100ns(io->Context);r->Uncertain|=r->Gauge.Uncertain;
 r->PolicyCommands=c.Policy.Commands;r->PolicyCompleted=c.Policy.Completed;r->PolicyFault=c.Policy.Faulted;
 if(r->Gauge.Code||r->GaugeGuard)r->Code=S183_GAUGE;
 else if(c.Policy.Active||c.Policy.Held||c.Policy.Faulted||c.Policy.Commands!=46||c.Policy.Completed!=46)r->Code=S183_POLICY;
 done:r->End100ns=io->Now100ns(io->Context);
 if(!Available(&c)){
  int cancelled=(!r->Config.Code||r->Config.Code==G111_CANCELLED||(r->Config.Code==G111_IO_ERROR&&c.CancelledBeforeConfigWrite))&&
   (!r->Gauge.Code||r->Gauge.Code==G104_CANCELLED||
    (r->Gauge.Code==G104_PREFLIGHT&&r->Gauge.Before.Code==G102_CANCELLED)||
    (r->Gauge.Code==G104_RESTORE&&r->Gauge.After.Code==G102_CANCELLED));
  if(cancelled&&!r->Uncertain&&!r->ConfigGuard&&!r->GaugeGuard&&!r->PolicyFault){r->CancelledClean=1;r->Code=S183_CANCELLED;}
 }
 if(!r->Code&&(r->ConfigEnd100ns<r->Begin100ns||r->GaugeEnd100ns<r->ConfigEnd100ns||r->End100ns<r->GaugeEnd100ns||r->End100ns-r->Begin100ns>S183_PAIR_100NS))r->Code=S183_TIME;
}
uint32_t S183Validate(const S183_RESULT*r,S183_READING*out){
 S183_READING h={0};if(out)memset(out,0,sizeof(*out));
 if(!r||!out||r->Size!=sizeof(*r)||r->Version!=1||!r->Epoch||!r->Sequence||r->CancelledClean>1)return S183_ARGUMENT;
 if(r->Code||r->Uncertain)return r->Code?r->Code:S183_GAUGE;
 if(r->CancelledClean)return S183_ARGUMENT;
 if(r->ConfigEnd100ns<r->Begin100ns||r->GaugeEnd100ns<r->ConfigEnd100ns||r->End100ns<r->GaugeEnd100ns||r->End100ns-r->Begin100ns>S183_PAIR_100NS)return S183_TIME;
 const G111_RESULT*c=&r->Config;const G104_RESULT*g=&r->Gauge;
 if(c->Size!=sizeof(*c)||c->Code||c->Stage||c->Cancelled||!c->PostRoutesVerified||c->Commands!=19||c->Writes!=19||c->TraceCount!=19||c->Reserved[0]||c->Reserved[1]||r->ConfigGuard||r->ConfigNativeWrites!=19)return S183_CONFIG;
 if(memcmp(c->Values[0],(const uint8_t[]){0x20,0,0,2,0x51,0x47,1,0},8)||c->Values[1][4]!=2||c->Values[1][5]!=0xa8||c->Values[2][4]!=2||c->Values[2][5]!=0xa9||c->Values[3][4]!=2||c->Values[3][5]!=0xab||c->Values[4][4]!=2||c->Values[4][5]!=0xac)return S183_CONFIG;
 for(unsigned i=0;i<19;i++){
  const G111_QUERY*q=G111Queries+i;const G111_TRACE*t=c->Trace+i;
  if(t->Target!=q->Target||t->Offset!=q->Offset||t->Bytes!=q->Bytes||t->Flags!=63||t->Reserved||((t->Completion&15)!=1)||(!(t->BeforeStatus&1)&&t->BeforeCommand)||memcmp(c->Values[i],&t->Data0,q->Bytes))return S183_CONFIG;
  for(unsigned j=q->Bytes;j<8;j++)if(c->Values[i][j])return S183_CONFIG;
 }
 if(g->Size!=sizeof(*g)||g->Code||g->Stage||g->Commands!=46||g->Completed!=46||g->QueryMask!=0xfffff||g->CleanMask!=3||g->RestoredMask!=3||g->TraceCount>G104_TRACE||g->TraceDropped||g->Cancels||g->Aborts||g->Uncertain||g->Cancelled||r->GaugeGuard||r->PolicyFault||r->PolicyCommands!=46||r->PolicyCompleted!=46)return S183_GAUGE;
 if(g->Before.Code||g->Before.ReadyMask!=3||g->Before.PostClockMask!=3||g->Before.PinStableMask!=15||g->After.Code||g->After.ReadyMask!=3||g->After.PostClockMask!=3||g->After.PinStableMask!=15)return S183_GAUGE;
 unsigned reads=0,writes=0,rx=0,commands=0;
 for(unsigned i=0;i<g->TraceCount;i++){
  const G104_EVENT*e=g->Trace+i;if(e->Command>46)return S183_GAUGE;
  if(e->Kind==1){if(!G104ReadAllowed(e->Address))return S183_GAUGE;reads++;
   if((e->Address&4095)==0x780){if(rx>=20||e->Address!=(rx<10?0x880780u:0x98c780u)||(e->Value&65535)!=g->Values[rx/10][rx%10])return S183_GAUGE;rx++;}
  }else if(e->Kind==2){int engine=G104Controller(e->Address);if(engine<0||!WriteOffset(e->Address-G102Controllers[engine].Base))return S183_GAUGE;writes++;if((e->Address&4095)==0x600)commands++;}
  else return S183_GAUGE;
 }
 if(reads!=g->Reads||writes!=g->Writes||writes!=r->GaugeNativeWrites||rx!=20||commands!=46)return S183_GAUGE;
 for(unsigned i=0;i<2;i++){
  const uint32_t*v=g->Values[i];for(unsigned j=0;j<10;j++)if(v[j]>65535)return S183_DATA;
  if(v[0]!=0x6002||v[1]!=0x0602||v[2]!=0x0200||!v[3]||!v[4]||!v[7]||v[6]>v[7]||v[9]>100)return S183_DATA;
  h.TemperatureDeciK[i]=v[3];h.VoltageMv[i]=v[4];h.Flags[i]=v[5];h.RemainingMah[i]=v[6];h.FullMah[i]=v[7];h.CurrentRaw[i]=v[8];h.Percent[i]=v[9];
 }
 h.ChargerStateFirst=c->Values[5][0]&7;h.ChargerStateLast=c->Values[18][0]&7;h.Enable=c->Values[7][6]&1;h.FloatMv=3600+(c->Values[9][0]&127)*10;h.FastMa=c->Values[8][4]*50;h.UsbType=c->Values[12][1];h.Mode=c->Values[17][0];
 *out=h;return S183_OK;
}
