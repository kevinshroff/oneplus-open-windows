#include "sensor.h"
#include "g104_policy.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t ULONG;
/* Actual core/policy execute with explicit register, time and bus models. */
#include "g104_policy.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static const uint32_t Pages[]={0x152000,0x11e000,0x117000,0x123000,0xf100000,0xf101000,0xf116000,0xf117000,0x880000,0x8c0000,0x98c000,0x9c0000};
typedef struct{
 uint32_t Memory[12][1024];G104_POLICY Policy;
 unsigned Reads,Writes,FailRead,FailWrite,CancelAt,ErrorCmd,TimeoutCmd,NoCancel,NoAbort,BadRX,Selectors[2],Fed[2],Waiting[2],Kind[2],CMDCount,Pointers[2],BadID;
 uint64_t Now;
}GAUGE_MODEL;

static uint32_t*At(GAUGE_MODEL*m,uint32_t at){for(unsigned i=0;i<12;i++)if(at>=Pages[i]&&at-Pages[i]<4096)return&m->Memory[i][(at-Pages[i])/4];assert(0);return NULL;}
static void Put(GAUGE_MODEL*m,unsigned i,unsigned o,uint32_t v){*At(m,G102Controllers[i].Base+o)=v;}
static int GaugeModelRead(void*x,uint32_t at,uint32_t*v){
 GAUGE_MODEL*m=x;assert(G104ReadAllowed(at));m->Reads++;if(m->Reads==m->FailRead)return 0;
 int i=G104Controller(at);unsigned o=i>=0?at-G102Controllers[i].Base:0;
 if(i>=0&&o==0x610&&m->Waiting[i]){
  if(m->CMDCount==m->ErrorCmd){Put(m,i,0x610,0x480);Put(m,i,0x40,0);Put(m,i,0x908,7);m->Waiting[i]=0;}
  else if(m->CMDCount!=m->TimeoutCmd){
   if(m->Kind[i]!=2&&!m->Fed[i])Put(m,i,0x610,0x40000080);
   else{
    Put(m,i,0x610,0x81|(m->Kind[i]==2?0x08000000:0));Put(m,i,0x40,0);Put(m,i,0x908,m->Kind[i]==1?1:7);
    if(m->Kind[i]==2)Put(m,i,0x804,m->BadRX?0xb0000001:0xa0000001);m->Waiting[i]=0;
   }
  }
 }
 if(i>=0&&o==0x780){
  assert(G104ReceiveAllowed(&m->Policy,(unsigned)i));
  uint32_t value=0;
  if(!m->Pointers[i])value=m->Selectors[i]==0?0x6002u:m->Selectors[i]==1?(m->BadID?0x0603u:0x0602u):0x0200u;
  else switch(m->Pointers[i]){case 6:value=3000+10*i;break;case 8:value=4000-25*i;break;case 10:value=1;break;case 16:value=i?500:1400;break;case 18:value=i?800:2000;break;case 20:value=i?0xffce:0xff9c;break;case 44:value=i?62:70;break;default:assert(0);}
  *v=0xa55a0000u|value;Put(m,i,0x804,0);
 }else *v=*At(m,at);
 if(i>=0)G104Observed(&m->Policy,(unsigned)i,o,*v);return 1;
}
static int GaugeModelWrite(void*x,uint32_t at,uint32_t v){
 GAUGE_MODEL*m=x;int i=G104Controller(at);assert(i>=0);unsigned o=at-G102Controllers[i].Base;m->Writes++;if(m->Writes==m->FailWrite)return 0;
 assert(G104WriteAllowed(&m->Policy,(unsigned)i,o,v));
 if(o==0x600){m->Kind[i]=G104Kind(m->CMDCount);m->CMDCount++;m->Waiting[i]=1;m->Fed[i]=0;Put(m,i,0x40,1);Put(m,i,0x610,0x80);}
 if(o==0x700){m->Fed[i]=1;if(m->Kind[i]==0){m->Selectors[i]=v>>8;m->Pointers[i]=0;}else if(m->Kind[i]==1)m->Pointers[i]=v;}
 if(o==0x604&&((v==4&&!m->NoCancel)||(v==2&&!m->NoAbort))){m->Waiting[i]=0;Put(m,i,0x40,0);Put(m,i,0x800,0);Put(m,i,0x804,0);Put(m,i,0x908,7);Put(m,i,0x610,0x80|(v==4?0x10:0x20));}
 if(o==0x618)*At(m,G102Controllers[i].Base+0x610)&=~v;
 else *At(m,at)=v;
 return 1;
}
static int GaugeModelAvailable(void*x){GAUGE_MODEL*m=x;return !m->CancelAt||m->Reads<m->CancelAt;}
static uint64_t GaugeModelNow(void*x){GAUGE_MODEL*m=x;return++m->Now;}
static void GaugeModelDelay(void*x,uint32_t us){assert(us==20);((GAUGE_MODEL*)x)->Now+=us;}
static void GaugeModelReset(GAUGE_MODEL*m){
 memset(m,0,sizeof(*m));
 for(unsigned i=0;i<2;i++){
  const G102_CONTROLLER*c=G102Controllers+i;
  for(unsigned j=0;j<3;j++){*At(m,c->Clocks[j].Vote)|=c->Clocks[j].Mask;*At(m,c->Clocks[j].Cbcr)=c->Clocks[j].Hwcg?0x80000002:0;}
  *At(m,c->Root+4)=i?1:0x100001;
  for(unsigned j=0;j<2;j++){*At(m,0xf100000+c->Pins[j]*0x1000)=(c->Mux[j]<<2)|3;*At(m,0xf100004+c->Pins[j]*0x1000)=1;}
  const unsigned off[]={0,4,0x24,0x28,0x48,0x68,0x6c,0x26c,0x270,0x278,0x610,0x640,0xe24,0xe28,0x260,0x264,0x284,0x288,0x600,0x614,0x644,0x810,0x814,0x908};
  const uint32_t val[]={9,9,0x7f,0x7f,0x71,0x303,0x303,1,2,0xa02c1a,0x80,0x08000000,0x201029e4,0x20104800,0x7f8fe,0xffefe,0x7f8fe,0xffefe,0x1000aa00,0x33c0007e,0x03001e36,13,14,7};
  for(unsigned j=0;j<sizeof(off)/sizeof(off[0]);j++)Put(m,i,off[j],val[j]);Put(m,i,0x50,1);
 }*At(m,0x8c0004)=0x30090000;
}

static ULONG Mem[5][1024],Cmd[G111_TARGETS],Reg[G111_TARGETS][256],Issued,MapCalls,Unmaps,ReadCalls,WriteCalls,CancelAt,CancelChecks,FailMap,TimeoutAt,ErrorAt,SlowPoll,Poll[G111_TARGETS],Mutation,NoRanges,FullOS,Firmware,Build,Processors;

static const uint32_t SpmiPages[]={0xc400000,0xc402000,0xc42d000,0xc443000,0xc445000};
static uint32_t Phys(uint32_t*p){for(unsigned i=0;i<5;i++)if((uintptr_t)p>=(uintptr_t)Mem[i]&&(uintptr_t)p<(uintptr_t)(Mem[i]+1024))return SpmiPages[i]+(uint32_t)((uintptr_t)p-(uintptr_t)Mem[i]);assert(0);return 0;}
static uint32_t SpmiModelRead(uint32_t* p){uint32_t at=Phys(p);assert(G111ReadAllowed(at));ReadCalls++;
 for(unsigned i=0;i<G111_TARGETS;i++){uint32_t base=G111Base(i);if(at==base)return Cmd[i];if(at==base+8){if(!Cmd[i])return 1;if(Issued==TimeoutAt)return 0;if(++Poll[i]<SlowPoll)return 0;return Issued==ErrorAt?3:1;}if(at==base+0x18||at==base+0x1c){uint32_t n=(Cmd[i]&7)+1,off=(Cmd[i]>>4)&255,start=at==base+0x18?0:4,v=0;for(uint32_t j=0;j<4&&j+start<n;j++)v|=Reg[i][off+start+j]<<(8*j);return v;}}
 return *p;
}
static void SpmiModelWrite(uint32_t* p,uint32_t v){uint32_t at=Phys(p);assert(G111WriteAllowed(at,v));assert((v>>24)==8);WriteCalls++;for(unsigned i=0;i<G111_TARGETS;i++)if(at==G111Base(i)){Cmd[i]=v;Poll[i]=0;Issued++;return;}assert(!"nonfixed write");}

static void SpmiReset(void){memset(Mem,0,sizeof(Mem));memset(Reg,0,sizeof(Reg));memset(Cmd,0,sizeof(Cmd));memset(Poll,0,sizeof(Poll));Issued=MapCalls=Unmaps=ReadCalls=WriteCalls=CancelAt=CancelChecks=FailMap=TimeoutAt=ErrorAt=Mutation=NoRanges=0;SlowPoll=2;FullOS=Firmware=1;Build=26100;Processors=8;
 Mem[0][0]=0x70000001;Mem[0][1]=0x80040300;Mem[0][2]=0x100;
 for(unsigned i=0;i<G111_TARGETS;i++){Mem[1][G111Targets[i].Apid]=G111Targets[i].Map;Mem[2][G111Targets[i].Apid]=G111Targets[i].Owner;}
 Reg[0][4]=0x51;Reg[0][5]=0x47;Reg[0][6]=1;
 for(unsigned i=1;i<5;i++){Reg[i][4]=2;Reg[i][5]=i==1?0xa8:0xa0+i;}
 Reg[2][6]=7;Reg[2][0x50]=4;Reg[2][0x54]=6;Reg[2][0x58]=87;Reg[4][0xa]=Reg[4][0xb]=1;Reg[5][0x43]=0x40;Reg[2][0xa0]=1;
}
