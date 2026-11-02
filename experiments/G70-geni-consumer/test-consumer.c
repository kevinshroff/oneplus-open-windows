/* SPDX-License-Identifier: MIT -- production core and modeled MMIO callbacks. */
#define main ClockRegressionMain
#include "test-clock.c"
#undef main
#include "g70_consumer.h"
static unsigned EngineReads,FailEngine,MutateAt,MutateBit,LastEngineReg;
static int Engine(void*x,uint32_t reg,uint32_t*v)
{
 MODEL*m=x;
 assert(reg<10&&!m->Removed&&(m->Reg[0]&G70_VOTE_MASK)==G70_VOTE_MASK);
 assert(reg==EngineReads%10);LastEngineReg=reg;EngineReads++;
 if(EngineReads==FailEngine)return 0;
 *v=G70EngineExpected[reg];if(EngineReads==MutateAt)*v^=1u<<MutateBit;
 return 1;
}
static int Consume(MODEL*m,G70_CLOCK_RESULT*c,G70_PROBE_RESULT*p)
{
 G70_CONSUMER_IO io={Io(m),Engine};return G70Consume(&io,c,p,42);
}
static void Fresh(MODEL*m,G70_CLOCK_RESULT*c,G70_PROBE_RESULT*p)
{Reset(m,c);memset(p,0,sizeof(*p));EngineReads=FailEngine=MutateAt=MutateBit=LastEngineReg=0;}
static void ControllerResources(uint8_t a[5][20])
{
 memset(a,0,100);
 for(unsigned i=0;i<4;i++){a[i][0]=3;a[i][1]=1;Put32(a[i]+4,G70MapBase[i]);Put32(a[i]+12,G70MapBytes[i]);}
 a[4][0]=2;a[4][1]=1;Put32(a[4]+4,389);Put32(a[4]+8,389);Put32(a[4]+12,0xffffffffu);
}
int main(void)
{
 MODEL m;G70_CLOCK_RESULT c;G70_PROBE_RESULT p;uint8_t a[5][20],b[5][20];uint32_t index[4];unsigned count=0;
 Fresh(&m,&c,&p);assert(Consume(&m,&c,&p)&&c.Restored&&p.ReadCount==20&&p.CompletePasses==2&&p.IdentityMatch&&p.Stable&&EngineReads==20&&LastEngineReg==9);Check(&m,&c);count++;
 for(unsigned at=1;at<=20;at++){
  Fresh(&m,&c,&p);FailEngine=at;assert(!Consume(&m,&c,&p)&&p.Code==2&&p.ReadCount==at&&EngineReads==at&&c.Restored&&!c.DirtyMask&&!c.Active);Check(&m,&c);count++;
  for(unsigned bit=0;bit<32;bit++){
   Fresh(&m,&c,&p);MutateAt=at;MutateBit=bit;assert(!Consume(&m,&c,&p)&&p.Code==3&&EngineReads==at&&c.Restored);Check(&m,&c);count++;
  }
 }
 for(unsigned at=1;at<=35;at++){
  Fresh(&m,&c,&p);m.FailRead=at;assert(!Consume(&m,&c,&p)&&(c.Code||c.RestoreError)&&p.ReadCount==EngineReads);Check(&m,&c);count++;
 }
 for(unsigned at=1;at<=6;at++){
  Fresh(&m,&c,&p);m.FailWrite=at;assert(!Consume(&m,&c,&p)&&(c.Code||c.RestoreError));Check(&m,&c);count++;
  Fresh(&m,&c,&p);m.AmbiguousWrite=at;assert(!Consume(&m,&c,&p)&&c.Code==3&&c.Restored);Check(&m,&c);count++;
 }
 Fresh(&m,&c,&p);assert(Consume(&m,&c,&p));unsigned checks=m.AvailableCalls;
 for(unsigned at=1;at<=checks;at++){
  Fresh(&m,&c,&p);m.RemoveAt=at;assert(!Consume(&m,&c,&p)&&m.Removed&&!c.Restored);Check(&m,&c);count++;
 }
 Fresh(&m,&c,&p);m.Reg[0]^=1;assert(!Consume(&m,&c,&p)&&p.Code==1&&!EngineReads&&!m.Writes);count++;
 Fresh(&m,&c,&p);assert(Consume(&m,&c,&p));unsigned calls=m.Calls;assert(!Consume(&m,&c,&p)&&m.Calls==calls&&EngineReads==20);count++;
 ControllerResources(a);ControllerResources(b);Put32(b[4]+4,10);Put32(b[4]+8,0xa00);Put32(b[4]+12,0xff);assert(G70ValidateControllerResources(a,b,index));count++;
 /* All 120 paired descriptor permutations preserve the four map indices. */
 for(unsigned x=0;x<5;x++)for(unsigned y=0;y<5;y++)if(y!=x)for(unsigned z=0;z<5;z++)if(z!=x&&z!=y)for(unsigned q=0;q<5;q++)if(q!=x&&q!=y&&q!=z)for(unsigned t=0;t<5;t++)if(t!=x&&t!=y&&t!=z&&t!=q){
  unsigned order[5]={x,y,z,q,t};uint8_t r[5][20],s[5][20];for(unsigned i=0;i<5;i++){memcpy(r[i],a[order[i]],20);memcpy(s[i],b[order[i]],20);}assert(G70ValidateControllerResources(r,s,index));for(unsigned i=0;i<4;i++)assert(order[index[i]]==i);count++;
 }
 /* Reject every corrupted memory-descriptor byte on either side. */
 for(unsigned side=0;side<2;side++)for(unsigned row=0;row<4;row++)for(unsigned byte=0;byte<20;byte++){
  ControllerResources(a);ControllerResources(b);(side?b:a)[row][byte]^=1;assert(!G70ValidateControllerResources(a,b,index));count++;
 }
 ControllerResources(a);ControllerResources(b);memcpy(a[3],a[0],20);memcpy(b[3],b[0],20);assert(!G70ValidateControllerResources(a,b,index));count++;
 ControllerResources(a);ControllerResources(b);Put32(b[4]+4,12);Put32(b[4]+8,0x321);Put32(b[4]+12,0x80);assert(G70ValidateControllerResources(a,b,index));count++;
 Put32(b[4]+12,0);assert(!G70ValidateControllerResources(a,b,index));count++;
 assert(!G70ValidateControllerResources(NULL,b,index)&&!G70ValidateControllerResources(a,NULL,index)&&!G70ValidateControllerResources(a,b,NULL));count++;
 printf("{\"passed\":true,\"cases\":%u,\"actual_consumer_core\":true,\"max_engine_reads\":20,\"engine_writes\":0,\"native_operations\":0}\n",count);return 0;
}
