/* SPDX-License-Identifier: MIT */
#include "g70_consumer.h"
const uint32_t G70MapBase[4]={0x118000,0x123000,0x152000,0xa90000};
const uint32_t G70MapBytes[4]={0x1000,0x1000,0x1000,0x4000};
/* Status reads never include RX data, IRQ clear, command, reset or SPMI. */
const uint32_t G70EngineOffset[10]={0x40,0x64,0x68,0x6c,0xe24,0xe28,0x610,0x640,0x800,0x804};
const uint32_t G70EngineExpected[10]={0,0,0x102,0x102,0x20102864,0x20104800,0,0,0,0};
static uint32_t U32(const uint8_t*p){return(uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
int G70ValidateControllerResources(const uint8_t raw[5][20],const uint8_t tr[5][20],uint32_t index[4])
{
 uint32_t mask=0,irq=0,i,j;
 if(!raw||!tr||!index)return 0;
 for(i=0;i<5;i++){
  const uint8_t*a=raw[i],*b=tr[i];
  if(a[1]!=1||b[1]!=1||a[2]||a[3]||b[2]||b[3])return 0;
  if(a[0]==2){
   /* Raw GSI389 is source-bound. Accept framework translation without a fixed
    * vector, level or affinity; this probe does not register or service IRQs. */
   if(irq++||b[0]!=2||U32(a+4)!=389||U32(a+8)!=389||U32(a+12)!=0xffffffffu||U32(a+16))return 0;
   if(!U32(b+8)||(!U32(b+12)&&!U32(b+16)))return 0;
   continue;
  }
  if(a[0]!=3||b[0]!=3||U32(a+8)||U32(b+8)||U32(a+16)||U32(b+16)||U32(a+4)!=U32(b+4))return 0;
  for(j=0;j<4&&U32(a+4)!=G70MapBase[j];j++){}
  if(j==4||(mask&(1u<<j))||U32(a+12)!=G70MapBytes[j]||U32(b+12)!=G70MapBytes[j])return 0;
  index[j]=i;mask|=1u<<j;
 }
 return mask==15&&irq==1;
}
int G70Consume(const G70_CONSUMER_IO*io,G70_CLOCK_RESULT*c,G70_PROBE_RESULT*p,uint64_t nonce)
{
 uint32_t pass,i,*out;int acquired;
 if(!io||!c||!p||!io->ReadEngine||!nonce||p->Code||p->ReadCount||p->CompletePasses||p->IdentityMatch||p->Stable||p->Reserved)return 0;
 /* ClockAcquire refuses a reused result. The driver also limits the attempt
  * across D0 and release/prepare transitions, independent of file handles. */
 acquired=G70ClockAcquire(&io->Clock,c,nonce);
 if(!acquired){p->Code=1;return 0;}
 for(pass=0;pass<2;pass++){
  out=pass?p->Second:p->First;
  for(i=0;i<10;i++){
   if(!c->Active||c->Phase!=4||!io->Clock.Available(io->Clock.Context)){p->Code=2;goto release;}
   p->ReadCount++;
   if(!io->ReadEngine(io->Clock.Context,i,&out[i])){p->Code=2;goto release;}
   if(out[i]!=G70EngineExpected[i]){p->Code=3;goto release;}
  }
  p->CompletePasses++;
 }
 p->IdentityMatch=1;p->Stable=1;
 release:
 if(!G70ClockRelease(&io->Clock,c,nonce)&&!p->Code)p->Code=4;
 return !p->Code&&!c->Code&&!c->RestoreError&&c->Restored&&!c->DirtyMask&&!c->Active;
}
