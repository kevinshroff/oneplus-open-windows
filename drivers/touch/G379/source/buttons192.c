/* SPDX-License-Identifier: MIT */
#include "buttons192.h"
#include <string.h>
static uint32_t U32(const uint8_t*p){return(uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static uint64_t U64(const uint8_t*p){return U32(p)|(uint64_t)U32(p+4)<<32;}
static int Trace(const uint8_t*t,uint32_t target,uint32_t offset,uint32_t length,const uint8_t*data)
{
 if(U32(t)!=target||U32(t+4)!=offset||U32(t+8)!=length||U32(t+12)!=63||
    (!(U32(t+20)&1)&&U32(t+16))||(U32(t+24)&15)!=1||U32(t+36))return 0;
 return memcmp(t+28,data,length)==0;
}
uint32_t B192ValidateCapture(const uint8_t*b,size_t n,uint64_t nonce,B192_CAPTURE*out)
{
 static const uint8_t ids[4][8]={{0x21,0,1,2,0x51,0x4a,1,0},{0,2,0,1,1,8,0,0},
  {0,2,0,1,1,9,0,0},{0,3,0,1,0x10,0x13,0,0}};
 static const uint8_t gpio[8]={0,1,0,0,0,1,0x80,0};
 const uint8_t*r,*trace;uint32_t count,commands,reads,polls;uint64_t begin,end,last;
 if(out)memset(out,0,sizeof(*out));
 if(!b||!out||!nonce)return B192_ARGUMENT;
 if(n!=B192_CAPTURE_BYTES||U32(b)!=80||U32(b+4)!=1||memcmp(b+8,"OG99KEY1",8))return B192_ABI;
 if(U32(b+16)!=26300||U32(b+20)!=8||U32(b+24)||U32(b+28)!=576||U32(b+32)!=1||
    U32(b+36)||U32(b+40)!=5||U32(b+44)!=1||U32(b+48)!=1||U32(b+52)||
    !U64(b+64)||U64(b+64)>UINT64_C(1000000000)||!U64(b+72))return B192_PLATFORM;
 if(U64(b+80)!=nonce)return B192_NONCE;
 r=b+104;count=U32(r+32);commands=6+3*count;reads=U32(r+12);polls=U32(r+24);
 if(U32(r)!=139616||!count||count>B192_MAX_SAMPLES||U32(b+88)!=count||U32(r+4)||U32(r+8)||
    U32(r+16)!=commands||U32(r+20)!=commands||U32(r+28)!=commands||U32(r+36)!=20||
    U32(r+40)||U32(r+44)!=1||polls<commands||polls>12*commands||reads>65000||
    reads!=18+5*commands+polls||U32(b+92)!=reads+4*commands||U32(b+96)!=commands||U32(b+100))return B192_RESULT;
 if(memcmp(r+64,ids,sizeof(ids)))return B192_IDENTITY;
 if(memcmp(r+96,gpio,8)||memcmp(r+104,gpio,8))return B192_CONFIG;
 begin=U64(r+48);end=U64(r+56);
 if(end<begin||end-begin>UINT64_C(60000000))return B192_CLOCK;
 trace=r+16496;
 for(unsigned i=0;i<4;i++)if(!Trace(trace+40*i,i,0,8,r+64+8*i))return B192_TRACE;
 if(!Trace(trace+40*4,3,0x40,8,r+96))return B192_TRACE;
 last=begin;
 for(unsigned i=0;i<count;i++){
  const uint8_t*s=r+112+16*i;uint64_t at=U64(s);
  if(at<last||at>end)return B192_CLOCK;
  for(unsigned j=0;j<5;j++)if(s[11+j])return B192_RESULT;
  for(unsigned j=0;j<3;j++)if(!Trace(trace+40*(5+3*i+j),j+1,0x10,1,s+8+j))return B192_TRACE;
  last=at;
 }
 if(!Trace(trace+40*(5+3*count),3,0x40,8,r+104))return B192_TRACE;
 /* Publish only after the complete capture validates. */
 out->Samples=out->Requested=count;out->BeginUs=begin;out->EndUs=end;
 for(unsigned i=0;i<count;i++){
  const uint8_t*s=r+112+16*i;out->Sample[i].AtUs=U64(s);
  memcpy(out->Sample[i].Raw,s+8,3);
 }
 return B192_OK;
}
uint32_t B192Levels(const uint8_t raw[3])
{
 if(!raw)return 0;
 return (raw[1]&0x80?B192_POWER:0)|(raw[1]&0x40?B192_VOLUME_UP:0)|(!(raw[2]&1)?B192_VOLUME_DOWN:0);
}
static void Reports(B192_EVENT*e)
{
 uint32_t changed=e->Down|e->Up;e->ReportCount=0;
 if(changed&B192_POWER){e->Report[e->ReportCount][0]=1;e->Report[e->ReportCount++][1]=(uint8_t)(e->Levels&1);}
 if(changed&(B192_VOLUME_UP|B192_VOLUME_DOWN)){
  e->Report[e->ReportCount][0]=2;e->Report[e->ReportCount++][1]=(uint8_t)((e->Levels>>1)&3);
 }
}
void B192StreamInit(B192_STREAM*s,uint64_t epoch)
{if(s){memset(s,0,sizeof(*s));s->Epoch=epoch;}}
static uint32_t Fault(B192_STREAM*s,uint32_t code){s->Fault=code;return code;}
uint32_t B192StreamStep(B192_STREAM*s,uint64_t epoch,uint64_t sequence,const B192_SAMPLE*sample,B192_EVENT*out)
{
 uint32_t observed,next;
 if(out)memset(out,0,sizeof(*out));
 if(!s||!sample||!out)return B192_ARGUMENT;
 if(s->Fault)return s->Fault;
 if(s->Stopped)return B192_STOPPED;
 if(!epoch||epoch!=s->Epoch||!sequence||s->LastSequence==UINT64_MAX||sequence!=s->LastSequence+1)return Fault(s,B192_SEQUENCE);
 if(s->Started&&(sample->AtUs<=s->LastUs))return Fault(s,B192_CLOCK);
 if(s->Started&&sample->AtUs-s->LastUs>B192_MAX_GAP_US)return Fault(s,B192_GAP);
 observed=B192Levels(sample->Raw);
 if(!s->Started){
  if(observed)return Fault(s,B192_HELD_START);
  s->Started=1;for(unsigned i=0;i<3;i++)s->CandidateAt[i]=sample->AtUs;
 }
 next=s->Stable;
 for(unsigned i=0;i<3;i++){
  uint32_t bit=1u<<i;
  if((observed&bit)!=(s->Candidate&bit))s->CandidateAt[i]=sample->AtUs;
  if((observed&bit)!=(next&bit)&&sample->AtUs-s->CandidateAt[i]>=B192_DEBOUNCE_US)next^=bit;
 }
 out->Sequence=sequence;out->AtUs=sample->AtUs;out->Levels=next;
 out->Down=next&~s->Stable;out->Up=s->Stable&~next;Reports(out);
 s->Stable=next;s->Candidate=observed;s->LastSequence=sequence;s->LastUs=sample->AtUs;
 return B192_OK;
}
void B192StreamStop(B192_STREAM*s,B192_EVENT*out)
{
 if(out)memset(out,0,sizeof(*out));
 if(!s||!out||s->Stopped)return;
 out->Sequence=s->LastSequence;out->AtUs=s->LastUs;out->Up=s->Stable;Reports(out);
 s->Stable=0;s->Stopped=1;
}
/* Separate System Control and Consumer Control top-level collections. Power
 * is System Power Down(0x01/0x81), never Consumer Power(0x0c/0x30).
 * Candidate descriptor only: no VHF device is created by this source. */
const uint8_t B192Descriptor[]={
 0x05,0x01,0x09,0x80,0xa1,0x01,0x85,0x01,
 0x15,0x00,0x25,0x01,0x75,0x01,0x95,0x01,
 0x09,0x81,0x81,0x02,0x95,0x07,0x81,0x03,0xc0,
 0x05,0x0c,0x09,0x01,0xa1,0x01,0x85,0x02,
 0x15,0x00,0x25,0x01,0x75,0x01,0x95,0x02,
 0x09,0xe9,0x09,0xea,0x81,0x02,0x95,0x06,0x81,0x03,0xc0
};
const uint32_t B192DescriptorBytes=sizeof(B192Descriptor);
int B192NativeAdmission(void){return 0;}
