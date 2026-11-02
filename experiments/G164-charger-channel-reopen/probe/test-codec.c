/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "g164_codec.h"
#include "original-queries.h"
static unsigned Cases;
static void Put(uint8_t*b,uint32_t v){for(unsigned i=0;i<4;i++)b[i]=(uint8_t)(v>>(8*i));}
static void Reply(unsigned index,uint8_t*b)
{
 const G164_QUERY*q=G164QuerySpec(index);memset(b,0,1024);Put(b,0x800a);Put(b+4,1);Put(b+8,q->Opcode);
 if(q->RequestBytes==24){Put(b+12,q->Property);Put(b+16,123456);}
 else if(index==0){Put(b+12,0);Put(b+16,20000);Put(b+20,18000);Put(b+28,3900);Put(b+40,100);}
 else if(index==1){for(unsigned i=3;i<11;i++)Put(b+i*4,100+i);Put(b+40,0xffffff9c);}
 else Put(b+12,4);
}
int main(void)
{
 uint8_t b[1024],request[24];G164_BATTERY v={0};
 for(unsigned i=0;i<G164_QUERY_COUNT;i++){
  const G164_QUERY*q=G164QuerySpec(i);assert(q&&G164BuildQuery(i,request)==q->RequestBytes);
  assert(request[0]==10&&request[1]==0x80&&request[4]==1&&request[12]==0&&request[20]==0);Cases++;
  if(i>=1&&i<4){assert(q->RequestBytes==OriginalBytes[i]&&!memcmp(request,OriginalRequests[i],q->RequestBytes));Cases++;}
  Reply(i,b);assert(G164DecodeReply(i,b,q->ReplyBytes,&v));Cases++;
  G164_BATTERY before=v;assert(!G164DecodeReply(i,b,q->ReplyBytes,&v)&&!memcmp(&before,&v,sizeof(v)));Cases++;
  for(unsigned field=0;field<3;field++){
   G164_BATTERY x={0};Reply(i,b);b[field*4]^=0x40;assert(!G164DecodeReply(i,b,q->ReplyBytes,&x)&&!x.WireValidMask&&!x.ValueValidMask);Cases++;
  }
  for(unsigned n=0;n<q->ReplyBytes;n++){
   G164_BATTERY x={0};Reply(i,b);assert(!G164DecodeReply(i,b,n,&x)&&!x.WireValidMask);Cases++;
  }
  G164_BATTERY x={0};Reply(i,b);assert(!G164DecodeReply(i,b,q->ReplyBytes+1,&x)&&!x.WireValidMask);Cases++;
  if(q->RequestBytes==24){
   Reply(i,b);Put(b+12,q->Property+1);assert(!G164DecodeReply(i,b,q->ReplyBytes,&x)&&!x.WireValidMask);Cases++;
   Reply(i,b);Put(b+20,5);assert(G164DecodeReply(i,b,q->ReplyBytes,&x)&&x.WireValidMask==(1u<<i)&&x.ServiceRejectedMask==(1u<<i)&&!x.ValueValidMask);Cases++;
  }
 }
 assert(v.WireValidMask==1023&&v.ValueValidMask==1023&&!v.ServiceRejectedMask&&v.CurrentRaw==0xffffff9c&&v.VoltageMax==123456&&v.Reserved1==0&&v.Reserved2==0);Cases++;
 for(unsigned i=10;i<50;i++){
  memset(&v,0,sizeof(v));assert(!G164QuerySpec(i)&&!G164BuildQuery(i,request)&&!G164DecodeReply(i,b,sizeof(b),&v));Cases++;
 }
 assert(!G164DecodeReply(0,NULL,24,&v)&&!G164DecodeReply(0,b,24,NULL)&&!G164BuildQuery(0,NULL));Cases++;
 printf("{\"passed\":true,\"cases\":%u,\"native_operations\":0}\n",Cases);return 0;
}
