/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "g159_core.h"
#include "g159_initial.h"
typedef struct {
 uint32_t D[8];uint8_t Tx[16384],Rx[16384];
 uint32_t Actions,FailAt,FailAfter,TxWrites,Publishes,Kicks,Reads;
 uint32_t Opened,Queries,RxSlots[G159_INTENTS],NextRemote,CurrentRemote;
 uint32_t Order,Reuse,Fragment,DoneFirst,Notify,Notified,NoInitialIntent,RequestAckLate,RemoteClose;
 uint32_t BadReply,Silent,ServiceReject,FreezeTxTail,ChannelClosed;
}MODEL;
static unsigned Cases;
static uint32_t U16(const uint8_t*b){return(uint32_t)b[0]|(uint32_t)b[1]<<8;}
static uint32_t U32(const uint8_t*b){return U16(b)|(U16(b+2)<<16);}
static void P16(uint8_t*b,uint32_t v){b[0]=(uint8_t)v;b[1]=(uint8_t)(v>>8);}
static void P32(uint8_t*b,uint32_t v){P16(b,v);P16(b+2,v>>16);}
static void H(uint8_t*b,uint32_t cmd,uint32_t cid,uint32_t p){P16(b,cmd);P16(b+2,cid);P32(b+4,p);}
static void Enqueue(MODEL*m,const uint8_t*b,uint32_t n)
{
 assert(n&&!(n&7)&&n<=2048&&((m->D[2]-m->D[3]-8)&16383)>=n);
 for(uint32_t i=0;i<n;i++)m->Rx[(m->D[3]+i)&16383]=b[i];m->D[3]=(m->D[3]+n)&16383;
}
static void ShortRx(MODEL*m,uint32_t cmd,uint32_t cid,uint32_t p){uint8_t b[8];H(b,cmd,cid,p);Enqueue(m,b,8);}
static void Intent(MODEL*m){uint8_t b[16];m->CurrentRemote=m->NextRemote++;H(b,5,8,1);P32(b+8,1024);P32(b+12,m->CurrentRemote);Enqueue(m,b,16);}
static void Payload(MODEL*m,const uint8_t*data,uint32_t n,uint32_t iid,uint32_t fragment)
{
 uint8_t b[1040]={0};uint32_t chunk=fragment?n/2:n;uint32_t bytes=(16+chunk+7)&~7u;
 H(b,9,8,iid);P32(b+8,chunk);P32(b+12,n-chunk);memcpy(b+16,data,chunk);Enqueue(m,b,bytes);
 if(chunk<n){memset(b,0,sizeof(b));H(b,12,8,iid);P32(b+8,n-chunk);memcpy(b+16,data+chunk,n-chunk);Enqueue(m,b,(16+n-chunk+7)&~7u);}
}
static uint32_t PickRx(MODEL*m){for(uint32_t i=0;i<G159_INTENTS;i++)if(m->RxSlots[i]){m->RxSlots[i]=0;return i+1;}assert(0);return 0;}
static void Reply(MODEL*m,const uint8_t*request,uint32_t n,uint32_t remote_iid)
{
 uint8_t expected[24],b[1024]={0};assert(m->Queries<G159_QUERY_COUNT);
 uint32_t index=m->Queries++,need=G159BuildQuery(index,expected);assert(need==n&&!memcmp(request,expected,n));
 const G159_QUERY*q=G159QuerySpec(index);P32(b,0x800a);P32(b+4,1);P32(b+8,q->Opcode);
 if(index==0){P32(b+12,0);P32(b+16,20000);P32(b+20,18000);P32(b+28,3900);P32(b+40,100);}
 else if(index==1){P32(b+12,2);P32(b+16,9000);P32(b+20,6000);P32(b+24,3888);P32(b+28,5);P32(b+32,2);P32(b+36,2785);P32(b+40,1500);}
 else if(index==3)P32(b+12,4);
 else{P32(b+12,q->Property);P32(b+16,123456+index);if(m->ServiceReject&&index>=8)P32(b+20,5);}
 if(m->BadReply==1&&index==0)b[4]=2;
 if(m->BadReply==2&&index==0)P32(b+732,1);
 if(m->DoneFirst)ShortRx(m,m->Reuse?14:6,8,remote_iid);
 if(!m->Silent)Payload(m,b,q->ReplyBytes,PickRx(m),m->Fragment);
 if(!m->DoneFirst)ShortRx(m,m->Reuse?14:6,8,remote_iid);
 if(!m->Reuse)Intent(m);
}
static int FailNow(MODEL*m){m->Actions++;return m->Actions==m->FailAt;}
static int Desc(void*c,uint32_t d[8]){MODEL*m=c;m->Reads++;memcpy(d,m->D,32);return 1;}
static int ReadRx(void*c,uint32_t at,uint8_t*b,uint32_t n){MODEL*m=c;assert(at<16384&&n<=2048);for(uint32_t i=0;i<n;i++)b[i]=m->Rx[(at+i)&16383];return 1;}
static int WriteTx(void*c,uint32_t at,const uint8_t*b,uint32_t n)
{MODEL*m=c;int fail=FailNow(m);assert(at<16384&&!(at&7)&&G159ValidateTx(b,n));if(fail&&!m->FailAfter)return 0;for(uint32_t i=0;i<n;i++)m->Tx[(at+i)&16383]=b[i];m->TxWrites++;return !fail;}
static int Publish(void*c,uint32_t word,uint32_t value)
{MODEL*m=c;int fail=FailNow(m);assert((word==1||word==2)&&value<16384&&!(value&7));if(fail&&!m->FailAfter)return 0;m->D[word]=value;m->Publishes++;return !fail;}
static void Barrier(void*c){(void)c;}
static int Kick(void*c)
{
 MODEL*m=c;int fail=FailNow(m);if(fail&&!m->FailAfter)return 0;m->Kicks++;
 uint32_t cursor=m->D[0];
 while(cursor!=m->D[1]){
  uint8_t b[2048];for(unsigned i=0;i<8;i++)b[i]=m->Tx[(cursor+i)&16383];uint32_t cmd=U16(b),cid=U16(b+2),p=U32(b+4),n=8;
  if(cmd==2)n=32;else if(cmd==5)n=8+8*p;else if(cmd==9){for(unsigned i=8;i<16;i++)b[i]=m->Tx[(cursor+i)&16383];n=16+U32(b+8);}
  assert(n<=2048);for(uint32_t i=8;i<n;i++)b[i]=m->Tx[(cursor+i)&16383];assert(G159ValidateTx(b,n));
  if(cmd==2){assert(cid==1&&!m->Opened);m->Opened=1;
   if(m->Order&&!m->NoInitialIntent)Intent(m);ShortRx(m,4,1,0);if(!m->Order&&!m->NoInitialIntent)Intent(m);
  }else if(cmd==5){
   for(uint32_t i=0;i<p;i++){uint32_t iid=U32(b+12+8*i);assert(iid>=1&&iid<=G159_INTENTS);m->RxSlots[iid-1]=1;}
   if(m->Notify&&!m->Notified){uint8_t notification[16]={0};P32(notification,0x800a);P32(notification+4,2);P32(notification+8,7);P32(notification+12,0x81);Payload(m,notification,16,PickRx(m),0);m->Notified=1;}
  }else if(cmd==7){if(m->RequestAckLate){Intent(m);ShortRx(m,8,8,1);}else{ShortRx(m,8,8,1);Intent(m);}}
  else if(cmd==9)Reply(m,b+16,U32(b+8),p);
  else if(cmd==3){m->ChannelClosed=1;ShortRx(m,11,1,0);if(m->RemoteClose)ShortRx(m,3,8,0);}
  cursor=(cursor+n)&16383;
 }
 if(!m->FreezeTxTail)m->D[0]=cursor;
 return !fail;
}
static G159_IO Io(MODEL*m){G159_IO io={Desc,ReadRx,WriteTx,Publish,Barrier,Kick,m};return io;}
static MODEL*Create(void)
{
 MODEL*m=calloc(1,sizeof(*m));assert(m);m->D[0]=m->D[1]=m->D[2]=16;m->D[3]=256;memcpy(m->Rx+16,G159InitialOpenBytes,240);return m;
}
static int Run(G159_STATE*s,G159_IO*io,unsigned limit)
{int result=G159_WAIT;for(unsigned i=0;i<limit&&result==G159_WAIT;i++)result=G159Step(s,io);return result;}
static void Frozen(G159_STATE*s,G159_IO*io,MODEL*m)
{unsigned actions=m->Actions,reads=m->Reads;G159_STATE*before=malloc(sizeof(*s));assert(before);memcpy(before,s,sizeof(*s));assert(G159Step(s,io)==G159_REFUSED&&actions==m->Actions&&reads==m->Reads&&!memcmp(before,s,sizeof(*s)));free(before);}
int main(void)
{
 unsigned maxActions=0;
 for(unsigned variant=0;variant<32;variant++){
  MODEL*m=Create();G159_STATE*s=calloc(1,sizeof(*s));assert(s);G159_IO io=Io(m);
  m->Order=variant&1;m->Reuse=(variant>>1)&1;m->Fragment=(variant>>2)&1;m->DoneFirst=(variant>>3)&1;m->RemoteClose=(variant>>4)&1;
  assert(Run(s,&io,500)==G159_COMPLETE&&s->Complete&&!s->Fault&&s->CloseAcked&&m->ChannelClosed&&m->Queries==10);
  assert(s->RepliesMask==1023&&s->Battery.WireValidMask==1023&&s->Battery.ValueValidMask==1023&&s->IgnoredOpens==8&&s->RemoteClosed==m->RemoteClose);
  assert(s->Battery.LastFullCapacity==18000&&s->Battery.DesignCapacity==20000&&s->Battery.CurrentRaw==1500&&s->Battery.TemperatureRaw==2785);
  assert(s->TxFrames+s->RxFrames==s->TraceCount&&s->TxWriteAttempts==s->TxFrames&&s->CounterWriteAttempts==s->TxFrames+s->RxFrames&&s->KickAttempts==s->CounterWriteAttempts);
  unsigned actions=m->Actions,reads=m->Reads;if(!variant)maxActions=actions;assert(G159Step(s,&io)==G159_COMPLETE&&actions==m->Actions&&reads==m->Reads);free(s);free(m);Cases++;
 }
 for(unsigned variant=0;variant<8;variant++){
  MODEL*m=Create();G159_STATE*s=calloc(1,sizeof(*s));assert(s);G159_IO io=Io(m);m->NoInitialIntent=variant&1;m->RequestAckLate=(variant>>1)&1;m->Notify=(variant>>2)&1;
  assert(Run(s,&io,600)==G159_COMPLETE&&s->Complete&&m->Queries==10&&s->Unsolicited==m->Notify);free(s);free(m);Cases++;
 }
 for(unsigned bit=0;bit<8;bit++){
  MODEL*m=Create();G159_STATE*s=calloc(1,sizeof(*s));assert(s);G159_IO io=Io(m);m->D[bit]^=1;
  assert(G159Step(s,&io)==G159_REFUSED&&s->Fault&&!m->Actions);Frozen(s,&io,m);free(s);free(m);Cases++;
 }
 {
  MODEL*m=Create();G159_STATE*s=calloc(1,sizeof(*s));assert(s);G159_IO io=Io(m);m->Rx[33]^=1;
  assert(G159Step(s,&io)==G159_REFUSED&&s->Fault==G159_F_INITIAL&&!m->Actions);Frozen(s,&io,m);free(s);free(m);Cases++;
 }
 for(unsigned field=1;field<=2;field++){
  MODEL*m=Create();G159_STATE*s=calloc(1,sizeof(*s));assert(s);G159_IO io=Io(m);assert(G159Step(s,&io)==G159_WAIT);m->D[field]+=8;
  unsigned actions=m->Actions;assert(G159Step(s,&io)==G159_REFUSED&&s->Fault==G159_F_OWNER&&actions==m->Actions);Frozen(s,&io,m);free(s);free(m);Cases++;
 }
 for(unsigned after=0;after<2;after++)for(unsigned action=1;action<=maxActions;action++){
  MODEL*m=Create();G159_STATE*s=calloc(1,sizeof(*s));assert(s);G159_IO io=Io(m);m->FailAt=action;m->FailAfter=after;
  assert(Run(s,&io,600)==G159_REFUSED&&s->Fault==G159_F_IO&&m->Actions==action);Frozen(s,&io,m);free(s);free(m);Cases++;
 }
 {
  MODEL*m=Create();G159_STATE*s=calloc(1,sizeof(*s));assert(s);G159_IO io=Io(m);m->ServiceReject=1;
  assert(Run(s,&io,500)==G159_COMPLETE&&s->Battery.WireValidMask==1023&&s->Battery.ServiceRejectedMask==768&&s->Battery.ValueValidMask==255);free(s);free(m);Cases++;
 }
 for(unsigned malformed=1;malformed<=2;malformed++){
  MODEL*m=Create();G159_STATE*s=calloc(1,sizeof(*s));assert(s);G159_IO io=Io(m);m->BadReply=malformed;m->RemoteClose=1;
  if(malformed==1){/* Wrong message type is unmatched, not a false reply. */assert(Run(s,&io,150)==G159_WAIT&&!s->RepliesMask&&s->Unsolicited==1);s->Fault=G159_F_TIMEOUT;s->Closing=1;}
  int result=Run(s,&io,150);assert(result==G159_REFUSED&&!s->Complete&&s->CloseAcked&&m->ChannelClosed);free(s);free(m);Cases++;
 }
 printf("{\"passed\":true,\"cases\":%u,\"native_operations\":0}\n",Cases);return 0;
}
