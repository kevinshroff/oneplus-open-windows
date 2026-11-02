/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "link_core.h"
typedef struct {
 CL_STATE*State;uint32_t RemoteCid;uint32_t D[8];uint8_t Tx[16384],Rx[16384];
 uint32_t ReplyEpoch,VersionSeen,VersionAcked,FreezeConsumer,PeerCursor;uint64_t Now;
 uint32_t Actions,FailAt,FailAfter,TxWrites,Publishes,Kicks,Reads;
 uint32_t Opened,Queries,Gets,Sets,Enables,Disables,RejectRestartOff,RejectEnable,RejectDisable,RxSlots[CL_INTENTS],NextRemote,CurrentRemote;
 uint64_t RestartOffAt,EnabledAt,DisabledAt;
 uint32_t Order,Reuse,Fragment,DoneFirst,Notify,Notified,NoInitialIntent,RequestAckLate,RemoteClose;
 uint32_t BadReply,Silent,ServiceReject,ChannelClosed,AckOnly,ReadFailure,CloseSilent,PeerCloseSent;
 uint32_t HoldReply,HeldBytes,HeldIid;uint8_t Held[1024];
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
static void ShortRx(MODEL*m,uint32_t cmd,uint32_t cid,uint32_t p){uint8_t b[8];H(b,cmd,cid,p);Enqueue(m,b,8);if(cmd==3&&cid==m->RemoteCid)m->PeerCloseSent=1;}
static void Intent(MODEL*m){uint8_t b[16];m->CurrentRemote=m->NextRemote++;H(b,5,m->RemoteCid,1);P32(b+8,1024);P32(b+12,m->CurrentRemote);Enqueue(m,b,16);}
static void Payload(MODEL*m,const uint8_t*data,uint32_t n,uint32_t iid,uint32_t fragment)
{
 uint8_t b[1040]={0};uint32_t chunk=fragment?n/2:n;uint32_t bytes=(16+chunk+7)&~7u;
 H(b,9,m->RemoteCid,iid);P32(b+8,chunk);P32(b+12,n-chunk);memcpy(b+16,data,chunk);Enqueue(m,b,bytes);
 if(chunk<n){memset(b,0,sizeof(b));H(b,12,m->RemoteCid,iid);P32(b+8,n-chunk);memcpy(b+16,data+chunk,n-chunk);Enqueue(m,b,(16+n-chunk+7)&~7u);}
}
static uint32_t PickRx(MODEL*m){for(uint32_t i=0;i<CL_INTENTS;i++)if(m->RxSlots[i]){uint32_t id=m->RxSlots[i];m->RxSlots[i]=0;return id;}assert(0);return 0;}
static void Reply(MODEL*m,const uint8_t*request,uint32_t n,uint32_t remote_iid)
{
 uint8_t expected[24],b[1024]={0};
 uint32_t index;
 if(n==24&&U32(request+8)==0x31){
  if(U32(request+16)==8)index=CL_FV_QUERY;
  else {assert(U32(request+16)==24&&U32(request+20)<=1);index=U32(request+20)?CL_ENABLE_QUERY:(m->Enables?CL_DISABLE_QUERY:CL_RESTART_OFF_QUERY);}
  m->Sets++;
  if(index==CL_RESTART_OFF_QUERY){assert(!m->Enables&&!m->Disables);m->Disables++;m->RestartOffAt=m->Now;}
  if(index==CL_ENABLE_QUERY){assert(m->Disables==1&&!m->Enables);m->Enables++;m->EnabledAt=m->Now;}
  if(index==CL_DISABLE_QUERY){m->Disables++;m->DisabledAt=m->Now;}
 }
 else index=(m->Gets++)%CL_GET_COUNT;
 m->Queries++;uint32_t need=CLBuildQuery(index,expected);assert(need==n&&!memcmp(request,expected,n));
 const CL_QUERY*q=CLQuerySpec(index);P32(b,0x800a);P32(b+4,1);P32(b+8,q->Opcode);
 if(index==0){P32(b+12,q->Property);P32(b+16,4470+m->ReplyEpoch);}
 else if(index==1){P32(b+12,2);P32(b+16,9000);P32(b+20,6000);P32(b+24,3888);P32(b+28,5);P32(b+32,2);P32(b+36,2785);P32(b+40,1500);}
 else if(index==3)P32(b+12,4);
 else{P32(b+12,q->Property);P32(b+16,123456+index);if(m->ServiceReject&&index>=8)P32(b+20,5);}
 if((index==CL_RESTART_OFF_QUERY&&m->RejectRestartOff)||(index==CL_ENABLE_QUERY&&m->RejectEnable)||(index==CL_DISABLE_QUERY&&m->RejectDisable))P32(b+20,5);
 if(m->BadReply==1&&index==0)b[4]=2;
 if(m->BadReply==2&&index==0)P32(b+12,q->Property+1);
 if(m->DoneFirst)ShortRx(m,m->Reuse?14:6,m->RemoteCid,remote_iid);
 if(!m->Silent){uint32_t iid=PickRx(m);if(m->HoldReply){m->HeldBytes=q->ReplyBytes;m->HeldIid=iid;memcpy(m->Held,b,q->ReplyBytes);}else Payload(m,b,q->ReplyBytes,iid,m->Fragment);}
 if(!m->DoneFirst)ShortRx(m,m->Reuse?14:6,m->RemoteCid,remote_iid);
 if(!m->Reuse)Intent(m);
}
static int FailNow(MODEL*m){m->Actions++;return m->Actions==m->FailAt;}
static int Desc(void*c,uint32_t d[8]){MODEL*m=c;m->Reads++;if(m->ReadFailure)return 0;memcpy(d,m->D,32);return 1;}
static int ReadRx(void*c,uint32_t at,uint8_t*b,uint32_t n){MODEL*m=c;m->Reads++;if(m->ReadFailure)return 0;assert(at<16384&&n<=2048);for(uint32_t i=0;i<n;i++)b[i]=m->Rx[(at+i)&16383];return 1;}
static int WriteTx(void*c,uint32_t at,const uint8_t*b,uint32_t n)
{MODEL*m=c;int fail=FailNow(m);assert(at<16384&&!(at&7)&&ClTxAllowed(m->State,b,n));if(fail&&!m->FailAfter)return 0;for(uint32_t i=0;i<n;i++)m->Tx[(at+i)&16383]=b[i];m->TxWrites++;return !fail;}
static int Publish(void*c,uint32_t word,uint32_t value)
{MODEL*m=c;int fail=FailNow(m);assert((word==1||word==2)&&value<16384&&!(value&7));if(fail&&!m->FailAfter)return 0;m->D[word]=value;m->Publishes++;return !fail;}
static void Barrier(void*c){(void)c;}
static int Kick(void*c)
{
 MODEL*m=c;int fail=FailNow(m);if(fail&&!m->FailAfter)return 0;m->Kicks++;if(m->FreezeConsumer)return !fail;
 uint32_t cursor=m->D[0];
 while(cursor!=m->D[1]){
  uint8_t b[2048];for(unsigned i=0;i<8;i++)b[i]=m->Tx[(cursor+i)&16383];uint32_t cmd=U16(b),cid=U16(b+2),p=U32(b+4),n=8;
  if(cmd==2)n=32;else if(cmd==5)n=8+8*p;else if(cmd==9){for(unsigned i=8;i<16;i++)b[i]=m->Tx[(cursor+i)&16383];n=16+U32(b+8);}
  assert(n<=2048);for(uint32_t i=8;i<n;i++)b[i]=m->Tx[(cursor+i)&16383];
  if(cmd==0){assert(cid==1&&!p);m->VersionSeen=1;ShortRx(m,1,1,0);}
  else if(cmd==1){assert(cid==1&&!p&&m->VersionSeen&&!m->VersionAcked);m->VersionAcked=1;
   uint8_t open[32]={0};H(open,2,m->RemoteCid,19);memcpy(open+8,"PMIC_RTR_ADSP_APPS",19);Enqueue(m,open,32);
   uint8_t other[24]={0};H(other,2,7,10);memcpy(other+8,"AUDIO_DSP",10);Enqueue(m,other,24);
  }else if(cmd==2){assert(cid==1&&!m->Opened);m->Opened=1;
   if(m->AckOnly)ShortRx(m,4,1,0);
   else {if(m->Order&&!m->NoInitialIntent)Intent(m);ShortRx(m,4,1,0);if(!m->Order&&!m->NoInitialIntent)Intent(m);}
  }else if(cmd==5){
   for(uint32_t i=0;i<p;i++){uint32_t iid=U32(b+12+8*i),slot=CL_INTENTS;assert(iid);for(unsigned j=0;j<CL_INTENTS;j++)if(!m->RxSlots[j]){slot=j;break;}assert(slot<CL_INTENTS);m->RxSlots[slot]=iid;}
   if(m->Notify&&!m->Notified){uint8_t notification[16]={0};P32(notification,0x800a);P32(notification+4,2);P32(notification+8,7);P32(notification+12,0x81);Payload(m,notification,16,PickRx(m),0);m->Notified=1;}
  }else if(cmd==7){if(m->RequestAckLate){Intent(m);ShortRx(m,8,m->RemoteCid,1);}else{ShortRx(m,8,m->RemoteCid,1);Intent(m);}}
  else if(cmd==9)Reply(m,b+16,U32(b+8),p);
  else if(cmd==3){m->ChannelClosed=1;if(!m->CloseSilent){ShortRx(m,11,1,0);if(m->RemoteClose&&!m->PeerCloseSent)ShortRx(m,3,m->RemoteCid,0);}}
  cursor=(cursor+n)&16383;
 }
 m->D[0]=cursor;
 return !fail;
}
