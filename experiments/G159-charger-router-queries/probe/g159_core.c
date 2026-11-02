/* SPDX-License-Identifier: MIT */
#include "g159_core.h"
#include "g159_initial.h"
#define LCID 1u
#define RCID 8u
static const uint8_t Name[19]="PMIC_RTR_ADSP_APPS";
static uint32_t U16(const uint8_t*b){return(uint32_t)b[0]|(uint32_t)b[1]<<8;}
static uint32_t U32(const uint8_t*b){return U16(b)|(U16(b+2)<<16);}
static void P16(uint8_t*b,uint32_t v){b[0]=(uint8_t)v;b[1]=(uint8_t)(v>>8);}
static void P32(uint8_t*b,uint32_t v){P16(b,v);P16(b+2,v>>16);}
static int Equal(const uint8_t*a,const uint8_t*b,uint32_t n){for(uint32_t i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1;}
static int Fail(G159_STATE*s,uint32_t fault){if(!s->Fault)s->Fault=fault;s->Terminal=1;return G159_REFUSED;}
static void Header(uint8_t*b,uint32_t cmd,uint32_t cid,uint32_t param){P16(b,cmd);P16(b+2,cid);P32(b+4,param);}
int G159ValidateTx(const uint8_t*b,uint32_t n)
{
 if(!b||n<8||n>G159_FRAME_BYTES||(n&7))return 0;
 uint32_t cmd=U16(b),cid=U16(b+2),p=U32(b+4);
 if(cmd==2){
  if(n!=32||cid!=LCID||p!=19||!Equal(b+8,Name,19))return 0;
  for(uint32_t i=27;i<32;i++)if(b[i])return 0;return 1;
 }
 if(cmd==4||cmd==11)return n==8&&cid==RCID&&!p;
 if(cmd==3)return n==8&&cid==LCID&&!p;
 if(cmd==6)return n==8&&cid==LCID&&p>=1&&p<=G159_INTENTS;
 if(cmd==8)return n==8&&cid==LCID&&p<=1;
 if(cmd==7)return n==8&&cid==LCID&&(p==16||p==24);
 if(cmd==5){
  if(cid!=LCID||!p||p>G159_INTENTS||n!=8+8*p)return 0;
  for(uint32_t i=0;i<p;i++){
   uint32_t id=U32(b+12+8*i);if(U32(b+8+8*i)!=G159_REPLY_LIMIT||id<1||id>G159_INTENTS)return 0;
   for(uint32_t j=0;j<i;j++)if(U32(b+12+8*j)==id)return 0;
  }return 1;
 }
 if(cmd==9){
  if(cid!=LCID||n<32||U32(b+12))return 0;
  uint8_t query[24];uint32_t bytes=U32(b+8);
  for(uint32_t i=0;i<G159_QUERY_COUNT;i++){
   uint32_t q=G159BuildQuery(i,query);
   if(bytes==q&&n==16+q&&Equal(b+16,query,q))return 1;
  }
 }
 return 0;
}
static int Trace(G159_STATE*s,uint32_t dir,const uint8_t*b,uint32_t n)
{
 if(s->TraceCount>=G159_TRACE_LIMIT)return 0;
 G159_TRACE*t=s->Trace+s->TraceCount++;
 t->Direction=dir;t->Command=U16(b);t->Channel=U16(b+2);t->Parameter=U32(b+4);
 t->Bytes=n;t->TxHead=s->OwnTxHead;t->RxTail=s->OwnRxTail;t->Query=s->QueryIndex;return 1;
}
static int Send(G159_STATE*s,const G159_IO*io,const uint8_t*b,uint32_t n)
{
 if(s->TraceCount==G159_TRACE_LIMIT||s->TxFrames==96)return Fail(s,G159_F_LIMIT);
 if(!G159ValidateTx(b,n))return Fail(s,G159_F_FRAME);
 uint32_t free=(s->LastDescriptor[0]-s->OwnTxHead-8)&G159_FIFO_MASK;
 if(free<n)return Fail(s,G159_F_SPACE);
 s->TxWriteAttempts++;if(!io->WriteTx(io->Context,s->OwnTxHead,b,n))return Fail(s,G159_F_IO);
 io->Barrier(io->Context);s->CounterWriteAttempts++;
 uint32_t next=(s->OwnTxHead+n)&G159_FIFO_MASK;
 if(!io->PublishHostWord(io->Context,1,next))return Fail(s,G159_F_IO);
 s->OwnTxHead=next;s->TxFrames++;if(!Trace(s,1,b,n))return Fail(s,G159_F_LIMIT);
 io->Barrier(io->Context);s->KickAttempts++;if(!io->Kick(io->Context))return Fail(s,G159_F_IO);return G159_WAIT;
}
static int Short(G159_STATE*s,const G159_IO*io,uint32_t cmd,uint32_t cid,uint32_t p)
{uint8_t b[8];Header(b,cmd,cid,p);return Send(s,io,b,8);}
static int Consume(G159_STATE*s,const G159_IO*io,const uint8_t*b,uint32_t n)
{
 if(s->TraceCount==G159_TRACE_LIMIT||s->RxFrames==96)return Fail(s,G159_F_LIMIT);
 io->Barrier(io->Context);s->CounterWriteAttempts++;
 uint32_t next=(s->OwnRxTail+n)&G159_FIFO_MASK;
 if(!io->PublishHostWord(io->Context,2,next))return Fail(s,G159_F_IO);
 s->OwnRxTail=next;s->RxFrames++;if(!Trace(s,2,b,n))return Fail(s,G159_F_LIMIT);
 io->Barrier(io->Context);s->KickAttempts++;if(!io->Kick(io->Context))return Fail(s,G159_F_IO);return G159_WAIT;
}
static int Advertise(G159_STATE*s,const G159_IO*io,uint32_t limit)
{
 uint8_t b[8+8*G159_INTENTS];uint32_t count=0;
 for(uint32_t i=0;i<G159_INTENTS&&count<limit;i++)if(!s->Local[i].State){
  s->Local[i].State=1;P32(b+8+8*count,G159_REPLY_LIMIT);P32(b+12+8*count,i+1);count++;
 }
 if(!count)return Fail(s,G159_F_INTENT);
 Header(b,5,LCID,count);if(Send(s,io,b,8+8*count)!=G159_WAIT)return G159_REFUSED;
 s->IntentsAdvertised+=count;return G159_WAIT;
}
static int StartClose(G159_STATE*s,const G159_IO*io)
{
 s->Closing=1;
 if(s->OpenSent&&!s->CloseSent){if(Short(s,io,3,LCID,0)!=G159_WAIT)return G159_REFUSED;s->CloseSent=1;}
 return G159_WAIT;
}
static int Progress(G159_STATE*s,const G159_IO*io)
{
 if(s->Closing)return StartClose(s,io);
 if(!s->OpenAcked)return G159_WAIT;
 if(s->IntentsAdvertised<16&&Advertise(s,io,16-s->IntentsAdvertised)!=G159_WAIT)return G159_REFUSED;
 if(s->Pending&&s->ReplyReceived&&s->TxCompleted){s->Pending=0;s->ReplyReceived=0;s->TxCompleted=0;s->QueryIndex++;s->IntentRequestPending=0;}
 if(s->QueryIndex==G159_QUERY_COUNT)return StartClose(s,io);
 if(s->Pending)return G159_WAIT;
 uint8_t query[24];uint32_t n=G159BuildQuery(s->QueryIndex,query),selected=G159_INTENTS;
 for(uint32_t i=0;i<G159_INTENTS;i++)if(s->Remote[i].State==1&&s->Remote[i].Bytes>=n&&
     (selected==G159_INTENTS||s->Remote[i].Bytes<s->Remote[selected].Bytes))selected=i;
 if(selected==G159_INTENTS){
  if(!s->IntentRequestPending){if(Short(s,io,7,LCID,n)!=G159_WAIT)return G159_REFUSED;s->IntentRequestPending=1;}
  return G159_WAIT;
 }
 uint8_t b[40];Header(b,9,LCID,s->Remote[selected].Id);P32(b+8,n);P32(b+12,0);
 for(uint32_t i=0;i<n;i++)b[16+i]=query[i];
 s->Remote[selected].State=2;s->CurrentRemoteIntent=selected;s->Pending=1;
 if(Send(s,io,b,16+n)!=G159_WAIT)return G159_REFUSED;
 s->QueriesSentMask|=1u<<s->QueryIndex;return G159_WAIT;
}
static int ReceiveData(G159_STATE*s,const G159_IO*io,const uint8_t*b,uint32_t n)
{
 uint32_t iid=U32(b+4),chunk=U32(b+8),left=U32(b+12),cmd=U16(b);
 if(U16(b+2)!=RCID||iid<1||iid>G159_INTENTS||n<16||chunk>G159_REPLY_LIMIT||left>G159_REPLY_LIMIT)return Fail(s,G159_F_INTENT);
 G159_LOCAL_INTENT*r=s->Local+iid-1;
 if(r->State!=1||(!chunk&&left)||chunk>G159_REPLY_LIMIT-r->Used||left>G159_REPLY_LIMIT-r->Used-chunk||
    (cmd==9?r->Used!=0:r->Used==0)||(r->Used&&r->Remaining!=chunk+left))return Fail(s,G159_F_INTENT);
 for(uint32_t i=0;i<chunk;i++)r->Data[r->Used+i]=b[16+i];r->Used+=chunk;r->Remaining=left;
 if(!left){
  int bad=0;
  if(!s->Closing&&s->Pending&&r->Used>=12&&U32(r->Data)==0x800a&&U32(r->Data+4)==1&&
     U32(r->Data+8)==G159QuerySpec(s->QueryIndex)->Opcode){
   s->ReplyBytes[s->QueryIndex]=r->Used;
   for(uint32_t i=0;i<r->Used;i++)s->Replies[s->QueryIndex][i]=r->Data[i];
   if(s->ReplyReceived||!G159DecodeReply(s->QueryIndex,r->Data,r->Used,&s->Battery))bad=1;
   else{s->RepliesMask|=1u<<s->QueryIndex;s->ReplyReceived=1;}
  }else if(++s->Unsolicited>16)bad=1;
  r->State=2;
  if(Short(s,io,6,LCID,iid)!=G159_WAIT)return G159_REFUSED;
  if(Consume(s,io,b,n)!=G159_WAIT)return G159_REFUSED;
  if(bad){if(!s->Fault)s->Fault=G159_F_REPLY;return StartClose(s,io);}
  return G159_WAIT;
 }
 return Consume(s,io,b,n);
}
int G159Step(G159_STATE*s,const G159_IO*io)
{
 uint32_t d[8];uint8_t b[G159_FRAME_BYTES];uint32_t avail,cmd,cid,p,n=8;
 if(!s||!io||!io->ReadDescriptor||!io->ReadRx||!io->WriteTx||!io->PublishHostWord||!io->Barrier||!io->Kick)return G159_REFUSED;
 if(s->Terminal)return G159_REFUSED;
 if(s->Fault&&!s->Closing)return G159_REFUSED;
 if(s->Complete)return G159_COMPLETE;
 s->Steps++;io->Barrier(io->Context);
 if(!io->ReadDescriptor(io->Context,d))return Fail(s,G159_F_IO);
 for(uint32_t i=0;i<4;i++)if(d[i]>=G159_FIFO_BYTES||(d[i]&7))return Fail(s,G159_F_DESCRIPTOR);
 for(uint32_t i=4;i<8;i++)if(d[i])return Fail(s,G159_F_DESCRIPTOR);
 for(uint32_t i=0;i<8;i++)s->LastDescriptor[i]=d[i];
 if(!s->Started){
  if(d[0]!=16||d[1]!=16||d[2]!=16||d[3]<256||s->TxFrames||s->RxFrames||s->OwnTxHead||s->OwnRxTail)return Fail(s,G159_F_INITIAL);
  if(!io->ReadRx(io->Context,16,b,240))return Fail(s,G159_F_IO);
  if(!Equal(b,G159InitialOpenBytes,240))return Fail(s,G159_F_INITIAL);
  s->Started=1;s->OwnTxHead=16;s->OwnRxTail=16;
 }else if(d[1]!=s->OwnTxHead||d[2]!=s->OwnRxTail)return Fail(s,G159_F_OWNER);
 avail=(d[3]-s->OwnRxTail)&G159_FIFO_MASK;
 if(s->Closing&&s->CloseAcked&&d[0]==s->OwnTxHead&&!avail){
  if(s->RemoteClosed||++s->CloseQuietSteps>=5){if(s->Fault){s->Terminal=1;return G159_REFUSED;}s->Complete=1;return G159_COMPLETE;}
 }else s->CloseQuietSteps=0;
 if(!avail)return Progress(s,io);
 if(avail<8||!io->ReadRx(io->Context,s->OwnRxTail,b,8))return Fail(s,G159_F_IO);
 cmd=U16(b);cid=U16(b+2);p=U32(b+4);
 if(cmd==2){if(!p||p>128)return Fail(s,G159_F_FRAME);n=(8+p+7)&~7u;}
 else if(cmd==5){if(!p||p>G159_INTENTS)return Fail(s,G159_F_INTENT);n=8+8*p;}
 else if(cmd==9||cmd==12){
  if(avail<16)return G159_WAIT;
  if(!io->ReadRx(io->Context,s->OwnRxTail,b,16))return Fail(s,G159_F_IO);
  uint32_t chunk=U32(b+8);if(chunk>G159_REPLY_LIMIT)return Fail(s,G159_F_FRAME);n=(16+chunk+7)&~7u;
 }
 if(n>G159_FRAME_BYTES)return Fail(s,G159_F_FRAME);
 if(avail<n)return G159_WAIT;
 if(!io->ReadRx(io->Context,s->OwnRxTail,b,n))return Fail(s,G159_F_IO);
 if(cmd==2){
  if(b[8+p-1])return Fail(s,G159_F_CHANNEL);
  for(uint32_t i=0;i<p-1;i++)if(!b[8+i])return Fail(s,G159_F_CHANNEL);
  if(p==19&&Equal(b+8,Name,19)){
   if(cid!=RCID||s->RemoteOpenSeen)return Fail(s,G159_F_CHANNEL);
   s->RemoteOpenSeen=1;
   if(Short(s,io,4,RCID,0)!=G159_WAIT)return G159_REFUSED;
   uint8_t open[32]={0};Header(open,2,LCID,19);for(uint32_t i=0;i<19;i++)open[8+i]=Name[i];
   if(Send(s,io,open,32)!=G159_WAIT)return G159_REFUSED;s->OpenSent=1;
  }else if(++s->IgnoredOpens>16)return Fail(s,G159_F_LIMIT);
 }else if(cmd==4){
  if(cid!=LCID||p||!s->OpenSent||s->OpenAcked)return Fail(s,G159_F_CHANNEL);s->OpenAcked=1;
 }else if(cmd==5){
  if(cid!=RCID||!s->RemoteOpenSeen)return Fail(s,G159_F_CHANNEL);
  for(uint32_t j=0;j<p;j++){
   uint32_t bytes=U32(b+8+8*j),id=U32(b+12+8*j),slot=G159_INTENTS;
   if(!bytes||bytes>0x100000)return Fail(s,G159_F_INTENT);
   for(uint32_t k=0;k<j;k++)if(U32(b+12+8*k)==id)return Fail(s,G159_F_INTENT);
   for(uint32_t i=0;i<G159_INTENTS;i++)if(s->Remote[i].State&&s->Remote[i].Id==id){slot=i;break;}
   if(slot==G159_INTENTS)for(uint32_t i=0;i<G159_INTENTS;i++)if(!s->Remote[i].State){slot=i;break;}
   if(slot==G159_INTENTS||s->Remote[slot].State==2)return Fail(s,G159_F_INTENT);
   s->Remote[slot]=(G159_REMOTE_INTENT){id,bytes,1};
  }s->IntentRequestPending=0;
 }else if(cmd==7){
  if(cid!=RCID||!s->RemoteOpenSeen)return Fail(s,G159_F_CHANNEL);
  if(p&&p<=G159_REPLY_LIMIT){if(Advertise(s,io,1)!=G159_WAIT)return G159_REFUSED;if(Short(s,io,8,LCID,1)!=G159_WAIT)return G159_REFUSED;}
  else if(Short(s,io,8,LCID,0)!=G159_WAIT)return G159_REFUSED;
 }else if(cmd==8){
  if(cid!=RCID||p>1)return Fail(s,G159_F_INTENT);
  /* A preadvertised intent can race this response. Only INTENT, not its ACK,
   * grants a buffer; never resend a data/query request on an ACK alone. */
  if(s->IntentRequestPending==1)s->IntentRequestPending=2;
 }else if(cmd==6||cmd==14){
  if(cid!=RCID||!s->Pending||s->CurrentRemoteIntent>=G159_INTENTS||
     s->Remote[s->CurrentRemoteIntent].Id!=p||s->TxCompleted)return Fail(s,G159_F_INTENT);
  s->Remote[s->CurrentRemoteIntent].State=cmd==14?1:3;s->TxCompleted=1;
 }else if(cmd==9||cmd==12)return ReceiveData(s,io,b,n);
 else if(cmd==15){if(cid!=RCID)return Fail(s,G159_F_CHANNEL);}
 else if(cmd==13){if(cid||p)return Fail(s,G159_F_FRAME);}
 else if(cmd==3){
  if(cid!=RCID||p||s->RemoteClosed)return Fail(s,G159_F_CHANNEL);s->RemoteClosed=1;
  if(Short(s,io,11,RCID,0)!=G159_WAIT)return G159_REFUSED;s->RemoteCloseAckSent=1;
  if(s->QueryIndex<G159_QUERY_COUNT&&!s->Fault)s->Fault=G159_F_REMOTE_CLOSE;
  if(StartClose(s,io)!=G159_WAIT)return G159_REFUSED;
 }else if(cmd==11){
  if(cid!=LCID||p||!s->CloseSent||s->CloseAcked)return Fail(s,G159_F_CHANNEL);s->CloseAcked=1;
 }else return Fail(s,G159_F_FRAME);
 if(Consume(s,io,b,n)!=G159_WAIT)return G159_REFUSED;
 return Progress(s,io);
}
