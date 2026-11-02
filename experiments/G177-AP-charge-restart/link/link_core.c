/* SPDX-License-Identifier: MIT */
#include "link_core.h"
#include <string.h>
#define LCID 1u
static const uint8_t ChargerName[19]="PMIC_RTR_ADSP_APPS";
static uint32_t U16(const uint8_t *p){return(uint32_t)p[0]|(uint32_t)p[1]<<8;}
static uint32_t U32(const uint8_t *p){return U16(p)|(U16(p+2)<<16);}
static void P16(uint8_t *p,uint32_t v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
static void P32(uint8_t *p,uint32_t v){P16(p,v);P16(p+2,v>>16);}
static void Header(uint8_t *p,uint32_t cmd,uint32_t cid,uint32_t value)
{P16(p,cmd);P16(p+2,cid);P32(p+4,value);}
static int HardFail(CL_STATE *s,uint32_t fault,int uncertain)
{if(!s->Fault)s->Fault=fault;s->TransportUncertain|=(uint32_t)uncertain;s->Phase=CL_FAILED;return CL_POLL_FAULT;}
static CL_LOCAL_INTENT *Local(CL_STATE *s,uint32_t id)
{for(unsigned i=0;i<CL_INTENTS;i++)if(s->Local[i].State&&s->Local[i].Id==id)return s->Local+i;return 0;}
static int OtherIndex(const CL_STATE *s,uint32_t cid)
{for(unsigned i=0;i<CL_OTHER_PORTS;i++)if(s->Other[i].Present&&s->Other[i].Cid==cid)return(int)i;return-1;}
static int IsRemote(const CL_STATE *s,uint32_t cid)
{return s->RemoteOpen&&cid==s->RemoteCid;}
void ClInitialize(CL_STATE *s)
{if(s){memset(s,0,sizeof(*s));s->NextLocalId=1;s->TraceNext=1;}}
static int TimeValid(CL_STATE *s,uint64_t now)
{if(now<s->LastNowUs)return HardFail(s,CL_F_CLOCK,1);s->LastNowUs=now;return 1;}
static void Closing(CL_STATE *,uint64_t,uint32_t);
static int BeginBatch(CL_STATE *s,uint64_t now,uint32_t kind)
{
 if(!s)return-1;
 if(s->Phase==CL_FAILED)return-1;
 if(TimeValid(s,now)<0)return-1;
 if(s->Phase!=CL_READY||s->BatchActive||s->CloseRequested)return 0;
 if(kind>2||(kind==1&&s->BoardFvAttempted)||
   (kind==2&&(s->PulseAttempted||!s->BoardFvAcked)))return 0;
 if(kind==2&&now>UINT64_MAX-CL_PULSE_BATCH_US)return HardFail(s,CL_F_CLOCK,0);
 if(s->BatchesStarted==UINT64_MAX)return HardFail(s,CL_F_EXHAUSTED,0);
 memset(&s->Working,0,sizeof(s->Working));
 s->Working.Generation=++s->BatchesStarted;s->Working.BeginUs=now;
 s->Working.Kind=kind;
 s->Query=s->Pending=s->ReplyReceived=s->TxDone=s->IntentRequestPending=0;
 if(kind==1){s->BoardFvAttempted=1;s->Query=CL_FV_QUERY;}
 if(kind==2){s->PulseAttempted=1;s->Query=CL_RESTART_OFF_QUERY;s->PulseUntilUs=0;s->RestartUntilUs=0;}
 s->BatchActive=1;return 1;
}
int ClRequestBatch(CL_STATE*s,uint64_t now){return BeginBatch(s,now,0);}
int ClRequestBoardFv(CL_STATE*s,uint64_t now){return BeginBatch(s,now,1);}
int ClRequestRestartPulse(CL_STATE*s,uint64_t now){return BeginBatch(s,now,2);}
int ClRequestStopPulse(CL_STATE*s,uint64_t now)
{
 if(!s||s->Phase==CL_FAILED)return-1;
 if(TimeValid(s,now)<0)return-1;
 if(s->Phase!=CL_READY||!s->BatchActive||s->Working.Kind!=2)return 0;
 s->StopPulseRequested=1;
 /* A pre-transmit stop cancels the experiment and closes this endpoint. It
  * must never send an unnecessary enable just to complete a disable pair. */
 if((s->Query==CL_RESTART_OFF_QUERY||s->Query==CL_ENABLE_QUERY)&&!s->Pending){Closing(s,now,0);return 1;}
 if(s->Query==CL_DISABLE_QUERY&&!s->Pending)s->PulseUntilUs=now;
 return 1;
}
static void Closing(CL_STATE *s,uint64_t now,uint32_t fault)
{
 (void)now;
 if(fault&&!s->Fault)s->Fault=fault;
 if(fault&&s->Pending)s->RpcUncertain=1;
 s->CloseRequested=1;
}
int ClRequestClose(CL_STATE *s,uint64_t now)
{
 if(!s)return-1;
 if(s->Phase==CL_FAILED)return-1;
 if(TimeValid(s,now)<0)return-1;
 if(s->Phase==CL_CLOSED)return 1;
 if(s->Phase==CL_NEW){s->Phase=CL_CLOSED;return 1;}
 if(s->BatchActive&&s->Working.Kind==2){
  s->CloseAfterPulse=1;ClRequestStopPulse(s,now);return 1;
 }
 Closing(s,now,0);return 1;
}
int ClTxAllowed(const CL_STATE *s,const uint8_t *b,uint32_t n)
{
 if(!s||!b||n<8||n>CL_FRAME_BYTES||(n&7))return 0;
 uint32_t cmd=U16(b),cid=U16(b+2),p=U32(b+4);
 if(cmd<=1)return s->Phase==CL_NEGOTIATING&&n==8&&cid==1&&!p;
 if(cmd==2)return s->Phase==CL_OPENING&&n==32&&cid==LCID&&p==19&&
  !memcmp(b+8,ChargerName,19)&&!memcmp(b+27,(const uint8_t[5]){0},5);
 if(cmd==4)return n==8&&IsRemote(s,cid)&&!p;
 if(cmd==11)return n==8&&!p&&(IsRemote(s,cid)||OtherIndex(s,cid)>=0);
 if(cmd==3)return n==8&&cid==LCID&&!p&&s->OpenSent;
 if(cmd==6){
  if(n!=8||cid!=LCID||!p)return 0;
  for(unsigned i=0;i<CL_INTENTS;i++)if(s->Local[i].State&&s->Local[i].Id==p)return 1;
  return 0;
 }
 if(cmd==7)return n==8&&cid==LCID&&(p==16||p==24);
 if(cmd==8)return n==8&&cid==LCID&&p<=1;
 if(cmd==5){
  if(cid!=LCID||!p||p>CL_INTENTS||n!=8+8*p)return 0;
  for(uint32_t i=0;i<p;i++){
   uint32_t id=U32(b+12+8*i);int found=0;
   if(U32(b+8+8*i)!=CL_REPLY_LIMIT||!id)return 0;
   for(uint32_t j=0;j<i;j++)if(U32(b+12+8*j)==id)return 0;
   for(unsigned j=0;j<CL_INTENTS;j++)if(s->Local[j].State==1&&s->Local[j].Id==id&&!s->Local[j].Used)found=1;
   if(!found)return 0;
  }return 1;
 }
 if(cmd==9){
  if(cid!=LCID||!s->BatchActive||!s->Pending||s->Query>=CL_QUERY_COUNT||n<32||U32(b+12))return 0;
  if(s->Working.Kind>2||
    (s->Working.Kind==0&&s->Query>=CL_GET_COUNT)||
    (s->Working.Kind==1&&(s->Query!=CL_FV_QUERY||s->BoardFvAttempted!=1))||
    (s->Working.Kind==2&&((s->Query!=CL_RESTART_OFF_QUERY&&s->Query!=CL_ENABLE_QUERY&&s->Query!=CL_DISABLE_QUERY)||!s->PulseAttempted||!s->BoardFvAcked)))return 0;
  if(s->Working.Kind==2&&s->Query==CL_ENABLE_QUERY&&
    (!s->RestartOffAcked||s->StopPulseRequested||s->LastNowUs<s->RestartUntilUs))return 0;
  uint8_t q[24];uint32_t bytes=CLBuildQuery(s->Query,q);
  return U32(b+8)==bytes&&n==16+bytes&&!memcmp(b+16,q,bytes);
 }
 return 0;
}
static void Record(CL_STATE *s,uint32_t direction,const uint8_t *b,uint32_t n,uint64_t now)
{
 CL_TRACE *t=s->Trace+(s->TraceNext-1)%CL_TRACE_SLOTS;
 memset(t,0,sizeof(*t));t->Serial=s->TraceNext++;t->TimeUs=now;
 t->Batch=s->BatchActive?s->Working.Generation:0;
 t->Direction=direction;t->Command=U16(b);t->Channel=U16(b+2);t->Parameter=U32(b+4);
 t->Bytes=n;t->TxHead=s->OwnTx;t->RxTail=s->OwnRx;t->Query=s->Query;
 memcpy(t->Frame,b,n);
 if(s->TraceCount<CL_TRACE_SLOTS)s->TraceCount++;else s->TraceOverwritten++;
 s->LastActivityUs=now;
}
static int CanSend(CL_STATE *s,uint32_t n,uint64_t now)
{
 uint32_t free=(s->LastDescriptor[0]-s->OwnTx-8)&CL_FIFO_MASK;
 if(free>=n){s->TxStallSinceUs=0;return 1;}
 if(!s->TxStallSinceUs)s->TxStallSinceUs=now;
 return 0;
}
static int Send(CL_STATE *s,const CL_IO *io,const uint8_t *b,uint32_t n,uint64_t now,int kick)
{
 if(!ClTxAllowed(s,b,n))return HardFail(s,CL_F_FRAME,0);
 s->TxWriteAttempts++;
 if(!io->WriteTx(io->Context,s->OwnTx,b,n))return HardFail(s,CL_F_IO,1);
 io->Barrier(io->Context);s->CounterWriteAttempts++;
 uint32_t next=(s->OwnTx+n)&CL_FIFO_MASK;
 if(!io->PublishHostWord(io->Context,1,next))return HardFail(s,CL_F_IO,1);
 s->OwnTx=next;s->TxFrames++;Record(s,1,b,n,now);
 if(kick){io->Barrier(io->Context);s->KickAttempts++;if(!io->Kick(io->Context))return HardFail(s,CL_F_IO,1);}
 return CL_POLL_PROGRESS;
}
static int Short(CL_STATE *s,const CL_IO *io,uint32_t cmd,uint32_t cid,uint32_t value,uint64_t now)
{uint8_t b[8];Header(b,cmd,cid,value);return Send(s,io,b,8,now,1);}
static int Consume(CL_STATE *s,const CL_IO *io,const uint8_t *b,uint32_t n,uint64_t now)
{
 io->Barrier(io->Context);s->CounterWriteAttempts++;
 uint32_t next=(s->OwnRx+n)&CL_FIFO_MASK;
 if(!io->PublishHostWord(io->Context,2,next))return HardFail(s,CL_F_IO,1);
 s->OwnRx=next;s->RxFrames++;Record(s,2,b,n,now);
 io->Barrier(io->Context);s->KickAttempts++;
 if(!io->Kick(io->Context))return HardFail(s,CL_F_IO,1);
 return CL_POLL_PROGRESS;
}
static unsigned FreeLocal(const CL_STATE *s)
{unsigned n=0;for(unsigned i=0;i<CL_INTENTS;i++)if(!s->Local[i].State)n++;return n;}
static int Advertise(CL_STATE *s,const CL_IO *io,unsigned limit,uint64_t now)
{
 uint8_t b[8+8*CL_INTENTS];unsigned count=0;
 if(limit>UINT32_MAX-s->NextLocalId)return HardFail(s,CL_F_EXHAUSTED,0);
 for(unsigned i=0;i<CL_INTENTS&&count<limit;i++)if(!s->Local[i].State){
  if(s->NextLocalId==UINT32_MAX)return HardFail(s,CL_F_EXHAUSTED,0);
  CL_LOCAL_INTENT *r=s->Local+i;memset(r,0,sizeof(*r));r->State=1;r->Id=s->NextLocalId++;
  P32(b+8+8*count,CL_REPLY_LIMIT);P32(b+12+8*count,r->Id);count++;
 }
 if(!count)return HardFail(s,CL_F_INTENT,0);
 Header(b,5,LCID,count);int rc=Send(s,io,b,8+8*count,now,1);
 if(rc>0)s->CurrentOffers+=count;
 return rc;
}
static int Partial(const CL_STATE *s)
{for(unsigned i=0;i<CL_INTENTS;i++)if(s->Local[i].State&&s->Local[i].Used)return 1;return 0;}
static void Advance(CL_STATE *s,uint64_t now)
{
 if(s->Pending&&s->ReplyReceived&&s->TxDone){
  uint32_t query=s->Query;
  s->Pending=s->ReplyReceived=s->TxDone=s->IntentRequestPending=0;s->Query++;
  if(s->Working.Kind==1)s->BoardFvAcked=s->Working.Battery.ControlAckMask==(1u<<CL_FV_QUERY);
  if(s->Working.Kind==2&&query==CL_RESTART_OFF_QUERY){
   s->RestartOffAcked=(s->Working.Battery.ControlAckMask&(1u<<CL_RESTART_OFF_QUERY))!=0;
   s->Query=CL_QUERY_COUNT; /* A rejected off must never advance to enable. */
   if(s->RestartOffAcked&&!s->StopPulseRequested){
    if(now>UINT64_MAX-CL_RESTART_GAP_US){HardFail(s,CL_F_CLOCK,0);return;}
    s->RestartUntilUs=now+CL_RESTART_GAP_US;s->Query=CL_ENABLE_QUERY;
   }else s->Working.Aborted=1;
  }
  if(s->Working.Kind==2&&query==CL_ENABLE_QUERY){
   s->Query=CL_DISABLE_QUERY;
   s->PulseEnableAcked=(s->Working.Battery.ControlAckMask&(1u<<CL_ENABLE_QUERY))!=0;
   s->PulseUntilUs=now;
   if(s->PulseEnableAcked&&!s->StopPulseRequested){
    if(now>UINT64_MAX-CL_PULSE_US){HardFail(s,CL_F_CLOCK,0);return;}
    s->PulseUntilUs=now+CL_PULSE_US;
   }
  }
  if(s->Working.Kind==2&&query==CL_DISABLE_QUERY){
   s->PulseDisableAcked=(s->Working.Battery.ControlAckMask&(1u<<CL_DISABLE_QUERY))!=0;
   s->Query=CL_QUERY_COUNT;
  }
  uint32_t end=s->Working.Kind==0?CL_GET_COUNT:s->Working.Kind==1?CL_FV_QUERY+1:CL_QUERY_COUNT;
  if(s->Query==end){
   s->Working.Complete=1;s->Working.EndUs=now;s->LastBatch=s->Working;
   s->BatchesCompleted++;s->BatchActive=0;
   if(s->CloseAfterPulse)Closing(s,now,0);
  }
 }
}
static int Progress(CL_STATE *s,const CL_IO *io,uint64_t now,int empty)
{
 Advance(s,now);
 if(s->Phase==CL_FAILED)return CL_POLL_FAULT;
 if(s->CloseRequested&&(!s->Pending||s->Fault)){
  if(s->Phase!=CL_CLOSING)s->CloseSinceUs=now;
  s->Phase=CL_CLOSING;
  if(s->BatchActive){s->Working.Aborted=1;s->Working.EndUs=now;s->BatchActive=0;}
  if(!s->OpenSent){
   if(s->LastDescriptor[0]==s->OwnTx&&empty){s->Phase=CL_CLOSED;return CL_POLL_CLOSED;}
   return CL_POLL_IDLE;
  }
  if(!s->CloseSent){
   if(!CanSend(s,8,now))return CL_POLL_IDLE;
   if(Short(s,io,3,LCID,0,now)<0)return CL_POLL_FAULT;
   s->CloseSent=1;return CL_POLL_PROGRESS;
  }
  /* An application endpoint that received our intents must also close its
   * sending half. A quiet timer alone is not permission to discard its owner. */
  if(s->CloseAcked&&(!s->RemoteOpen||s->RemoteClosed)&&s->LastDescriptor[0]==s->OwnTx&&empty&&!Partial(s)){
   if(!s->ClosedQuietUs)s->ClosedQuietUs=now;
   if(now-s->ClosedQuietUs>=CL_CLOSED_QUIET_US){s->Phase=CL_CLOSED;return CL_POLL_CLOSED;}
  }else s->ClosedQuietUs=0;
  return CL_POLL_IDLE;
 }
 if(s->Phase!=CL_READY)return CL_POLL_IDLE;
 if(s->CurrentOffers<16){
  unsigned count=16-s->CurrentOffers,free=FreeLocal(s);
  if(count>free)count=free;
  if(count){if(!CanSend(s,8+8*count,now))return CL_POLL_IDLE;return Advertise(s,io,count,now);}
 }
 if(!s->BatchActive||s->Pending)return CL_POLL_IDLE;
 if(s->Working.Kind==2&&s->Query==CL_ENABLE_QUERY&&now<s->RestartUntilUs)return CL_POLL_IDLE;
 if(s->Working.Kind==2&&s->Query==CL_DISABLE_QUERY&&now<s->PulseUntilUs)return CL_POLL_IDLE;
 /* No blind repeat after a timeout. First query starts only at a drained,
  * quiet boundary. GLINK has no firmware transaction ID; the generation is
  * local bookkeeping, not a claim of wire-level duplicate disambiguation. */
 uint32_t first=s->Working.Kind==0?0:s->Working.Kind==1?CL_FV_QUERY:CL_RESTART_OFF_QUERY;
 if(s->Query==first&&(!empty||Partial(s)||s->LastDescriptor[0]!=s->OwnTx||now-s->LastActivityUs<CL_QUIET_US))return CL_POLL_IDLE;
 uint8_t query[24];uint32_t n=CLBuildQuery(s->Query,query),selected=CL_INTENTS;
 for(unsigned i=0;i<CL_INTENTS;i++)if(s->Remote[i].State==1&&s->Remote[i].Bytes>=n&&
  (selected==CL_INTENTS||s->Remote[i].Bytes<s->Remote[selected].Bytes))selected=i;
 if(selected==CL_INTENTS){
  if(!s->IntentRequestPending){
   if(!CanSend(s,8,now))return CL_POLL_IDLE;
   if(Short(s,io,7,LCID,n,now)<0)return CL_POLL_FAULT;
   s->IntentRequestPending=1;return CL_POLL_PROGRESS;
  }return CL_POLL_IDLE;
 }
 if(!CanSend(s,16+n,now))return CL_POLL_IDLE;
 uint8_t frame[40];Header(frame,9,LCID,s->Remote[selected].Id);P32(frame+8,n);P32(frame+12,0);memcpy(frame+16,query,n);
 s->Remote[selected].State=2;s->RemoteIntentIndex=selected;s->Pending=1;s->PendingSinceUs=now;
 return Send(s,io,frame,16+n,now,1);
}
static int Data(CL_STATE *s,const CL_IO *io,const uint8_t *b,uint32_t n,uint64_t now)
{
 uint32_t id=U32(b+4),chunk=U32(b+8),left=U32(b+12),cmd=U16(b);
 CL_LOCAL_INTENT *r=Local(s,id);
 if(!IsRemote(s,U16(b+2))||!r||r->State!=1||(!chunk&&left)||chunk>CL_REPLY_LIMIT-r->Used||
  left>CL_REPLY_LIMIT-r->Used-chunk||(cmd==9?r->Used!=0:r->Used==0)||
  (r->Used&&r->Remaining!=chunk+left))return HardFail(s,CL_F_INTENT,1);
 if(!left&&!CanSend(s,8,now))return CL_POLL_IDLE;
 if(!r->Used)r->BeganUs=now;
 memcpy(r->Data+r->Used,b+16,chunk);r->Used+=chunk;r->Remaining=left;
 int bad=0;
 if(!left){
  if(r->Used>=12&&U32(r->Data)==0x800a&&U32(r->Data+4)==1){
   if(!s->Pending||s->ReplyReceived||s->Query>=CL_QUERY_COUNT||
    U32(r->Data+8)!=CLQuerySpec(s->Query)->Opcode||
    !CLDecodeReply(s->Query,r->Data,r->Used,&s->Working.Battery))bad=1;
   else{
    s->Working.ReplyBytes[s->Query]=r->Used;memcpy(s->Working.Replies[s->Query],r->Data,r->Used);
    s->ReplyReceived=1;
   }
  }else{
   s->Events++;s->EventBytes=r->Used;memset(s->LastEvent,0,sizeof(s->LastEvent));memcpy(s->LastEvent,r->Data,r->Used);
  }
  if(Short(s,io,6,LCID,id,now)<0)return CL_POLL_FAULT;
 }
 if(Consume(s,io,b,n,now)<0)return CL_POLL_FAULT;
 if(!left){memset(r,0,sizeof(*r));s->CurrentOffers--;}
 if(bad){s->RpcUncertain=1;Closing(s,now,CL_F_REPLY);}
 return CL_POLL_PROGRESS;
}
int ClPoll(CL_STATE *s,const CL_IO *io,uint64_t now)
{
 uint32_t d[8];uint8_t b[CL_FRAME_BYTES];uint32_t avail,cmd,cid,p,n=8;
 if(!s||!io||!io->ReadDescriptor||!io->ReadRx||!io->WriteTx||!io->PublishHostWord||!io->Barrier||!io->Kick)return CL_POLL_FAULT;
 if(s->Phase==CL_FAILED)return CL_POLL_FAULT;
 if(s->Phase==CL_CLOSED)return CL_POLL_CLOSED;
 if(TimeValid(s,now)<0)return CL_POLL_FAULT;
 if(s->Steps>UINT64_MAX-16||s->TraceNext>UINT64_MAX-16||s->TxFrames>UINT64_MAX-16||s->RxFrames>UINT64_MAX-16||
  s->CounterWriteAttempts>UINT64_MAX-16||s->KickAttempts>UINT64_MAX-16||s->TxWriteAttempts>UINT64_MAX-16||
  s->Events>UINT64_MAX-16||s->IgnoredOpens>UINT64_MAX-16||s->BatchesCompleted>UINT64_MAX-16)return HardFail(s,CL_F_EXHAUSTED,0);
 s->Steps++;io->Barrier(io->Context);
 if(!io->ReadDescriptor(io->Context,d))return HardFail(s,CL_F_IO,1);
 for(unsigned i=0;i<4;i++)if(d[i]>=CL_FIFO_BYTES||(d[i]&7))return HardFail(s,CL_F_DESCRIPTOR,1);
 for(unsigned i=4;i<8;i++)if(d[i])return HardFail(s,CL_F_DESCRIPTOR,1);
 if(s->Phase!=CL_NEW){
  uint32_t consumed=(d[0]-s->LastDescriptor[0])&CL_FIFO_MASK;
  uint32_t published=(s->OwnTx-s->LastDescriptor[0])&CL_FIFO_MASK;
  uint32_t produced=(d[3]-s->LastDescriptor[3])&CL_FIFO_MASK;
  uint32_t free=(s->OwnRx-s->LastDescriptor[3]-8)&CL_FIFO_MASK;
  if(consumed>published||produced>free)return HardFail(s,CL_F_OWNER,1);
 }
 memcpy(s->LastDescriptor,d,sizeof(d));
 if(s->Phase==CL_NEW){
  if(d[0]||d[1]||d[2]||d[3]!=8||s->OwnTx||s->OwnRx||s->TxWriteAttempts||
   s->CounterWriteAttempts||s->KickAttempts||s->TraceNext!=1||s->NextLocalId!=1)return HardFail(s,CL_F_INITIAL,0);
  if(!io->ReadRx(io->Context,0,b,8))return HardFail(s,CL_F_IO,0);
  if(U16(b)||U16(b+2)!=1||U32(b+4)!=7)return HardFail(s,CL_F_INITIAL,0);
  s->BeginUs=now;s->Phase=CL_NEGOTIATING;
  Header(b,0,1,0);if(Send(s,io,b,8,now,0)<0)return CL_POLL_FAULT;s->VersionSent=1;
  Header(b,1,1,0);if(Send(s,io,b,8,now,0)<0)return CL_POLL_FAULT;s->VersionAckSent=1;
  Header(b,0,1,7);return Consume(s,io,b,8,now);
 }
 if(d[1]!=s->OwnTx||d[2]!=s->OwnRx)return HardFail(s,CL_F_OWNER,1);
 if(s->BatchActive&&s->Query>=CL_QUERY_COUNT)return HardFail(s,CL_F_FRAME,0);
 Advance(s,now);
 if(s->Phase==CL_FAILED)return CL_POLL_FAULT;
 avail=(d[3]-s->OwnRx)&CL_FIFO_MASK;
 if((s->Phase==CL_NEGOTIATING||s->Phase==CL_OPENING)&&now-s->BeginUs>CL_OPEN_US)Closing(s,now,CL_F_TIMEOUT);
 if(s->Pending&&now-s->PendingSinceUs>CL_RPC_US)Closing(s,now,CL_F_TIMEOUT);
 if(s->BatchActive){
  if(s->Working.Kind!=2){if(now-s->Working.BeginUs>CL_BATCH_US)Closing(s,now,CL_F_TIMEOUT);}
  else if(s->Query==CL_RESTART_OFF_QUERY){if(now-s->Working.BeginUs>CL_BATCH_US)Closing(s,now,CL_F_TIMEOUT);}
  else if(s->Query==CL_ENABLE_QUERY){
   if(now>=s->RestartUntilUs&&now-s->RestartUntilUs>CL_BATCH_US)Closing(s,now,CL_F_TIMEOUT);
  }
  else {
   /* A late kernel timer must still attempt normal disable after the hold.
    * Start its bounded transport window when pumping resumes, not at the
    * original hold deadline. Lost replies still remain uncertain/no retry. */
   if(!s->PulseDisableSinceUs&&now>=s->PulseUntilUs)s->PulseDisableSinceUs=now;
   if(s->PulseDisableSinceUs&&now-s->PulseDisableSinceUs>CL_BATCH_US)Closing(s,now,CL_F_TIMEOUT);
  }
 }
 if(s->TxStallSinceUs&&now-s->TxStallSinceUs>CL_RPC_US)Closing(s,now,CL_F_TIMEOUT);
 if(s->IncompleteSinceUs&&now-s->IncompleteSinceUs>CL_RPC_US)Closing(s,now,CL_F_TIMEOUT);
 for(unsigned i=0;i<CL_INTENTS;i++)if(s->Local[i].Used&&now-s->Local[i].BeganUs>CL_RPC_US)Closing(s,now,CL_F_TIMEOUT);
 if(s->Phase==CL_CLOSING&&now-s->CloseSinceUs>CL_CLOSE_US)return HardFail(s,s->Fault?s->Fault:CL_F_TIMEOUT,1);
 if(s->CloseRequested){int rc=Progress(s,io,now,!avail);if(rc!=CL_POLL_IDLE)return rc;}
 if(s->Phase==CL_NEGOTIATING&&s->VersionAckSeen&&s->VersionAckSent&&d[0]==s->OwnTx)s->Phase=CL_OPENING;
 if(!avail)return Progress(s,io,now,1);
 if(avail<8)return HardFail(s,CL_F_FRAME,1);
 if(!io->ReadRx(io->Context,s->OwnRx,b,8))return HardFail(s,CL_F_IO,1);
 cmd=U16(b);cid=U16(b+2);p=U32(b+4);
 if(s->Phase==CL_NEGOTIATING){
  if(cmd>1){if(s->VersionAckSeen)return CL_POLL_IDLE;return HardFail(s,CL_F_FRAME,1);}
  if(cid!=1||(cmd==1?p!=0:(p!=0&&p!=7)))return HardFail(s,CL_F_FRAME,1);
  if(!cmd){if(!CanSend(s,8,now))return CL_POLL_IDLE;if(Short(s,io,1,1,0,now)<0)return CL_POLL_FAULT;}
  else s->VersionAckSeen=1;
  return Consume(s,io,b,8,now);
 }
 if(cmd<=1)return HardFail(s,CL_F_PEER_RESTART,1);
 if(cmd==2){if(!cid||!p||p>128)return HardFail(s,CL_F_FRAME,1);n=(8+p+7)&~7u;}
 else if(cmd==5){if(!p||p>CL_INTENTS)return HardFail(s,CL_F_INTENT,1);n=8+8*p;}
 else if(cmd==9||cmd==12){
  if(avail<16){if(!s->IncompleteSinceUs)s->IncompleteSinceUs=now;return CL_POLL_IDLE;}
  if(!io->ReadRx(io->Context,s->OwnRx,b,16))return HardFail(s,CL_F_IO,1);
  uint32_t chunk=U32(b+8);if(chunk>CL_REPLY_LIMIT)return HardFail(s,CL_F_FRAME,1);n=(16+chunk+7)&~7u;
 }
 if(n>CL_FRAME_BYTES)return HardFail(s,CL_F_FRAME,1);
 if(avail<n){if(!s->IncompleteSinceUs)s->IncompleteSinceUs=now;return CL_POLL_IDLE;}
 s->IncompleteSinceUs=0;
 if(!io->ReadRx(io->Context,s->OwnRx,b,n))return HardFail(s,CL_F_IO,1);
 if(cmd==2){
  if(b[8+p-1])return HardFail(s,CL_F_CHANNEL,1);
  for(uint32_t i=0;i+1<p;i++)if(!b[8+i])return HardFail(s,CL_F_CHANNEL,1);
  if(p==19&&!memcmp(b+8,ChargerName,19)){
   if(s->RemoteOpen||OtherIndex(s,cid)>=0||s->Phase!=CL_OPENING)return HardFail(s,CL_F_CHANNEL,1);
   if(!CanSend(s,40,now))return CL_POLL_IDLE;
   s->RemoteOpen=1;s->RemoteCid=cid;
   if(Short(s,io,4,cid,0,now)<0)return CL_POLL_FAULT;
   uint8_t open[32]={0};Header(open,2,LCID,19);memcpy(open+8,ChargerName,19);
   if(Send(s,io,open,32,now,1)<0)return CL_POLL_FAULT;s->OpenSent=1;
  }else{
   if(IsRemote(s,cid))return HardFail(s,CL_F_CHANNEL,1);
   int slot=OtherIndex(s,cid);
   if(slot>=0){if(s->Other[slot].NameBytes!=p||memcmp(s->Other[slot].Name,b+8,p))return HardFail(s,CL_F_CHANNEL,1);}
   else{
    for(unsigned i=0;i<CL_OTHER_PORTS;i++)if(!s->Other[i].Present){slot=(int)i;break;}
    if(slot<0)return HardFail(s,CL_F_CHANNEL,1);
    s->Other[slot].Present=1;s->Other[slot].Cid=cid;s->Other[slot].NameBytes=p;memcpy(s->Other[slot].Name,b+8,p);
   }s->IgnoredOpens++;
  }
 }else if(cmd==4){
  if(cid!=LCID||p||!s->OpenSent||s->OpenAcked)return HardFail(s,CL_F_CHANNEL,1);s->OpenAcked=1;
 }else if(cmd==5){
  if(!IsRemote(s,cid))return HardFail(s,CL_F_CHANNEL,1);
  for(uint32_t j=0;j<p;j++){
   uint32_t bytes=U32(b+8+8*j),id=U32(b+12+8*j);int slot=-1;
   if(!bytes||bytes>0x100000)return HardFail(s,CL_F_INTENT,1);
   for(uint32_t k=0;k<j;k++)if(U32(b+12+8*k)==id)return HardFail(s,CL_F_INTENT,1);
   for(unsigned i=0;i<CL_INTENTS;i++)if(s->Remote[i].State&&s->Remote[i].Id==id){slot=(int)i;break;}
   if(slot<0)for(unsigned i=0;i<CL_INTENTS;i++)if(!s->Remote[i].State){slot=(int)i;break;}
   if(slot<0||s->Remote[slot].State==2)return HardFail(s,CL_F_INTENT,1);
   s->Remote[slot]=(CL_REMOTE_INTENT){id,bytes,1};
  }s->IntentRequestPending=0;
 }else if(cmd==7){
  if(!IsRemote(s,cid))return HardFail(s,CL_F_CHANNEL,1);
  int offer=p&&p<=CL_REPLY_LIMIT&&FreeLocal(s);
  if(!CanSend(s,offer?24:8,now))return CL_POLL_IDLE;
  if(offer&&Advertise(s,io,1,now)<0)return CL_POLL_FAULT;
  if(Short(s,io,8,LCID,(uint32_t)!!offer,now)<0)return CL_POLL_FAULT;
 }else if(cmd==8){
  if(!IsRemote(s,cid)||p>1)return HardFail(s,CL_F_INTENT,1);
  if(s->IntentRequestPending==1)s->IntentRequestPending=2;
 }else if(cmd==6||cmd==14){
  unsigned i=s->RemoteIntentIndex;
  if(!IsRemote(s,cid)||!s->Pending||i>=CL_INTENTS||s->Remote[i].State!=2||s->Remote[i].Id!=p||s->TxDone)return HardFail(s,CL_F_INTENT,1);
  s->Remote[i].State=cmd==14?1:0;s->TxDone=1;
 }else if(cmd==9||cmd==12)return Data(s,io,b,n,now);
 else if(cmd==15){
  int slot=OtherIndex(s,cid);if(!IsRemote(s,cid)&&slot<0)return HardFail(s,CL_F_CHANNEL,1);
  if(slot>=0)s->Other[slot].Signals=p;
 }else if(cmd==13){if(cid||p)return HardFail(s,CL_F_FRAME,1);}
 else if(cmd==3){
  if(p||!CanSend(s,16,now))return p?HardFail(s,CL_F_FRAME,1):CL_POLL_IDLE;
  int slot=OtherIndex(s,cid);
  if(slot>=0){if(Short(s,io,11,cid,0,now)<0)return CL_POLL_FAULT;memset(s->Other+slot,0,sizeof(s->Other[slot]));}
  else{
   if(!IsRemote(s,cid)||s->RemoteClosed)return HardFail(s,CL_F_CHANNEL,1);
   if(Short(s,io,11,cid,0,now)<0)return CL_POLL_FAULT;
   s->RemoteClosed=s->RemoteCloseAcked=1;Closing(s,now,s->CloseRequested?0:CL_F_PEER_CLOSE);
  }
 }else if(cmd==11){
  if(cid!=LCID||p||!s->CloseSent||s->CloseAcked)return HardFail(s,CL_F_CHANNEL,1);s->CloseAcked=1;
 }else return HardFail(s,CL_F_FRAME,1);
 if(Consume(s,io,b,n,now)<0)return CL_POLL_FAULT;
 if(s->Phase==CL_OPENING&&s->RemoteOpen&&s->OpenAcked)s->Phase=CL_READY;
 return CL_POLL_PROGRESS;
}
