/* SPDX-License-Identifier: MIT
 * Runs the actual portable C owner against an explicit asynchronous ring peer.
 * Peer behavior and virtual time are models, not native firmware observations.
 */
#include "peer.h"
static uint64_t TotalBatches,TotalFrames;
static MODEL *Create(void)
{
 MODEL *m=calloc(1,sizeof(*m));assert(m);m->State=calloc(1,sizeof(*m->State));assert(m->State);
 ClInitialize(m->State);m->RemoteCid=8;m->RemoteClose=1;m->Now=1000;m->D[3]=8;H(m->Rx,0,1,7);return m;
}
static CL_IO Io(MODEL*m){return(CL_IO){Desc,ReadRx,WriteTx,Publish,Barrier,Kick,m};}
static int Step(MODEL*m){CL_IO io=Io(m);m->Now+=1000;return ClPoll(m->State,&io,m->Now);}
static void Destroy(MODEL*m){TotalFrames+=m->State->TxFrames+m->State->RxFrames;TotalBatches+=m->State->BatchesCompleted;free(m->State);free(m);Cases++;}
static void Open(MODEL*m)
{
 for(unsigned i=0;i<200&&m->State->Phase!=CL_READY;i++){int rc=Step(m);if(rc<0)fprintf(stderr,"open i=%u phase=%u fault=%u owned=%u/%u desc=%u/%u/%u/%u last=%u/%u/%u/%u\n",i,m->State->Phase,m->State->Fault,m->State->OwnTx,m->State->OwnRx,m->D[0],m->D[1],m->D[2],m->D[3],m->State->LastDescriptor[0],m->State->LastDescriptor[1],m->State->LastDescriptor[2],m->State->LastDescriptor[3]);assert(rc>=0);}
 assert(m->State->Phase==CL_READY&&m->State->RemoteCid==m->RemoteCid&&m->State->OpenAcked);
 for(unsigned i=0;i<40;i++)assert(Step(m)>=0);
 assert(m->State->Other[0].Present&&m->State->Other[0].Cid==7&&!m->ChannelClosed);
}
static void Batch(MODEL*m)
{
 uint64_t gen=m->State->BatchesStarted+1;assert(ClRequestBatch(m->State,m->Now)==1);
 assert(ClRequestBatch(m->State,m->Now)==0);
 for(unsigned i=0;i<1000&&m->State->BatchesCompleted<gen;i++)assert(Step(m)>=0);
 assert(m->State->LastBatch.Complete&&m->State->LastBatch.Generation==gen);
 assert(m->State->LastBatch.BeginUs<m->State->LastBatch.EndUs&&m->State->BatchesCompleted==gen);
 assert(m->State->LastBatch.Battery.WireValidMask==1023&&m->State->Phase==CL_READY&&!m->State->BatchActive);
 assert(m->State->LastBatch.Battery.VoltageMax==4470+m->ReplyEpoch);
 assert(!m->ChannelClosed&&!m->State->Fault&&!m->State->TransportUncertain);
}
static void Close(MODEL*m)
{
 assert(ClRequestClose(m->State,m->Now)==1);
 for(unsigned i=0;i<3000&&m->State->Phase!=CL_CLOSED&&m->State->Phase!=CL_FAILED;i++)Step(m);
 if(m->State->Phase!=CL_CLOSED)fprintf(stderr,"close phase=%u fault=%u ack=%u remoteClosed=%u partial=%u queries=%u\n",m->State->Phase,m->State->Fault,m->State->CloseAcked,m->State->RemoteClosed,m->State->Pending,m->Queries);
 assert(m->State->Phase==CL_CLOSED&&m->State->CloseAcked&&m->D[0]==m->D[1]&&m->D[2]==m->D[3]);
 uint32_t actions=m->Actions,reads=m->Reads;uint64_t steps=m->State->Steps;
 for(unsigned i=0;i<10;i++)assert(Step(m)==CL_POLL_CLOSED);
 assert(m->Actions==actions&&m->Reads==reads&&m->State->Steps==steps&&ClRequestBatch(m->State,m->Now)==0);
}
static void BoardFv(void)
{
 /* Independently inspect every wire byte, including the only admitted mV value.
  * Changing to microvolts or exposing another property must fail this test. */
 uint8_t want[24]={0x0a,0x80,0,0,1,0,0,0,0x31,0,0,0,0,0,0,0,8,0,0,0,0x76,0x11,0,0},got[24];
 assert(CLBuildQuery(CL_FV_QUERY,got)==24&&!memcmp(got,want,24));
 for(unsigned v=0;v<128;v++){
  MODEL*m=Create();assert(ClRequestBoardFv(m->State,m->Now)==0);
  m->Order=v&1;m->Reuse=(v>>1)&1;m->Fragment=(v>>2)&1;m->DoneFirst=(v>>3)&1;
  m->Notify=(v>>4)&1;m->NoInitialIntent=(v>>5)&1;m->RequestAckLate=(v>>6)&1;
  Open(m);Batch(m);uint64_t gen=m->State->BatchesStarted+1;
  assert(!m->Sets&&ClRequestBoardFv(m->State,m->Now)==1&&m->State->BoardFvAttempted==1);
  assert(ClRequestBoardFv(m->State,m->Now)==0&&ClRequestBatch(m->State,m->Now)==0);
  for(unsigned i=0;i<1000&&m->State->BatchesCompleted<gen;i++)assert(Step(m)>=0);
  CL_BATCH*b=&m->State->LastBatch;
  assert(b->Kind==1&&b->Complete&&b->Generation==gen&&b->Battery.WireValidMask==1024&&b->Battery.ControlAckMask==1024);
  assert(!b->Battery.ValueValidMask&&!b->Battery.VoltageMax&&m->Sets==1); /* stale word4 deliberately ignored */
  assert(U32(b->Replies[CL_FV_QUERY]+16)==123466);
  assert(ClRequestBoardFv(m->State,m->Now)==0);Batch(m);assert(m->Sets==1&&m->Gets==20);Close(m);Destroy(m);
 }
 MODEL*m=Create();Open(m);m->ServiceReject=1;assert(ClRequestBoardFv(m->State,m->Now)==1);
 for(unsigned i=0;i<1000&&!m->State->LastBatch.Complete;i++)assert(Step(m)>=0);
 assert(m->Sets==1&&m->State->LastBatch.Battery.ServiceRejectedMask==1024&&!m->State->LastBatch.Battery.ControlAckMask);
 assert(ClRequestBoardFv(m->State,m->Now)==0);Close(m);Destroy(m);
 m=Create();Open(m);m->Silent=1;assert(ClRequestBoardFv(m->State,m->Now)==1);
 for(unsigned i=0;i<5000&&m->State->Phase!=CL_CLOSED&&m->State->Phase!=CL_FAILED;i++)Step(m);
 assert(m->Sets==1&&m->State->RpcUncertain&&m->State->Fault==CL_F_TIMEOUT);
 assert(ClRequestBoardFv(m->State,m->Now)!=1);Destroy(m);
}
static void Fv(MODEL*m)
{
 uint64_t gen=m->State->BatchesStarted+1;assert(ClRequestBoardFv(m->State,m->Now)==1);
 for(unsigned i=0;i<1000&&m->State->BatchesCompleted<gen;i++)assert(Step(m)>=0);
 assert(m->State->BoardFvAcked&&m->State->LastBatch.Kind==1);
}
static void OffGap(MODEL*m)
{
 assert(ClRequestRestartPulse(m->State,m->Now)==1);
 assert(ClRequestRestartPulse(m->State,m->Now)==0&&ClRequestBatch(m->State,m->Now)==0);
 for(unsigned i=0;i<1000&&!m->State->RestartOffAcked;i++)assert(Step(m)>=0);
 assert(m->Disables==1&&!m->Enables&&m->State->Query==CL_ENABLE_QUERY&&!m->State->Pending);
 assert(m->State->RestartUntilUs>=m->Now+CL_RESTART_GAP_US-1000);
}
static void Enabled(MODEL*m)
{
 OffGap(m);uint64_t ready=m->State->RestartUntilUs;
 CL_IO io=Io(m);m->Now=ready-1;assert(ClPoll(m->State,&io,m->Now)>=0&&!m->Enables);
 m->Now=ready;
 for(unsigned i=0;i<1000&&!m->State->PulseEnableAcked;i++)assert(Step(m)>=0);
 assert(m->State->PulseEnableAcked&&m->State->BatchActive&&m->State->Query==CL_DISABLE_QUERY&&m->Disables==1);
 assert(m->EnabledAt>=ready&&m->EnabledAt-m->RestartOffAt>=CL_RESTART_GAP_US);
}
static void ChargePulse(void)
{
 uint8_t want[24]={0x0a,0x80,0,0,1,0,0,0,0x31,0,0,0,0,0,0,0,24,0,0,0,1,0,0,0},got[24];
 assert(CLBuildQuery(CL_ENABLE_QUERY,got)==24&&!memcmp(got,want,24));want[20]=0;
 assert(CLBuildQuery(CL_DISABLE_QUERY,got)==24&&!memcmp(got,want,24));
 assert(CLBuildQuery(CL_RESTART_OFF_QUERY,got)==24&&!memcmp(got,want,24));
 for(unsigned v=0;v<32;v++){
  MODEL*m=Create();assert(ClRequestRestartPulse(m->State,m->Now)==0);Open(m);assert(ClRequestRestartPulse(m->State,m->Now)==0);
  m->Reuse=v&1;m->Fragment=(v>>1)&1;m->DoneFirst=(v>>2)&1;m->NoInitialIntent=(v>>3)&1;m->RequestAckLate=(v>>4)&1;
  Fv(m);Enabled(m);uint64_t until=m->State->PulseUntilUs;assert(until>=m->Now+CL_PULSE_US-1000);
  CL_IO io=Io(m);m->Now=until-1;assert(ClPoll(m->State,&io,m->Now)>=0&&m->Disables==1);
  m->Now=until;assert(ClPoll(m->State,&io,m->Now)>=0);
  for(unsigned i=0;i<1000&&m->State->BatchesCompleted<2;i++)assert(Step(m)>=0);
  assert(m->Sets==4&&m->Enables==1&&m->Disables==2&&m->DisabledAt>=until);
  assert(m->State->RestartOffAcked&&m->State->PulseDisableAcked&&m->State->LastBatch.Kind==2&&m->State->LastBatch.Battery.ControlAckMask==14336&&!m->State->LastBatch.Battery.ValueValidMask);
  assert(ClRequestRestartPulse(m->State,m->Now)==0);Batch(m);Close(m);Destroy(m);
 }
 for(unsigned stop=0;stop<2;stop++){
  MODEL*m=Create();Open(m);Fv(m);Enabled(m);uint64_t until=m->State->PulseUntilUs;
  if(stop)assert(ClRequestClose(m->State,m->Now)==1);else assert(ClRequestStopPulse(m->State,m->Now)==1);
  for(unsigned i=0;i<1000&&!m->State->PulseDisableAcked;i++)assert(Step(m)>=0);
  assert(m->Disables==2&&m->DisabledAt<until&&m->State->PulseDisableAcked);
  Close(m);Destroy(m);
 }
 MODEL*m=Create();Open(m);Fv(m);Enabled(m);m->Now=m->State->PulseUntilUs+2*CL_BATCH_US;
 for(unsigned i=0;i<1000&&m->State->BatchActive;i++)assert(Step(m)>=0);
 assert(m->Disables==2&&m->State->PulseDisableAcked&&!m->State->Fault);Close(m);Destroy(m);
 m=Create();Open(m);Fv(m);assert(ClRequestRestartPulse(m->State,m->Now)==1);assert(ClRequestStopPulse(m->State,m->Now)==1);Close(m);assert(!m->Enables&&!m->Disables);Destroy(m);
 for(unsigned which=0;which<2;which++){
  m=Create();Open(m);Fv(m);m->RejectEnable=which==0;m->RejectDisable=which==1;
  OffGap(m);m->Now=m->State->RestartUntilUs;
  for(unsigned i=0;i<1000&&!m->State->PulseEnableAcked&&m->State->BatchesCompleted<2;i++)assert(Step(m)>=0);
  if(which){m->Now=m->State->PulseUntilUs;}
  for(unsigned i=0;i<1000&&m->State->BatchesCompleted<2;i++)assert(Step(m)>=0);
  assert(m->Enables==1&&m->Disables==2&&m->State->LastBatch.Battery.ServiceRejectedMask==(1u<<(which?CL_DISABLE_QUERY:CL_ENABLE_QUERY)));
  if(!which)assert(m->DisabledAt-m->EnabledAt<CL_RPC_US); /* no hold after rejected enable */
  Close(m);Destroy(m);
 }
 /* Cancel and delayed timer before enable must remain disabled and never emit1. */
 for(unsigned stop=0;stop<2;stop++){
  m=Create();Open(m);Fv(m);OffGap(m);
  if(stop)assert(ClRequestClose(m->State,m->Now)==1);else assert(ClRequestStopPulse(m->State,m->Now)==1);
  Close(m);assert(!m->Enables&&m->Disables==1);Destroy(m);
 }
 /* Cancellation races the reply of either the initial off or the enable.
  * In the first case enable stays unsent; in the second it must be followed
  * by off immediately after the delayed reply, without a ninety-second hold. */
 for(unsigned stage=0;stage<2;stage++)for(unsigned close=0;close<2;close++){
  m=Create();Open(m);Fv(m);
  if(stage){OffGap(m);m->Now=m->State->RestartUntilUs;}
  else assert(ClRequestRestartPulse(m->State,m->Now)==1);
  m->HoldReply=1;
  for(unsigned i=0;i<1000&&!m->HeldBytes;i++)assert(Step(m)>=0);
  assert(m->HeldBytes&&m->State->Pending&&!m->State->ReplyReceived);
  if(close)assert(ClRequestClose(m->State,m->Now)==1);else assert(ClRequestStopPulse(m->State,m->Now)==1);
  for(unsigned i=0;i<20;i++)assert(Step(m)>=0);
  assert(m->State->Pending&&m->Enables==stage&&m->Disables==1);
  m->HoldReply=0;Payload(m,m->Held,m->HeldBytes,m->HeldIid,1);
  for(unsigned i=0;i<1000&&(stage?!m->State->PulseDisableAcked:m->State->BatchActive);i++)assert(Step(m)>=0);
  assert(!m->State->Fault&&!m->State->RpcUncertain&&m->Enables==stage&&m->Disables==stage+1);
  if(stage)assert(m->DisabledAt-m->EnabledAt<CL_RPC_US);else assert(m->State->LastBatch.Aborted);
  Close(m);Destroy(m);
 }
 m=Create();Open(m);Fv(m);OffGap(m);m->Now=m->State->RestartUntilUs+CL_BATCH_US+1;
 for(unsigned i=0;i<3000&&m->State->Phase!=CL_CLOSED&&m->State->Phase!=CL_FAILED;i++)Step(m);
 assert(!m->Enables&&m->Disables==1&&m->State->Fault==CL_F_TIMEOUT);Destroy(m);
 m=Create();Open(m);Fv(m);m->RejectRestartOff=1;assert(ClRequestRestartPulse(m->State,m->Now)==1);
 for(unsigned i=0;i<1000&&m->State->BatchActive;i++)assert(Step(m)>=0);
 assert(!m->Enables&&m->Disables==1&&m->State->LastBatch.Aborted&&m->State->LastBatch.Battery.ServiceRejectedMask==8192&&!m->State->RestartOffAcked);
 Close(m);Destroy(m);
 for(unsigned which=0;which<3;which++){
  m=Create();Open(m);Fv(m);
  if(which==2){Enabled(m);m->Now=m->State->PulseUntilUs;}
  else if(which==1){OffGap(m);m->Now=m->State->RestartUntilUs;}
  else assert(ClRequestRestartPulse(m->State,m->Now)==1);
  m->Silent=1;
  for(unsigned i=0;i<5000&&m->State->Phase!=CL_CLOSED&&m->State->Phase!=CL_FAILED;i++)Step(m);
  assert(m->State->Fault==CL_F_TIMEOUT&&m->State->RpcUncertain&&m->Enables==(which!=0)&&m->Disables==(which==2?2:1));
  assert(ClRequestRestartPulse(m->State,m->Now)!=1);Destroy(m);
 }
}
static void Frozen(MODEL*m)
{
 assert(m->State->Phase==CL_FAILED);
 CL_STATE *copy=malloc(sizeof(*copy));assert(copy);*copy=*m->State;
 uint32_t actions=m->Actions,reads=m->Reads;
 for(unsigned i=0;i<10;i++)assert(Step(m)==CL_POLL_FAULT);
 assert(ClRequestBatch(m->State,m->Now)==-1&&ClRequestClose(m->State,m->Now)==-1);
 assert(m->Actions==actions&&m->Reads==reads&&!memcmp(copy,m->State,sizeof(*copy)));free(copy);
}
static void NormalLifetime(void)
{
 MODEL*m=Create();Open(m);
 for(unsigned i=0;i<1000;i++){m->ReplyEpoch=i;Batch(m);}
 assert(m->State->NextLocalId>10000&&m->State->TraceOverwritten>20000&&m->Queries==10000);
 assert(m->State->TraceCount==32&&m->State->CurrentOffers<=32);
 uint64_t frames=m->State->TxFrames+m->State->RxFrames;
 for(unsigned i=0;i<60000;i++)assert(Step(m)>=0); /* 60 seconds idle; no lifetime expiry. */
 assert(m->State->Phase==CL_READY&&frames+1>=m->State->TxFrames+m->State->RxFrames);
 m->ReplyEpoch=1001;Batch(m);Close(m);assert(!m->State->Fault);Destroy(m);
}
static void OrderVariants(void)
{
 for(unsigned v=0;v<128;v++){
  MODEL*m=Create();m->Order=v&1;m->Reuse=(v>>1)&1;m->Fragment=(v>>2)&1;m->DoneFirst=(v>>3)&1;
  m->Notify=(v>>4)&1;m->NoInitialIntent=(v>>5)&1;m->RequestAckLate=(v>>6)&1;m->RemoteClose=1;
  m->RemoteCid=(v%3==0)?65535:(v%3==1?40:8);Open(m);
  for(unsigned i=0;i<8;i++){m->ReplyEpoch=i;Batch(m);}
  assert(m->State->Events==m->Notify);Close(m);assert(!m->State->Fault);Destroy(m);
 }
 MODEL*m=Create();m->ServiceReject=1;Open(m);Batch(m);
 assert(m->State->LastBatch.Battery.ServiceRejectedMask==768&&m->State->LastBatch.Battery.ValueValidMask==255);
 assert(m->State->LastBatch.Battery.ServiceResult[8]==5&&m->State->LastBatch.ReplyBytes[8]==24);Close(m);Destroy(m);
}
static void BeforeAfterFailures(void)
{
 MODEL*b=Create();Open(b);Batch(b);Close(b);uint32_t actions=b->Actions;Destroy(b);
 for(unsigned after=0;after<2;after++)for(uint32_t at=1;at<=actions;at++){
  MODEL*m=Create();m->FailAt=at;m->FailAfter=after;unsigned requested=0,closed=0;
  for(unsigned i=0;i<2000&&m->State->Phase!=CL_FAILED;i++){
   Step(m);if(m->State->Phase==CL_FAILED)break;
   if(m->State->Phase==CL_READY&&!requested){assert(ClRequestBatch(m->State,m->Now)==1);requested=1;}
   if(m->State->BatchesCompleted&&!closed){assert(ClRequestClose(m->State,m->Now)==1);closed=1;}
  }
  assert(m->State->Fault==CL_F_IO&&m->State->TransportUncertain);Frozen(m);Destroy(m);
 }
 for(unsigned stage=0;stage<3;stage++){
  MODEL*m=Create();if(stage)Open(m);if(stage==2){m->HoldReply=1;assert(ClRequestBatch(m->State,m->Now)==1);while(!m->HeldBytes)assert(Step(m)>=0);}
  m->ReadFailure=1;assert(Step(m)<0);Frozen(m);Destroy(m);
 }
}
static void InvalidState(void)
{
 for(unsigned word=0;word<8;word++){
  MODEL*m=Create();m->D[word]=word==3?16:8;assert(Step(m)<0&&m->Actions==0);Frozen(m);Destroy(m);
 }
 for(unsigned word=0;word<8;word++){
  MODEL*m=Create();Open(m);m->D[word]=word<4?(m->D[word]+(word==0?8:word==3?16376:8))&16383:8;
  assert(Step(m)<0&&m->State->Fault);Frozen(m);Destroy(m);
 }
 MODEL*m=Create();Open(m);CL_IO io=Io(m);assert(ClPoll(m->State,&io,m->Now-1)<0&&m->State->Fault==CL_F_CLOCK);Frozen(m);Destroy(m);
 m=Create();Open(m);m->State->Steps=UINT64_MAX;assert(Step(m)<0&&m->State->Fault==CL_F_EXHAUSTED);Frozen(m);Destroy(m);
 m=Create();Open(m);m->State->CurrentOffers=0;m->State->NextLocalId=UINT32_MAX;
 assert(Step(m)<0&&m->State->Fault==CL_F_EXHAUSTED);Frozen(m);Destroy(m);
 m=Create();assert(ClRequestClose(m->State,m->Now)==1&&m->Actions==0);assert(Step(m)==CL_POLL_CLOSED);Destroy(m);
}
static void IdleTraffic(void)
{
 MODEL*m=Create();Open(m);
 for(unsigned i=0;i<10000;i++){
  uint8_t event[16];P32(event,0x800a);P32(event+4,2);P32(event+8,7);P32(event+12,i);
  Payload(m,event,16,PickRx(m),i&1);
  for(unsigned j=0;j<5;j++)assert(Step(m)>=0);
 }
 assert(m->State->Events==10000&&U32(m->State->LastEvent+12)==9999&&m->State->NextLocalId>10000);
 ShortRx(m,15,7,0xabcd);assert(Step(m)>=0&&m->State->Other[0].Signals==0xabcd);
 ShortRx(m,3,7,0);assert(Step(m)>=0&&!m->State->Other[0].Present);
 Batch(m);Close(m);Destroy(m);
}
static void Backpressure(void)
{
 MODEL*m=Create();Open(m);m->FreezeConsumer=1;
 for(unsigned i=0;i<2047;i++){
  ShortRx(m,7,m->RemoteCid,4096);assert(Step(m)>=0);
 }
 uint32_t head=m->State->OwnTx,tail=m->State->OwnRx;uint64_t writes=m->State->TxWriteAttempts;
 ShortRx(m,7,m->RemoteCid,4096);assert(Step(m)==CL_POLL_IDLE);
 assert(m->State->Phase==CL_READY&&m->State->OwnTx==head&&m->State->OwnRx==tail&&m->State->TxWriteAttempts==writes);
 m->FreezeConsumer=0;assert(Kick(m));
 for(unsigned j=0;j<5;j++)assert(Step(m)>=0);
 assert(m->State->OwnRx!=tail&&!m->State->Fault);Batch(m);Close(m);Destroy(m);
}
static void RepliesAndClose(void)
{
 MODEL*m=Create();Open(m);m->HoldReply=1;assert(ClRequestBatch(m->State,m->Now)==1);
 while(!m->HeldBytes)assert(Step(m)>=0);
 assert(ClRequestClose(m->State,m->Now)==1);
 for(unsigned i=0;i<20;i++)assert(Step(m)>=0);
 assert(!m->State->CloseSent&&m->State->Pending);
 m->HoldReply=0;Payload(m,m->Held,m->HeldBytes,m->HeldIid,1);Close(m);
 assert(!m->State->Fault&&!m->State->RpcUncertain&&m->State->Working.Aborted&&!m->State->BatchesCompleted&&m->Queries==1);Destroy(m);
 for(unsigned bad=1;bad<=2;bad++){
  m=Create();Open(m);m->BadReply=bad;assert(ClRequestBatch(m->State,m->Now)==1);
  for(unsigned i=0;i<4000&&m->State->Phase!=CL_CLOSED&&m->State->Phase!=CL_FAILED;i++)Step(m);
  assert(m->State->Phase==CL_CLOSED&&m->State->Fault==(bad==1?CL_F_TIMEOUT:CL_F_REPLY));
  assert(m->Queries==1&&m->State->RpcUncertain&&!m->State->LastBatch.Complete);Destroy(m);
 }
 m=Create();Open(m);Batch(m);
 uint8_t b[24]={0};P32(b,0x800a);P32(b+4,1);P32(b+8,0x30);P32(b+12,8);P32(b+16,4470);
 Payload(m,b,24,PickRx(m),0);for(unsigned i=0;i<200&&m->State->Phase!=CL_CLOSED;i++)assert(Step(m)>=0);
 assert(m->State->Phase==CL_CLOSED&&m->State->Fault==CL_F_REPLY&&m->Queries==10);Destroy(m);
 m=Create();Open(m);ShortRx(m,3,m->RemoteCid,0);Close(m);assert(!m->State->Fault);Destroy(m);
 m=Create();Open(m);ShortRx(m,3,m->RemoteCid,0);assert(Step(m)>0);Close(m);assert(m->State->Fault==CL_F_PEER_CLOSE);Destroy(m);
 m=Create();Open(m);m->CloseSilent=1;assert(ClRequestClose(m->State,m->Now)==1);
 for(unsigned i=0;i<3000&&m->State->Phase!=CL_FAILED;i++)Step(m);
 assert(m->State->Fault==CL_F_TIMEOUT&&m->State->TransportUncertain);Frozen(m);Destroy(m);
 m=Create();Open(m);m->RemoteClose=0;assert(ClRequestClose(m->State,m->Now)==1);
 for(unsigned i=0;i<3000&&m->State->Phase!=CL_FAILED;i++)Step(m);
 assert(m->State->CloseAcked&&!m->State->RemoteClosed&&m->State->Fault==CL_F_TIMEOUT);Frozen(m);Destroy(m);
 m=Create();Open(m);ShortRx(m,0,1,7);assert(Step(m)<0&&m->State->Fault==CL_F_PEER_RESTART);Frozen(m);Destroy(m);
}
int main(void)
{
 NormalLifetime();OrderVariants();BeforeAfterFailures();InvalidState();IdleTraffic();Backpressure();RepliesAndClose();BoardFv();ChargePulse();
 printf("{\"cases\":%u,\"completed_batches\":%llu,\"wire_frames\":%llu,\"lifetime_batches\":1000,\"idle_events\":10000,\"sanitizers\":\"address,undefined\"}\n",Cases,(unsigned long long)TotalBatches,(unsigned long long)TotalFrames);return 0;
}
