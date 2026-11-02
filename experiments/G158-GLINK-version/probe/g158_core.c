/* SPDX-License-Identifier: MIT */
#include "g158_core.h"
static uint32_t U16(const uint8_t*b){return(uint32_t)b[0]|(uint32_t)b[1]<<8;}
static uint32_t U32(const uint8_t*b){return U16(b)|(U16(b+2)<<16);}
static int Fail(G158_STATE*s,uint32_t fault){s->Fault=fault;return G158_REFUSED;}
static int Trace(G158_STATE*s,uint32_t direction,uint32_t command,uint32_t features)
{
 if(s->TraceCount==G158_TRACE_LIMIT)return 0;
 G158_TRACE*t=s->Trace+s->TraceCount++;
 t->Direction=direction;t->Command=command;t->Version=1;t->Features=features;
 t->TxHead=s->OwnTxHead;t->RxTail=s->OwnRxTail;
 t->TxTail=s->LastDescriptor[0];t->RxHead=s->LastDescriptor[3];return 1;
}
static int Send(G158_STATE*s,const G158_IO*io,uint32_t command)
{
 uint8_t frame[8]={0,0,1,0,0,0,0,0};frame[0]=(uint8_t)command;
 if(s->TxFrames==G158_FRAME_LIMIT||s->TraceCount==G158_TRACE_LIMIT)return Fail(s,G158_F_LIMIT);
 uint32_t free=(s->LastDescriptor[0]-s->OwnTxHead-8u)&G158_FIFO_MASK;
 if(free<8)return Fail(s,G158_F_SPACE);
 s->TxWriteAttempts++;
 if(!io->WriteTx8(io->Context,s->OwnTxHead,frame))return Fail(s,G158_F_IO);
 io->Barrier(io->Context);s->CounterWriteAttempts++;
 uint32_t next=(s->OwnTxHead+8)&G158_FIFO_MASK;
 if(!io->PublishHostWord(io->Context,1,next))return Fail(s,G158_F_IO);
 s->OwnTxHead=next;s->TxFrames++;
 if(!Trace(s,1,command,0))return Fail(s,G158_F_LIMIT);
 return G158_WAIT;
}
static int Consume(G158_STATE*s,const G158_IO*io,uint32_t command,uint32_t features)
{
 if(s->RxFrames==G158_FRAME_LIMIT||s->TraceCount==G158_TRACE_LIMIT)return Fail(s,G158_F_LIMIT);
 io->Barrier(io->Context);s->CounterWriteAttempts++;
 uint32_t next=(s->OwnRxTail+8)&G158_FIFO_MASK;
 if(!io->PublishHostWord(io->Context,2,next))return Fail(s,G158_F_IO);
 s->OwnRxTail=next;s->RxFrames++;
 if(!Trace(s,2,command,features))return Fail(s,G158_F_LIMIT);
 io->Barrier(io->Context);s->KickAttempts++;
 if(!io->Kick(io->Context))return Fail(s,G158_F_IO);
 return G158_WAIT;
}
int G158Step(G158_STATE*s,const G158_IO*io)
{
 uint32_t d[8];uint8_t frame[8];uint32_t command,version,features,pending;
 if(!s||!io||!io->ReadDescriptor||!io->ReadRx8||!io->WriteTx8||
    !io->PublishHostWord||!io->Barrier||!io->Kick)return G158_REFUSED;
 if(s->Fault)return G158_REFUSED;
 if(s->Complete)return G158_COMPLETE;
 s->Steps++;io->Barrier(io->Context);
 if(!io->ReadDescriptor(io->Context,d))return Fail(s,G158_F_IO);
 for(uint32_t i=0;i<4;i++)if(d[i]>=G158_FIFO_BYTES||(d[i]&7))return Fail(s,G158_F_DESCRIPTOR);
 for(uint32_t i=4;i<8;i++)if(d[i])return Fail(s,G158_F_DESCRIPTOR);
 for(uint32_t i=0;i<8;i++)s->LastDescriptor[i]=d[i];
 if(!s->Started){
  /* Exact unused-host state and VERSION observed in the actual G156 capture. */
  if(s->OwnTxHead||s->OwnRxTail||s->TxFrames||s->RxFrames||
     s->CounterWriteAttempts||s->TxWriteAttempts||s->KickAttempts||
     d[0]||d[1]||d[2]||d[3]!=8)return Fail(s,G158_F_INITIAL);
 }else if(d[1]!=s->OwnTxHead||d[2]!=s->OwnRxTail)return Fail(s,G158_F_OWNER);
 pending=(d[3]-d[2])&G158_FIFO_MASK;
 if(!pending){
  if(s->Started&&s->PeerVersionAckSent&&s->LocalAckObserved&&d[0]==s->OwnTxHead){s->Complete=1;return G158_COMPLETE;}
  return G158_WAIT;
 }
 if(!io->ReadRx8(io->Context,s->OwnRxTail,frame))return Fail(s,G158_F_IO);
 command=U16(frame);version=U16(frame+2);features=U32(frame+4);
 if(!s->Started){
  if(command||version!=1||features!=7)return Fail(s,G158_F_INITIAL);
  s->Started=1;s->PeerVersionSeen=1;
  if(Send(s,io,0)!=G158_WAIT)return G158_REFUSED;
  s->LocalVersionSent=1;
  if(Send(s,io,1)!=G158_WAIT)return G158_REFUSED;
  s->PeerVersionAckSent=1;
  return Consume(s,io,command,features);
 }
 if(command>1){
  s->NextCommand=command;s->NextCommandPresent=1;
  if(s->PeerVersionAckSent&&s->LocalAckObserved&&d[0]==s->OwnTxHead){s->Complete=1;return G158_COMPLETE;}
  /* Preserve the frame for inspection. Wait only for our final ACK consumption. */
  if(s->LocalAckObserved)return G158_WAIT;
  return Fail(s,G158_F_FRAME);
 }
 if(version!=1||(command==1?features!=0:(features!=0&&features!=7)))return Fail(s,G158_F_FRAME);
 if(command==0){
  if(Send(s,io,1)!=G158_WAIT)return G158_REFUSED;
  s->PeerVersionAckSent=1;
 }else s->LocalAckObserved=1;
 return Consume(s,io,command,features);
}
