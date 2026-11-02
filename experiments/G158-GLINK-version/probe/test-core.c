/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "g158_core.h"
#include "native-g156.h"
typedef struct {
 uint32_t D[8],Reads,RxReads,TxWrites,Publishes,Kicks,Barriers;
 uint32_t Actions,FailAt,FailAfter,RemoteMode,AckFirst,AppendOpen;
 uint8_t Rx[G158_FIFO_BYTES],Tx[G158_FIFO_BYTES];
} MODEL;
static unsigned Cases;
static void Frame(uint8_t*b,uint32_t command,uint32_t version,uint32_t features)
{b[0]=(uint8_t)command;b[1]=(uint8_t)(command>>8);b[2]=(uint8_t)version;b[3]=(uint8_t)(version>>8);for(unsigned i=0;i<4;i++)b[4+i]=(uint8_t)(features>>(8*i));}
static uint32_t Word(const uint8_t*b){return(uint32_t)b[0]|(uint32_t)b[1]<<8;}
static void PutRx(MODEL*m,uint32_t command,uint32_t version,uint32_t features)
{
 uint8_t b[8];Frame(b,command,version,features);
 for(unsigned i=0;i<8;i++)m->Rx[(m->D[3]+i)&G158_FIFO_MASK]=b[i];
 m->D[3]=(m->D[3]+8)&G158_FIFO_MASK;
}
static int Failure(MODEL*m){m->Actions++;return m->FailAt==m->Actions;}
static int Desc(void*c,uint32_t d[8]){MODEL*m=c;m->Reads++;memcpy(d,m->D,32);return 1;}
static int Rx(void*c,uint32_t at,uint8_t b[8])
{MODEL*m=c;m->RxReads++;assert(at<G158_FIFO_BYTES&&!(at&7));for(unsigned i=0;i<8;i++)b[i]=m->Rx[(at+i)&G158_FIFO_MASK];return 1;}
static int Tx(void*c,uint32_t at,const uint8_t b[8])
{
 MODEL*m=c;int fail=Failure(m);assert(at<G158_FIFO_BYTES&&!(at&7));
 assert(Word(b)<=1&&Word(b+2)==1&&b[4]==0&&b[5]==0&&b[6]==0&&b[7]==0);
 if(fail&&!m->FailAfter)return 0;
 for(unsigned i=0;i<8;i++)m->Tx[(at+i)&G158_FIFO_MASK]=b[i];m->TxWrites++;
 return !fail;
}
static int Publish(void*c,uint32_t field,uint32_t value)
{
 MODEL*m=c;int fail=Failure(m);assert((field==1||field==2)&&value<G158_FIFO_BYTES&&!(value&7));
 if(fail&&!m->FailAfter)return 0;m->D[field]=value;m->Publishes++;return !fail;
}
static void Barrier(void*c){((MODEL*)c)->Barriers++;}
static int Kick(void*c)
{
 MODEL*m=c;int fail=Failure(m);if(fail&&!m->FailAfter)return 0;m->Kicks++;
 if(m->RemoteMode==1){
  /* Explicit peer model: original DSP firmware is not executed by these tests. */
  unsigned version=0,ack=0;
  while(m->D[0]!=m->D[1]){
   unsigned at=m->D[0],command=Word(m->Tx+at);assert(command<=1);
   version+=command==0;ack+=command==1;m->D[0]=(at+8)&G158_FIFO_MASK;
  }
  if(version){if(!m->AckFirst)PutRx(m,0,1,0);PutRx(m,1,1,0);if(m->AckFirst)PutRx(m,0,1,0);}
  else if(ack&&m->AppendOpen)PutRx(m,2,7,12);
 }
 return !fail;
}
static G158_IO Io(MODEL*m){G158_IO io={Desc,Rx,Tx,Publish,Barrier,Kick,m};return io;}
static MODEL Model(void)
{
 MODEL m;memset(&m,0,sizeof(m));memcpy(m.D,NativeDescriptor,32);memcpy(m.Rx,NativeFrame,8);return m;
}
static void Frozen(G158_STATE*s,G158_IO*io,MODEL*m)
{unsigned actions=m->Actions;G158_STATE old=*s;assert(G158Step(s,io)==G158_REFUSED);assert(actions==m->Actions);assert(!memcmp(s,&old,sizeof(old)));}
static void Success(unsigned ackFirst,unsigned open)
{
 MODEL m=Model();G158_STATE s={0};G158_IO io=Io(&m);m.RemoteMode=1;m.AckFirst=ackFirst;m.AppendOpen=open;
 int result=G158_WAIT;for(unsigned i=0;i<12&&result==G158_WAIT;i++)result=G158Step(&s,&io);
 assert(result==G158_COMPLETE&&s.Complete&&!s.Fault&&s.LocalAckObserved&&s.PeerVersionAckSent);
 assert(s.TxFrames==3&&s.RxFrames==3&&m.D[0]==24&&m.D[1]==24&&m.D[2]==24);
 assert(s.NextCommandPresent==open&&(!open||s.NextCommand==2));
 if(open){assert(m.D[3]==32);assert(Word(m.Rx+m.D[2])==2);}else assert(m.D[3]==24);
 unsigned actions=m.Actions;assert(G158Step(&s,&io)==G158_COMPLETE&&actions==m.Actions);Cases++;
}
static void InvalidDescriptor(unsigned word,uint32_t value)
{
 MODEL m=Model();G158_STATE s={0};G158_IO io=Io(&m);m.D[word]=value;
 assert(G158Step(&s,&io)==G158_REFUSED&&s.Fault&&!m.Actions);Frozen(&s,&io,&m);Cases++;
}
static void InitialFrame(unsigned offset,uint8_t value)
{
 MODEL m=Model();G158_STATE s={0};G158_IO io=Io(&m);m.Rx[offset]=value;
 assert(G158Step(&s,&io)==G158_REFUSED&&s.Fault==G158_F_INITIAL&&!m.Actions);Frozen(&s,&io,&m);Cases++;
}
int main(void)
{
 for(unsigned order=0;order<2;order++)for(unsigned open=0;open<2;open++)Success(order,open);
 for(unsigned word=0;word<8;word++){
  InvalidDescriptor(word,1);InvalidDescriptor(word,16384);
 }
 for(unsigned word=0;word<3;word++)InvalidDescriptor(word,8);
 InvalidDescriptor(3,0);InvalidDescriptor(3,16);
 for(unsigned i=0;i<8;i++)InitialFrame(i,(uint8_t)(NativeFrame[i]^0x80));
 for(unsigned owner=1;owner<=2;owner++){
  MODEL m=Model();G158_STATE s={0};G158_IO io=Io(&m);assert(G158Step(&s,&io)==G158_WAIT);
  m.D[owner]=(m.D[owner]+8)&G158_FIFO_MASK;unsigned actions=m.Actions;
  assert(G158Step(&s,&io)==G158_REFUSED&&s.Fault==G158_F_OWNER&&actions==m.Actions);Frozen(&s,&io,&m);Cases++;
 }
 for(unsigned after=0;after<2;after++)for(unsigned failure=1;failure<=6;failure++){
  MODEL m=Model();G158_STATE s={0};G158_IO io=Io(&m);m.FailAt=failure;m.FailAfter=after;
  assert(G158Step(&s,&io)==G158_REFUSED&&s.Fault==G158_F_IO&&m.Actions==failure);
  Frozen(&s,&io,&m);Cases++;
 }
 /* No remote response causes bounded waiting by the OS adapter, no repeat TX. */
 {
  MODEL m=Model();G158_STATE s={0};G158_IO io=Io(&m);assert(G158Step(&s,&io)==G158_WAIT);
  unsigned actions=m.Actions;for(unsigned i=0;i<1000;i++)assert(G158Step(&s,&io)==G158_WAIT);
  assert(!s.Complete&&actions==m.Actions&&s.TxFrames==2&&s.RxFrames==1);Cases++;
 }
 /* Host counters at ring boundary, including RX wrap; no indices are reset. */
 {
  MODEL m=Model();G158_STATE s={0};G158_IO io=Io(&m);memset(m.Rx,0,sizeof(m.Rx));
  s.Started=s.LocalVersionSent=s.PeerVersionSeen=s.PeerVersionAckSent=1;
  s.OwnTxHead=s.OwnRxTail=16376;m.D[0]=m.D[1]=m.D[2]=16376;m.D[3]=8;
  Frame(m.Rx+16376,0,1,0);Frame(m.Rx,1,1,0);
  assert(G158Step(&s,&io)==G158_WAIT&&s.OwnTxHead==0&&s.OwnRxTail==0);
  m.D[0]=0;assert(G158Step(&s,&io)==G158_WAIT&&s.OwnRxTail==8);
  assert(G158Step(&s,&io)==G158_COMPLETE&&s.LocalAckObserved);Cases++;
 }
 /* A reserved eight-byte gap is never used. */
 {
  MODEL m=Model();G158_STATE s={0};G158_IO io=Io(&m);s.Started=1;
  m.D[0]=8;m.D[1]=0;m.D[2]=0;m.D[3]=8;Frame(m.Rx,0,1,0);
  assert(G158Step(&s,&io)==G158_REFUSED&&s.Fault==G158_F_SPACE&&!m.Actions);Cases++;
 }
 /* Unexpected channel data remains untouched; it cannot fake an ACK. */
 {
  MODEL m=Model();G158_STATE s={0};G158_IO io=Io(&m);assert(G158Step(&s,&io)==G158_WAIT);
  PutRx(&m,2,7,12);unsigned actions=m.Actions,tail=m.D[2];
  assert(G158Step(&s,&io)==G158_REFUSED&&s.Fault==G158_F_FRAME&&m.D[2]==tail&&actions==m.Actions);Cases++;
 }
 /* A peer cannot negotiate an unsupported version or nonzero ACK features. */
 for(unsigned field=0;field<3;field++){
  MODEL m=Model();G158_STATE s={0};G158_IO io=Io(&m);assert(G158Step(&s,&io)==G158_WAIT);
  PutRx(&m,field?1:0,field==0?2:1,field==1?7:(field==2?0x100:0));
  unsigned actions=m.Actions;assert(G158Step(&s,&io)==G158_REFUSED&&s.Fault==G158_F_FRAME&&actions==m.Actions);Cases++;
 }
 /* Repeated VERSION requests have a finite trace/frame bound. */
 {
  MODEL m=Model();G158_STATE s={0};G158_IO io=Io(&m);assert(G158Step(&s,&io)==G158_WAIT);
  int result=G158_WAIT;
  for(unsigned i=0;i<40&&result==G158_WAIT;i++){m.D[0]=m.D[1];PutRx(&m,0,1,0);result=G158Step(&s,&io);}
  assert(result==G158_REFUSED&&s.Fault==G158_F_LIMIT&&s.TraceCount<=32&&s.TxFrames<=16&&s.RxFrames<=16);Frozen(&s,&io,&m);Cases++;
 }
 printf("{\"passed\":true,\"cases\":%u,\"native_operations\":0}\n",Cases);return 0;
}
