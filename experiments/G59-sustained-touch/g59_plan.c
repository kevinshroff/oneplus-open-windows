/* SPDX-License-Identifier: MIT
 * Validate only the current cycle, from completed raw bytes. Advancing to a
 * new cycle requires terminal idle or one completed valid clear. Global
 * counters are never reset. The owner and native adapter hold separate bases.
 */
#include "g59_touch.h"
#define FINISHED 5u
static int Complete(const G59_WIRE_RESULT*f)
{
 uint32_t i,wire=f->Kind==G59_WIRE_CLEAR?6:f->Payload+8;uint8_t tx[72]={0};
 if(!f->Attempted||!f->TransportOk||f->StartCode||f->StepCode||f->State!=4||f->CancelSent||f->AbortSent||f->TxDone!=wire||f->RxDone!=(f->Kind==G59_WIRE_CLEAR?0:wire))return 0;
 if(f->Kind==G59_WIRE_CLEAR){if(!G59EventClearFrame(tx,72))return 0;}
 else if(g27_goodix_read_frame(f->Address,f->Payload,tx,72))return 0;
 for(i=0;i<72;i++)if(tx[i]!=f->Tx[i])return 0;return 1;
}
static int Startup(const G59_TOUCH_RESULT*r)
{
 return r&&r->Poll.Limit&&r->Poll.Limit<=G59_POLL_CYCLES&&r->FullBlockChecksumValid&&G59InfoContract(r->Rx+8,242)&&G59AckEligible(&r->Report)&&r->Ack.TransportOk&&r->Post.TransportOk&&r->Post.State==4&&r->Post.TxDone==34&&r->Post.RxDone==34&&!r->Post.CancelSent&&!r->Post.AbortSent;
}
static int Descriptor(const G59_WIRE_RESULT*f,uint32_t need,uint32_t tail)
{
 if(f->Kind!=need)return 0;
 if(need==G59_WIRE_PREFETCH||need==G59_WIRE_RETRY)return f->Address==G59_TOUCH_ADDRESS&&f->Payload==G59_PREFETCH;
 if(need==G59_WIRE_TAIL)return f->Address==G59_TAIL_ADDRESS&&f->Payload==tail&&tail>=8&&tail<=64&&!(tail&7);
 if(need==G59_WIRE_CLEAR)return f->Address==G59_TOUCH_ADDRESS&&f->Payload==1;
 return 0;
}
static uint32_t Next(const G59_TOUCH_RESULT*r,uint32_t start,uint32_t end,uint32_t*tail)
{
 uint32_t i,need=G59_WIRE_PREFETCH;uint8_t bytes[90]={0};G59_FRAME decoded;
 if(!Startup(r)||start>end||end>r->PollFrameCount||end-start>4||end>4*r->Poll.Limit)return 0;
 *tail=0;
 for(i=start;i<end;i++){
  const G59_WIRE_RESULT*f=&r->PollFrames[i%G59_POLL_WIRES];uint32_t j;
  if(!Descriptor(f,need,*tail)||!Complete(f))return 0;
  if(need==G59_WIRE_CLEAR){need=FINISHED;continue;}
  if(need==G59_WIRE_PREFETCH||need==G59_WIRE_RETRY){
   for(j=0;j<90;j++)bytes[j]=0;for(j=0;j<26;j++)bytes[j]=f->Rx[8+j];G59DecodeReport(bytes,26,&decoded);
   if(decoded.Error==G59_BAD_HEADER&&decoded.HeaderChecked&&!decoded.HeaderValid){if(need!=G59_WIRE_PREFETCH)return 0;need=G59_WIRE_RETRY;continue;}
  }else{for(j=0;j<*tail;j++)bytes[26+j]=f->Rx[8+j];G59DecodeReport(bytes,26+*tail,&decoded);}
  if(decoded.Kind==G59_FRAME_IDLE)need=FINISHED;
  else if(decoded.Kind==G59_FRAME_MORE){if(need!=G59_WIRE_PREFETCH&&need!=G59_WIRE_RETRY)return 0;*tail=decoded.TailBytes;need=G59_WIRE_TAIL;}
  else if(decoded.Kind==G59_FRAME_REQUEST_ZERO||decoded.Kind==G59_FRAME_CONTACTS)need=G59_WIRE_CLEAR;
  else return 0;
 }
 return need;
}
int G59PollPlan(const G59_TOUCH_RESULT*r,uint32_t start,uint32_t index)
{
 uint32_t need,tail;
 if(!r||index>=4*r->Poll.Limit||r->PollFrameCount!=index+1||start>index||index-start>=4)return 0;
 need=Next(r,start,index,&tail);return Descriptor(&r->PollFrames[index%G59_POLL_WIRES],need,tail);
}
int G59CycleComplete(const G59_TOUCH_RESULT*r,uint32_t start,uint32_t end)
{
 uint32_t tail;if(!r||end!=r->PollFrameCount||end<=start||end-start>4)return 0;
 return Next(r,start,end,&tail)==FINISHED;
}
