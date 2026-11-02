/* SPDX-License-Identifier: MIT
 * Validate only the current cycle, from completed raw bytes. Advancing to a
 * new cycle requires terminal idle or one completed valid clear. Global
 * counters are never reset. The owner and native adapter hold separate bases.
 */
#include "g92_touch.h"
#define FINISHED 5u
static int Complete(const G92_WIRE_RESULT*f)
{
 uint32_t i,wire=f->Kind==G92_WIRE_CLEAR?6:f->Payload+8;uint8_t tx[72]={0};
 if(!f->Attempted||!f->TransportOk||f->StartCode||f->StepCode||f->State!=4||f->CancelSent||f->AbortSent||f->TxDone!=wire||f->RxDone!=(f->Kind==G92_WIRE_CLEAR?0:wire))return 0;
 if(f->Kind==G92_WIRE_CLEAR){if(!G92EventClearFrame(tx,72))return 0;}
 else if(g27_goodix_read_frame(f->Address,f->Payload,tx,72))return 0;
 for(i=0;i<72;i++)if(tx[i]!=f->Tx[i])return 0;return 1;
}
static int Startup(const G92_TOUCH_RESULT*r)
{
 return r&&r->Poll.Limit&&r->Poll.Limit<=G92_POLL_CYCLES&&r->FullBlockChecksumValid&&G92InfoContract(r->Rx+8,242)&&G92AckEligible(&r->Report)&&r->Ack.TransportOk&&r->Post.TransportOk&&r->Post.State==4&&r->Post.TxDone==34&&r->Post.RxDone==34&&!r->Post.CancelSent&&!r->Post.AbortSent;
}
static int Descriptor(const G92_WIRE_RESULT*f,uint32_t need,uint32_t tail)
{
 if(f->Kind!=need)return 0;
 if(need==G92_WIRE_PREFETCH||need==G92_WIRE_RETRY)return f->Address==G92_TOUCH_ADDRESS&&f->Payload==G92_PREFETCH;
 if(need==G92_WIRE_TAIL)return f->Address==G92_TAIL_ADDRESS&&f->Payload==tail&&tail>=8&&tail<=64&&!(tail&7);
 if(need==G92_WIRE_CLEAR)return f->Address==G92_TOUCH_ADDRESS&&f->Payload==1;
 return 0;
}
static uint32_t Next(const G92_TOUCH_RESULT*r,uint32_t start,uint32_t end,uint32_t*tail)
{
 uint32_t i,need=G92_WIRE_PREFETCH;uint8_t bytes[90]={0};G92_FRAME decoded;
 if(!Startup(r)||start>end||end>r->PollFrameCount||end-start>4||end>4*r->Poll.Limit)return 0;
 *tail=0;
 for(i=start;i<end;i++){
  const G92_WIRE_RESULT*f=&r->PollFrames[i%G92_POLL_WIRES];uint32_t j;
  if(!Descriptor(f,need,*tail)||!Complete(f))return 0;
  if(need==G92_WIRE_CLEAR){need=FINISHED;continue;}
  if(need==G92_WIRE_PREFETCH||need==G92_WIRE_RETRY){
   for(j=0;j<90;j++)bytes[j]=0;for(j=0;j<26;j++)bytes[j]=f->Rx[8+j];G92DecodeReport(bytes,26,&decoded);
   if(decoded.Error==G92_BAD_HEADER&&decoded.HeaderChecked&&!decoded.HeaderValid){if(need!=G92_WIRE_PREFETCH)return 0;need=G92_WIRE_RETRY;continue;}
  }else{for(j=0;j<*tail;j++)bytes[26+j]=f->Rx[8+j];G92DecodeReport(bytes,26+*tail,&decoded);}
  if(decoded.Kind==G92_FRAME_IDLE)need=FINISHED;
  else if(decoded.Kind==G92_FRAME_MORE){if(need!=G92_WIRE_PREFETCH&&need!=G92_WIRE_RETRY)return 0;*tail=decoded.TailBytes;need=G92_WIRE_TAIL;}
  else if(decoded.Kind==G92_FRAME_REQUEST_ZERO||decoded.Kind==G92_FRAME_CONTACTS)need=G92_WIRE_CLEAR;
  else return 0;
 }
 return need;
}
int G92PollPlan(const G92_TOUCH_RESULT*r,uint32_t start,uint32_t index)
{
 uint32_t need,tail;
 if(!r||index>=4*r->Poll.Limit||r->PollFrameCount!=index+1||start>index||index-start>=4)return 0;
 need=Next(r,start,index,&tail);return Descriptor(&r->PollFrames[index%G92_POLL_WIRES],need,tail);
}
int G92CycleComplete(const G92_TOUCH_RESULT*r,uint32_t start,uint32_t end)
{
 uint32_t tail;if(!r||end!=r->PollFrameCount||end<=start||end-start>4)return 0;
 return Next(r,start,end,&tail)==FINISHED;
}
