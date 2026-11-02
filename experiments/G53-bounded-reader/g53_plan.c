/* SPDX-License-Identifier: MIT
 * Raw-byte proof of each next command. This policy is independently called
 * by both the portable owner and native register adapter. Cached decode flags
 * never authorize an event clear. No I/O or allocation occurs here.
 */
#include "g53_touch.h"
static int Complete(const G53_WIRE_RESULT*f)
{
 uint32_t i,wire=f->Kind==G53_WIRE_CLEAR?6:f->Payload+8;uint8_t tx[72]={0};
 if(!f->Attempted||!f->TransportOk||f->StartCode||f->StepCode||f->State!=4||f->CancelSent||f->AbortSent||f->TxDone!=wire||f->RxDone!=(f->Kind==G53_WIRE_CLEAR?0:wire))return 0;
 if(f->Kind==G53_WIRE_CLEAR){if(!G53EventClearFrame(tx,72))return 0;}
 else if(g27_goodix_read_frame(f->Address,f->Payload,tx,72))return 0;
 for(i=0;i<72;i++)if(tx[i]!=f->Tx[i])return 0;
 return 1;
}
int G53PollPlan(const G53_TOUCH_RESULT*r,uint32_t index)
{
 uint32_t i,need=G53_WIRE_PREFETCH,tail=0,prefixes=0;uint8_t bytes[90]={0};G53_FRAME decoded;
 if(!r||index>=G53_POLL_WIRES||r->PollFrameCount!=index+1||!r->FullBlockChecksumValid||!G53InfoContract(r->Rx+8,242)||!G53AckEligible(&r->Report)||!r->Ack.TransportOk||!r->Post.TransportOk||r->Post.State!=4||r->Post.TxDone!=34||r->Post.RxDone!=34||r->Post.CancelSent||r->Post.AbortSent)return 0;
 for(i=0;i<=index;i++){
  const G53_WIRE_RESULT*f=&r->PollFrames[i];uint32_t j;
  if(f->Kind!=need)return 0;
  if(need==G53_WIRE_PREFETCH){if(prefixes>=G53_POLL_CYCLES||f->Address!=G53_TOUCH_ADDRESS||f->Payload!=G53_PREFETCH)return 0;prefixes++;}
  else if(need==G53_WIRE_TAIL){if(f->Address!=G53_TAIL_ADDRESS||f->Payload!=tail||tail<8||tail>64||(tail&7))return 0;}
  else if(need==G53_WIRE_CLEAR){if(f->Address!=G53_TOUCH_ADDRESS||f->Payload!=1)return 0;}
  else return 0;
  if(i==index)return 1;
  if(!Complete(f))return 0;
  if(need==G53_WIRE_CLEAR){need=G53_WIRE_PREFETCH;continue;}
  if(need==G53_WIRE_PREFETCH){for(j=0;j<90;j++)bytes[j]=0;for(j=0;j<26;j++)bytes[j]=f->Rx[8+j];G53DecodeReport(bytes,26,&decoded);}
  else{for(j=0;j<tail;j++)bytes[26+j]=f->Rx[8+j];G53DecodeReport(bytes,26+tail,&decoded);}
  if(decoded.Kind==G53_FRAME_IDLE)need=G53_WIRE_PREFETCH;
  else if(decoded.Kind==G53_FRAME_MORE){if(need!=G53_WIRE_PREFETCH)return 0;tail=decoded.TailBytes;need=G53_WIRE_TAIL;}
  else if(decoded.Kind==G53_FRAME_REQUEST_ZERO||decoded.Kind==G53_FRAME_CONTACTS)need=G53_WIRE_CLEAR;
  else return 0;
 }
 return 0;
}
