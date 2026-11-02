/* SPDX-License-Identifier: MIT
 * The completed raw history, not cached decode/IRQ/retry flags, proves the
 * only legal next command. One fixed retry follows one completed bad header.
 */
#include "g57_touch.h"
static int Complete(const G57_WIRE_RESULT*f)
{
 uint32_t i,wire=f->Kind==G57_WIRE_CLEAR?6:f->Payload+8;uint8_t tx[72]={0};
 if(!f->Attempted||!f->TransportOk||f->StartCode||f->StepCode||f->State!=4||f->CancelSent||f->AbortSent||f->TxDone!=wire||f->RxDone!=(f->Kind==G57_WIRE_CLEAR?0:wire))return 0;
 if(f->Kind==G57_WIRE_CLEAR){if(!G57EventClearFrame(tx,72))return 0;}
 else if(g27_goodix_read_frame(f->Address,f->Payload,tx,72))return 0;
 for(i=0;i<72;i++)if(tx[i]!=f->Tx[i])return 0;
 return 1;
}
int G57PollPlan(const G57_TOUCH_RESULT*r,uint32_t index)
{
 uint32_t i,need=G57_WIRE_PREFETCH,tail=0,prefixes=0;uint8_t bytes[90]={0};G57_FRAME decoded;
 if(!r||r->Poll.Limit==0||r->Poll.Limit>G57_POLL_CYCLES||index>=4*r->Poll.Limit||index>=G57_POLL_WIRES||r->PollFrameCount!=index+1||!r->FullBlockChecksumValid||!G57InfoContract(r->Rx+8,242)||!G57AckEligible(&r->Report)||!r->Ack.TransportOk||!r->Post.TransportOk||r->Post.State!=4||r->Post.TxDone!=34||r->Post.RxDone!=34||r->Post.CancelSent||r->Post.AbortSent)return 0;
 for(i=0;i<=index;i++){
  const G57_WIRE_RESULT*f=&r->PollFrames[i];uint32_t j;
  if(f->Kind!=need)return 0;
  if(need==G57_WIRE_PREFETCH){if(prefixes>=r->Poll.Limit||f->Address!=G57_TOUCH_ADDRESS||f->Payload!=G57_PREFETCH)return 0;prefixes++;}
  else if(need==G57_WIRE_RETRY){if(f->Address!=G57_TOUCH_ADDRESS||f->Payload!=G57_PREFETCH)return 0;}
  else if(need==G57_WIRE_TAIL){if(f->Address!=G57_TAIL_ADDRESS||f->Payload!=tail||tail<8||tail>64||(tail&7))return 0;}
  else if(need==G57_WIRE_CLEAR){if(f->Address!=G57_TOUCH_ADDRESS||f->Payload!=1)return 0;}
  else return 0;
  if(i==index)return 1;
  if(!Complete(f))return 0;
  if(need==G57_WIRE_CLEAR){need=G57_WIRE_PREFETCH;continue;}
  if(need==G57_WIRE_PREFETCH||need==G57_WIRE_RETRY){
   for(j=0;j<90;j++)bytes[j]=0;for(j=0;j<26;j++)bytes[j]=f->Rx[8+j];G57DecodeReport(bytes,26,&decoded);
   if(decoded.Error==G57_BAD_HEADER&&decoded.HeaderChecked&&!decoded.HeaderValid){if(need!=G57_WIRE_PREFETCH)return 0;need=G57_WIRE_RETRY;continue;}
  }else{for(j=0;j<tail;j++)bytes[26+j]=f->Rx[8+j];G57DecodeReport(bytes,26+tail,&decoded);}
  if(decoded.Kind==G57_FRAME_IDLE)need=G57_WIRE_PREFETCH;
  else if(decoded.Kind==G57_FRAME_MORE){if(need!=G57_WIRE_PREFETCH&&need!=G57_WIRE_RETRY)return 0;tail=decoded.TailBytes;need=G57_WIRE_TAIL;}
  else if(decoded.Kind==G57_FRAME_REQUEST_ZERO||decoded.Kind==G57_FRAME_CONTACTS)need=G57_WIRE_CLEAR;
  else return 0;
 }
 return 0;
}
