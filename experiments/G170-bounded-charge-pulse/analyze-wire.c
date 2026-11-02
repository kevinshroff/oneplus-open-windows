/* SPDX-License-Identifier: MIT; actual C layout independently parses native trace. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#define C_ASSERT(x) _Static_assert(x,#x)
#define CTL_CODE(t,f,m,a) (((t)<<16)|((a)<<14)|((f)<<2)|(m))
#define FILE_DEVICE_UNKNOWN 0x22u
#define METHOD_BUFFERED 0
#define FILE_READ_ACCESS 1
#define FILE_WRITE_ACCESS 2
#include "link_core.h"
#include "slots.h"
#include "protocol.h"
#include "abi-checks.h"
static uint32_t Word(const uint8_t*p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
int main(int argc,char**argv)
{
 assert(argc==2);CLN_SNAPSHOT_DATA*s=calloc(1,sizeof(*s));assert(s);
 FILE*f=fopen(argv[1],"rb");assert(f&&fread(s,1,sizeof(*s),f)==sizeof(*s)&&fgetc(f)==EOF);fclose(f);
 assert(s->Magic==CLN_MAGIC&&s->Size==sizeof(*s)&&s->State.BoardFvAttempted==1);
 CL_BATCH*b=&s->State.LastBatch;assert(b->Complete&&(b->Kind==1||b->Kind==2)&&!b->Battery.ValueValidMask);
 unsigned counts[3]={0};uint64_t times[3]={0};
 for(unsigned i=0;i<CL_TRACE_SLOTS;i++){
  CL_TRACE*t=s->State.Trace+i;
  if(!t->Serial||t->Direction!=1||t->Command!=9||t->Query<CL_FV_QUERY)continue;
  assert(t->Query<=CL_DISABLE_QUERY&&t->Bytes==40&&Word(t->Frame+8)==24&&Word(t->Frame+12)==0);
  unsigned q=t->Query-CL_FV_QUERY;const uint8_t*p=t->Frame+16;
  const uint32_t expected[6]={0x800a,1,0x31,0,q?24:8,q==0?4470:q==1?1:0};
  for(unsigned n=0;n<6;n++)assert(Word(p+4*n)==expected[n]);
  counts[q]++;times[q]=t->TimeUs;
 }
 if(b->Kind==1)assert(counts[0]==1&&b->Battery.WireValidMask==1024);
 else assert(counts[1]==1&&counts[2]==1&&times[2]>=times[1]&&b->Battery.WireValidMask==6144&&s->State.PulseAttempted==1);
 printf("{\"passed\":true,\"actual_C_layout\":true,\"kind\":%u,\"FV_frames\":%u,\"enable_frames\":%u,\"disable_frames\":%u,\"enable_us\":%llu,\"disable_us\":%llu,\"between_requests_us\":%llu,\"FV_result\":%u,\"enable_result\":%u,\"disable_result\":%u,\"control_ack_mask\":%u,\"SET_reply_not_hardware_readback\":true}\n",b->Kind,counts[0],counts[1],counts[2],(unsigned long long)times[1],(unsigned long long)times[2],(unsigned long long)(b->Kind==2?times[2]-times[1]:0),b->Battery.ServiceResult[CL_FV_QUERY],b->Battery.ServiceResult[CL_ENABLE_QUERY],b->Battery.ServiceResult[CL_DISABLE_QUERY],b->Battery.ControlAckMask);
 free(s);return 0;
}
