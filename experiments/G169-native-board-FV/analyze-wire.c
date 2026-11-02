/* SPDX-License-Identifier: MIT; C owns layout and control-code definitions. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
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
#define O(t,n) printf("\"" #n "\":%zu,",offsetof(t,n))
#define Z(t,n) printf("\"" #n "\":%zu",offsetof(t,n))

#include <stdlib.h>
#include <string.h>
static uint32_t U32(const uint8_t*p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
int main(int argc,char**argv){assert(argc==2);CLN_SNAPSHOT_DATA*s=calloc(1,sizeof(*s));assert(s);FILE*f=fopen(argv[1],"rb");assert(f&&fread(s,1,sizeof(*s),f)==sizeof(*s)&&fgetc(f)==EOF);fclose(f);assert(s->Magic==CLN_MAGIC&&s->Size==sizeof(*s));unsigned count=0;
 for(unsigned i=0;i<CL_TRACE_SLOTS;i++){CL_TRACE*t=s->State.Trace+i;if(t->Serial&&t->Direction==1&&t->Command==9&&t->Query==CL_FV_QUERY){
  assert(t->Bytes==40&&U32(t->Frame+8)==24&&U32(t->Frame+12)==0);
  const uint8_t*q=t->Frame+16;const uint32_t words[]={0x800a,1,0x31,0,8,4470};for(unsigned j=0;j<6;j++)assert(U32(q+4*j)==words[j]);count++;
 }}
 assert(count==1&&s->State.BoardFvAttempted==1&&!s->State.Fault&&!s->State.RpcUncertain&&!s->State.TransportUncertain);
 assert(s->State.LastBatch.Kind==1&&s->State.LastBatch.Complete&&s->State.LastBatch.Battery.ControlAckMask==1024&&!s->State.LastBatch.Battery.ValueValidMask);
 printf("{\"passed\":true,\"actual_C_layout\":true,\"SET_frames_in_frozen_trace\":%u,\"words\":[32778,1,49,0,8,4470],\"service_result\":%u,\"SET_reply_not_a_voltage\":true}\n",count,s->State.LastBatch.Battery.ServiceResult[CL_FV_QUERY]);free(s);return 0;}
