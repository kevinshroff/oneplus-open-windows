/* SPDX-License-Identifier: MIT; actual C layout parses the saved native trace. */
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
#include "health_monitor.h"
typedef int32_t NTSTATUS;typedef void*WDFDEVICE;
#include "provider_io.h"
#include "protocol.h"
#include "abi-checks.h"
static uint32_t Word(const uint8_t*p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
int main(int argc,char**argv)
{
 assert(argc==2);CLN_SNAPSHOT_DATA*s=calloc(1,sizeof(*s));assert(s);
 FILE*f=fopen(argv[1],"rb");assert(f&&fread(s,1,sizeof(*s),f)==sizeof(*s)&&fgetc(f)==EOF);fclose(f);
 assert(s->Magic==CLN_MAGIC&&s->Size==sizeof(*s)&&s->State.BoardFvAttempted==1);
 CL_BATCH*b=&s->State.LastBatch;assert(b->Complete&&!b->Aborted&&(b->Kind==1||b->Kind==2)&&!b->Battery.ValueValidMask);
 unsigned counts[4]={0};uint64_t times[4]={0};
 for(unsigned i=0;i<CL_TRACE_SLOTS;i++){
  CL_TRACE*t=s->State.Trace+i;
  if(!t->Serial||t->Direction!=1||t->Command!=9||t->Query<CL_FV_QUERY)continue;
  assert(t->Query<=CL_RESTART_OFF_QUERY&&t->Bytes==40&&Word(t->Frame+8)==24&&Word(t->Frame+12)==0);
  unsigned q=t->Query-CL_FV_QUERY;const uint8_t*p=t->Frame+16;
  const uint32_t expected[6]={0x800a,1,0x31,0,q?24:8,q==0?4470:q==1?1:0};
  for(unsigned n=0;n<6;n++)assert(Word(p+4*n)==expected[n]);
  counts[q]++;times[q]=t->TimeUs;
 }
 if(b->Kind==1)assert(counts[0]==1&&b->Battery.WireValidMask==1024);
 else {
  assert(counts[1]==1&&counts[2]==1&&counts[3]==1&&times[1]>=times[3]&&times[2]>=times[1]);
  assert(times[1]-times[3]>=CL_RESTART_GAP_US&&times[2]-times[1]>=CL_PULSE_HARD_US&&times[2]>=s->State.PulseHardUntilUs&&times[2]-s->State.PulseHardUntilUs<CL_RPC_US);
  assert(b->Battery.WireValidMask==14336&&b->Battery.ControlAckMask==14336&&s->State.PulseAttempted==1&&s->State.RestartOffAcked==1&&s->State.PulseDisableAcked==1&&!s->State.StopPulseRequested);
 }
 assert(!s->HealthBusy&&!s->ProviderUncertain&&!s->Health.Fault);
 if(b->Kind==2)assert(s->Health.Accepted==31&&s->Health.Checks==31&&s->State.HealthLeaseRenewals==29&&s->State.PulseUntilUs==s->State.PulseHardUntilUs);
 if(b->Kind==1)printf("{\"passed\":true,\"actual_C_layout\":true,\"kind\":1,\"FV_frames\":%u,\"FV_result\":%u,\"control_ack_mask\":%u,\"SET_reply_not_hardware_readback\":true}\n",counts[0],b->Battery.ServiceResult[CL_FV_QUERY],b->Battery.ControlAckMask);
 else printf("{\"passed\":true,\"actual_C_layout\":true,\"kind\":2,\"FV_frames\":%u,\"initial_off_frames\":%u,\"enable_frames\":%u,\"final_off_frames\":%u,\"initial_off_us\":%llu,\"enable_us\":%llu,\"final_off_us\":%llu,\"off_to_on_us\":%llu,\"on_to_off_us\":%llu,\"initial_off_result\":%u,\"enable_result\":%u,\"final_off_result\":%u,\"control_ack_mask\":%u,\"SET_reply_not_hardware_readback\":true}\n",counts[0],counts[3],counts[1],counts[2],(unsigned long long)times[3],(unsigned long long)times[1],(unsigned long long)times[2],(unsigned long long)(times[1]-times[3]),(unsigned long long)(times[2]-times[1]),b->Battery.ServiceResult[CL_RESTART_OFF_QUERY],b->Battery.ServiceResult[CL_ENABLE_QUERY],b->Battery.ServiceResult[CL_DISABLE_QUERY],b->Battery.ControlAckMask);
 free(s);return 0;
}
