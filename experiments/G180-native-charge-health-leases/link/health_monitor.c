/* SPDX-License-Identifier: MIT */
#include "health_monitor.h"
#include "health_recheck.h"
#include <string.h>
void CHMonitorInitialize(CH_MONITOR*m){if(m)memset(m,0,sizeof(*m));}
static uint32_t Fail(CH_MONITOR*m,CL_STATE*s,uint32_t code,uint64_t now)
{
 if(!m->Fault)m->Fault=code;m->LastCode=m->Fault;
 /* Stop never emits another on. Failed GLINK remains retained/uncertain. */
 ClRequestStopPulse(s,now/10);return m->Fault;
}
uint32_t CHMonitorReject(CH_MONITOR*m,CL_STATE*s,uint32_t code,uint64_t now)
{
 if(!m||!s)return CH_ARGUMENT;
 if(m->Checks==UINT64_MAX)return Fail(m,s,CH_CONTROL_REJECTED,now);
 m->Checks++;return Fail(m,s,code?code:CH_PROVIDER_IO,now);
}
uint32_t CHMonitorApplyKernelHealth(CH_MONITOR*m,CL_STATE*s,const CH_HEALTH*h,
 uint64_t nonce,uint64_t now,uint32_t role)
{
 if(!m||!s)return CH_ARGUMENT;
 if(m->Checks==UINT64_MAX)return Fail(m,s,CH_CONTROL_REJECTED,now);
 m->Checks++;
 if(m->Fault)return Fail(m,s,m->Fault,now);
 if(role<CH_BEFORE_FV||role>CH_RENEW)return Fail(m,s,CH_ARGUMENT,now);
 if(s->Phase!=CL_READY||s->CloseRequested||s->StopPulseRequested||s->Pending||
  (role!=CH_RENEW&&s->BatchActive)||
  (role==CH_RENEW&&(!s->BatchActive||s->Working.Kind!=2||
   !s->PulseEnableAcked||s->Query!=CL_DISABLE_QUERY)))
  return Fail(m,s,CH_CONTROL_REJECTED,now);
 uint32_t code=CHRecheck(h,nonce,now,m->LastNonce,m->LastGaugeEnd100ns,role);
 if(code)return Fail(m,s,code,now);
 int result=role==CH_BEFORE_FV?ClRequestBoardFv(s,now/10):
  role==CH_BEFORE_RESTART?ClRequestRestartPulse(s,now/10):ClRequestHealthLease(s,now/10);
 if(result!=1||s->StopPulseRequested)return Fail(m,s,CH_CONTROL_REJECTED,now);
 m->Accepted++;m->LastNonce=nonce;m->LastGaugeEnd100ns=h->GaugeEnd100ns;
 m->LastGood=*h;m->LastCode=CH_OK;return CH_OK;
}
uint32_t CHMonitorRenew(CH_MONITOR*m,CL_STATE*s,const uint8_t*c,size_t cn,
 const uint8_t*g,size_t gn,uint64_t nonce,uint64_t now)
{
 if(!m||!s)return CH_ARGUMENT;
 CH_HEALTH h;uint32_t code=CHValidate(c,cn,g,gn,nonce,now,m->LastNonce,m->LastGaugeEnd100ns,CH_RENEW,&h);
 if(code)return CHMonitorReject(m,s,code,now);
 return CHMonitorApplyKernelHealth(m,s,&h,nonce,now,CH_RENEW);
}
