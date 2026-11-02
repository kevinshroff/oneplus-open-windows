/* SPDX-License-Identifier: MIT; internal producer-to-charge-policy bridge.
 * Input captures must come from the two fixed live kernel RESULT interfaces.
 * This is not a user-mode sensor injection interface or a resource lease.
 */
#ifndef OPEN_CHARGE_HEALTH_MONITOR_H
#define OPEN_CHARGE_HEALTH_MONITOR_H
#include "health_capture.h"
#include "link_core.h"
#define CH_CONTROL_REJECTED 15u
#define CH_PROVIDER_IO 16u
typedef struct {
 uint32_t Fault,LastCode;
 uint64_t Checks,Accepted,LastNonce,LastGaugeEnd100ns;
 CH_HEALTH LastGood;
}CH_MONITOR;
void CHMonitorInitialize(CH_MONITOR*);
/* Bad, missing, replayed or expired physical data latches a policy fault and
 * requests early off. A later good sample cannot clear that latch or re-enable.
 * The GLINK transport retains its own separate uncertainty/fault reporting. */
uint32_t CHMonitorRenew(CH_MONITOR*,CL_STATE*,const uint8_t*,size_t,
 const uint8_t*,size_t,uint64_t nonce,uint64_t now100ns);
/* Trusted internal entry points, never user sensor input. Fixed typed operations
 * select their role; CHRecheck rejects an expired or replayed measurement. */
uint32_t CHMonitorApplyKernelHealth(CH_MONITOR*,CL_STATE*,const CH_HEALTH*,
 uint64_t nonce,uint64_t now100ns,uint32_t role);
uint32_t CHMonitorReject(CH_MONITOR*,CL_STATE*,uint32_t code,uint64_t now100ns);
#endif
