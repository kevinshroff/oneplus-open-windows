/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Source-derived initial HFI DCVS vote and non-legacy OOB GPU power hold.
 * Existing real g190 transport/owner services; no replacement success ops. */
#include "g440_gpu_power.h"
#define GX_STATUS (0x50d0u*4u)
#define OOB_REQUEST (UINT32_C(1)<<30)
#define G440_SETUP_US UINT64_C(5000000) /* independent native proof/setup cap */
#define OOB_ACK (UINT32_C(1)<<31)
static g190_status fail(g440_gpu_power*p,g190_status s){p->poisoned=1;p->status=s;return s;}
static g190_status live(g440_gpu_power*p){
 g190_backend*b=p->backend;uint32_t v;
 if(b->epoch!=p->epoch||b->generation!=p->generation||b->phase!=G190_STARTUP_COMPLETE||b->stage!=11||b->startup_acked!=15||!b->reset_released)return fail(p,G190_STATE);
 if(b->ops.cancelled(b->ops.cookie))return fail(p,G190_CANCELLED);
 if(b->ops.lease(b->ops.cookie,p->generation))return fail(p,G190_LEASE_LOST);
 if(b->ops.read_reg(b->ops.cookie,G190_CM3_RESET,&v))return fail(p,G190_IO);
 if(v)return fail(p,G190_STATE);
 if(b->ops.read_reg(b->ops.cookie,G190_HFI_STATUS,&v))return fail(p,G190_IO);
 if(!(v&1))return fail(p,G190_STATE);
 if(b->ops.read_reg(b->ops.cookie,G190_AO_STATUS,&v))return fail(p,G190_IO);
 if(v&G190_AO_FATAL)return fail(p,G190_FW_ERROR);
 if(b->ops.read_reg(b->ops.cookie,G190_G2H_INFO,&v))return fail(p,G190_IO);
 if(v&G190_CM3_FAULT)return fail(p,G190_FW_ERROR);
 return G190_OK;
}
static g190_status stamp(g440_gpu_power*p,uint64_t*v){
 if(p->backend->ops.now_us(p->backend->ops.cookie,v))return fail(p,G190_CLOCK);
 if(*v<p->last||(p->backend->time_seen&&*v<p->backend->last_us))return fail(p,G190_CLOCK);
 p->last=*v;p->backend->last_us=*v;p->backend->time_seen=1;return G190_OK;
}
static g190_status rd(g440_gpu_power*p,uint32_t r,uint32_t*v){g190_status s=live(p);if(s)return s;if(p->backend->ops.read_reg(p->backend->ops.cookie,r,v))return fail(p,G190_IO);return G190_OK;}
static g190_status wr(g440_gpu_power*p,uint32_t r,uint32_t v){g190_status s=live(p);if(s)return s;if(p->backend->ops.write_reg(p->backend->ops.cookie,r,v)||p->backend->ops.barrier(p->backend->ops.cookie,G190_COMPLETE))return fail(p,G190_IO);return G190_OK;}
g190_status g440_gpu_acquire(g440_gpu_power*p,g190_backend*b,const AdrenoHfiStartupConfig*c,uint64_t serial){
 g190_status s;g190_reply reply;uint64_t now;uint32_t payload[3]={1,1,1};
 if(!p||!b||!c||p->attempted||!serial||!b->epoch||!b->generation||b->pending_header||!b->shared||!b->ops.read_reg||!b->ops.write_reg||!b->ops.barrier||!b->ops.now_us||!b->ops.wait_us||!b->ops.cancelled||!b->ops.lease)return G190_ARGUMENT;
 /* The runtime passes ONLY g196_prepare's pinned selected policy. These
  * explicit values independently prevent a silent foreign-profile vote. */
 if(c->gpu_count!=10||c->bandwidth_count!=10||c->gpu[0].hz||c->gpu[1].hz!=UINT64_C(124800000)||c->gpu[1].vote!=3408385u||c->ddr_count!=3||c->ddr_data[1][0]!=0x600007f2u||c->ddr_data[1][1]!=0x600007f2u||c->ddr_data[1][2]!=0x60000008u||c->enable_ifpc||c->acd_enable_mask)return G190_UNSUPPORTED;
 p->backend=b;p->epoch=b->epoch;p->generation=b->generation;p->stop_serial=serial;p->attempted=1;p->stage=1;
 if((s=stamp(p,&p->setup_begin_us)))return s;
 if((s=live(p)))return s;
 /* Reject pre-existing ACK31 without clearing it: cannot attribute to us. */
 if((s=rd(p,G190_G2H_INFO,&p->ack_before)))return s;
 if(p->ack_before&OOB_ACK)return fail(p,G190_BUSY);
 if((s=rd(p,GX_STATUS,&p->gx_before)))return s;p->gx_before_valid=1;
 /* Real HFI30 blocking frequency/BW vote, with the existing sequence match,
  * queue bounds, firmware-error, cancellation and timeout implementation. */
 s=g190_submit(b,b->epoch,30,payload,3);if(s)return fail(p,s);p->freq_header=b->pending_header;p->stage=2;
 do{s=g190_poll(b,b->epoch,&reply);if(s==G190_PENDING&&b->ops.wait_us(b->ops.cookie,b->limits.wait_us))return fail(p,G190_IO);}while(s==G190_PENDING);
 if(s)return fail(p,s);p->freq_acked=1;p->stage=3;
 if((s=rd(p,G190_G2H_INFO,&p->ack_observed)))return s;
 if(p->ack_observed&OOB_ACK)return fail(p,G190_BUSY);
 if((s=stamp(p,&now)))return s;if(now-p->setup_begin_us>=G440_SETUP_US)return fail(p,G190_TIMEOUT);
 /* Mark retention BEFORE the actual write: failure is indeterminate. */
 p->oob_may_be_held=1;
 if((s=wr(p,G190_H2G_SET,OOB_REQUEST)))return s;p->stage=4;
 /* Vendor timed poll begins after the posted request wrapper, not before
  * native owner qualification. Setup is independently bounded/retained. */
 if((s=stamp(p,&now)))return s;if(now-p->setup_begin_us>=G440_SETUP_US)return fail(p,G190_TIMEOUT);p->begin=p->request_posted_us=now;
 for(p->polls=1;p->polls<=101;p->polls++){
  /* Same read-before-timeout level polling semantics as vendor. A sampled
   * newly-owned ACK is real even when owner checks delayed first sample. */
  if((s=rd(p,G190_G2H_INFO,&p->ack_observed)))return s;
  if(p->ack_observed&OOB_ACK){if((s=stamp(p,&p->ack_sample_us)))return s;break;}
  if((s=stamp(p,&now)))return s;if(now-p->begin>=10000)return fail(p,G190_TIMEOUT);
  if(p->polls==101)return fail(p,G190_TIMEOUT);
  if(b->ops.wait_us(b->ops.cookie,100))return fail(p,G190_IO);
 }
 /* W1C only our newly observed ACK. Never acknowledge MSGQ/fault/foreign
  * OOB bits and never clear the retained GPU_SET request here. */
 if((s=wr(p,G190_G2H_CLEAR,OOB_ACK)))return s;p->stage=5;
 if((s=rd(p,GX_STATUS,&p->gx_after)))return s;p->gx_after_valid=1;
 if(p->gx_after&3u)return fail(p,G190_STATE);
 p->held=1;p->stage=6;p->status=G190_OK;return G190_OK;
}
g190_status g440_gpu_clear_stopped(g440_gpu_power*p,uint64_t serial){
 g190_status s;
 if(!p||!p->attempted||p->released||serial<=p->stop_serial)return G190_STATE;
 if(p->oob_may_be_held){if((s=wr(p,G190_H2G_SET,OOB_ACK)))return s;p->oob_may_be_held=0;}
 p->held=0;p->released=1;p->stop_serial=serial;p->stage=7;p->status=G190_OK;return G190_OK;
}
