/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef G440_GPU_POWER_H
#define G440_GPU_POWER_H
#include "g190_backend.h"
typedef struct {
 g190_backend *backend;uint64_t epoch,generation,begin,last,stop_serial;
 uint32_t stage,polls,ack_before,ack_observed,gx_before,gx_after,freq_header;
 g190_status status;int gx_before_valid,gx_after_valid;int attempted,freq_acked,oob_may_be_held,held,poisoned,released;
 uint64_t setup_begin_us,request_posted_us,ack_sample_us;
} g440_gpu_power;
/* Same actual G321 owner/exclusion and live GMU backend. Fixed Open G196
 * lowest admitted OPP: index1 124.8MHz / DT bus index1; not sheng's 220MHz.
 * Does not grant a resource/stop witness, map MMIO, unmask IRQs or touch GPU.
 * Zero-initialize once; never retry an attempted/uncertain acquisition. */
g190_status g440_gpu_acquire(g440_gpu_power *,g190_backend *,const AdrenoHfiStartupConfig *,uint64_t gpu_stop_serial);
/* Sole composition calls AFTER its real G433_GPU_OPS.GpuStopped succeeds
 * under the same owner exclusion, with serial > acquisition witness. */
g190_status g440_gpu_clear_stopped(g440_gpu_power *,uint64_t fresh_gpu_stop_serial);
#endif
