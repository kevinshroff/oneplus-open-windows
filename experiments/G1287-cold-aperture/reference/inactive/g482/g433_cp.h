/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Real A740 CP_ME_INIT/ring/timestamp transport. No OS or hardware stubs.
 * Call only with actual GPU-role S1 backing and owned powered/stopped GPU.
 */
#ifndef G433_CP_H
#define G433_CP_H
#include <stdint.h>
#include <stddef.h>
typedef enum {G433_OK,G433_PENDING,G433_ARGUMENT,G433_STATE,G433_LEASE,G433_IO,G433_TIMEOUT,G433_CANCELLED,G433_CORRUPT} g433_status;
typedef struct {
 void*cookie;int(*lease)(void*);int(*read)(void*,uint32_t byte_offset,uint32_t*);
 int(*write)(void*,uint32_t byte_offset,uint32_t);
 int(*publish)(void*,const volatile uint32_t*,size_t);
 int(*acquire)(void*,volatile uint32_t*,size_t);int(*barrier)(void*);
 int(*now)(void*,uint64_t*);int(*wait)(void*,uint32_t);int(*cancelled)(void*);
 /* Mandatory owner-qualified GMU AHB status. No implicit clear/retry: a drop
  * fails closed; only the actual owner may recover after a new stop witness. */
 int(*fence_status)(void*,uint32_t*);
} g433_cp_ops;
typedef struct {volatile uint32_t*cpu;uint64_t iova;size_t bytes;} g433_memory;
typedef struct {
 g433_cp_ops ops;g433_memory ring,fence,sqe,pwrup;
 uint32_t stage,writes,issued,completed,last_observed,polls;
 uint64_t begin,last,timeout;g433_status status;
 int attempted,may_run,poisoned,time_seen,secure_transition;
} g433_cp;
/* All memory/ops validated before writes; caller has copied/verified actual
 * SQE payload and completed real protection/GPU stopped setup.
 * The struct must be zero-initialized before its single lifetime. */
g433_status g433_cp_begin(g433_cp*,const g433_cp_ops*,const g433_memory[4],uint64_t timeout_us);
g433_status g433_cp_poll(g433_cp*);
/* Only after real init fence1 AND successful owner authentication of ZAP.
 * Sends CP_SET_SECURE_MODE(0) + actual timestamp2; never raw TRUST_CNTL. */
g433_status g433_cp_secure_begin(g433_cp*,uint64_t timeout_us);
g433_status g433_cp_secure_run(g433_cp*,uint64_t timeout_us);
g433_status g433_cp_run(g433_cp*,const g433_cp_ops*,const g433_memory[4],uint64_t timeout_us);
#endif
