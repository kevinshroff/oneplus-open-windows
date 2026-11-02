/* SPDX-License-Identifier: MIT -- selected Open cold GMU six-clock requests. */
#ifndef OPEN_GMU_CLOCK_H
#define OPEN_GMU_CLOCK_H
#include <stdint.h>
enum gmc_state {GMC_NEW,GMC_MUTATING,GMC_HELD,GMC_RELEASED,GMC_REFUSED,GMC_POISONED};
enum gmc_error {GMC_OK,GMC_ARGUMENT,GMC_OWNER,GMC_IO_ERROR,GMC_PARENT,GMC_FOREIGN,GMC_TIMEOUT,GMC_NEED_PLL_OWNER};
typedef struct {
 void *cookie;uint64_t generation;
 int (*current)(void*,uint64_t); /* actual broker lock/current D0 + active four-clock SMMU lease,
                              * including its retained AHB delay request or borrowed enable */
 int (*read)(void*,uint64_t,uint32_t*);
 int (*write)(void*,uint64_t,uint32_t,uint32_t); /* current, desired; exact mask */
 void (*barrier)(void*);void (*wait1us)(void*);
}GMC_IO;
typedef struct {
 enum gmc_state state;enum gmc_error error;GMC_IO io;uint64_t generation;
 unsigned refs,attempted,writes,reads,polls,owned_mask;
 uint32_t before[6],raw[6],root_before,root_expected,root_cmd_before,last_pa_low,last_word;
 uint32_t pll[6];unsigned root_dirty_allowed,root_left_configured,root_owned,delay_request_mask,bit0_confirmed_mask;
 unsigned no_disable_left_mask,request_dropped_mask,write_cleared_mask;
}GMC_LEASE;
/* Borrows an already enabled stable source PLL1~440MHz. No PLL reset,
 * calibration, voltage, SMCCC, force-off or foreign leaf writes exist here. */
enum gmc_error GmcAcquire(GMC_LEASE*,const GMC_IO*);
enum gmc_error GmcWitness(GMC_LEASE*);
/* Real caller must first establish cold CM3/reset + drained GBIF and retire
 * running masters. This routine is private broker-only, not a drain boolean. */
enum gmc_error GmcReleaseCold(GMC_LEASE*);
#endif
