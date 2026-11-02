/* SPDX-License-Identifier: MIT -- fixed Open cold GMU/GBIF hold. */
#ifndef OPEN_COLD_HOLD_H
#define OPEN_COLD_HOLD_H
#include <stdint.h>
enum cgh_bank {CGH_GPU,CGH_CORE,CGH_RSC};
enum cgh_status {CGH_OK,CGH_ARGUMENT,CGH_OWNER,CGH_IO_ERROR,CGH_NOT_COLD,CGH_FOREIGN,CGH_TIMEOUT,CGH_UNCERTAIN};
enum cgh_state {CGH_NEW,CGH_MUTATING,CGH_HELD,CGH_RELEASED,CGH_REFUSED,CGH_POISONED,CGH_RESET_QUIESCENT,CGH_RESET_RELEASED,CGH_BOOT_UNHALTING,CGH_BOOT_RELEASED};
/* Native binding checks the actual held lifecycle thread/generation, assigned
 * mappings and retained source GMU-six-clock lease on every access. No flag
 * supplied by a caller can substitute for those actual producer objects. */
typedef struct {
 void *cookie;uint64_t generation;
 int (*current)(void*,uint64_t);
 int (*read)(void*,unsigned,uint32_t,uint32_t*);
 int (*write_halt)(void*,uint32_t,uint32_t); /* expected current, desired */
 void (*barrier)(void*);void (*wait10us)(void*);
}CGH_IO;
typedef struct {
 enum cgh_state state;enum cgh_status error;CGH_IO io;
 uint64_t generation,serial;uint32_t attempted,owned,reads,writes,polls;
 uint32_t before_halt,last_halt,last_ack,reset,hfi,gx,fence,tcs[4];
 uint32_t last_bank,last_offset,last_value;int last_io;
 int deferred; /* ABI retained; G736 never creates or accepts deferred holds. */
 uint32_t reset_mode; /* produced only by actual cold-reset acquisition, never HELD/owned */
 uint32_t sampled_mask,cold_fail_mask; /* successful reads: reset/HFI/GX/fence bits0..3, TCS bits4..7, HALT/ACK bits8..9; fail profile bits0..3 */
}CGH_HOLD;
/* One acquisition only, no reset assertion, HFI calls, foreign fault resume,
 * secure/CB/global-SMMU operations or clock writes. Poll budget1..10000. */
enum cgh_status CghAcquire(CGH_HOLD*,const CGH_IO*,uint64_t serial,unsigned poll_budget);
enum cgh_status CghCheck(CGH_HOLD*);
/* Fresh no-store reset/idle/halt-retired check, never a cached drain flag. */
enum cgh_status CghCheckReleased(CGH_HOLD*);
/* Only owned halt bit1 is removed, while CM3 remains reset/GX off. This is
 * handoff toward cold setup, NOT proof that future running masters stopped. */
enum cgh_status CghReleaseToReset(CGH_HOLD*,unsigned poll_budget);
/* Separate first-cold-boot authority: exact observed HALT8/ACK3 retained,
 * CM3reset1/HFI0/GXpower+clock-off/fence0 under actual exclusive native owner.
 * No traffic hold is acquired or claimed. No store occurs until boot unhalt. */
enum cgh_status CghResetAcquire(CGH_HOLD*,const CGH_IO*,uint64_t serial);
enum cgh_status CghResetCheck(CGH_HOLD*);
enum cgh_status CghResetReleaseUnpublished(CGH_HOLD*);
enum cgh_status CghResetCheckReleased(CGH_HOLD*);
/* Native caller must first consume stopped SMMU authority and promote the
 * exact active SID5 namespace. Called at vendor pre-GMU-boot unhalt position. */
enum cgh_status CghResetUnhaltForBoot(CGH_HOLD*);
enum cgh_status CghResetCheckBootReleased(CGH_HOLD*);
#endif
