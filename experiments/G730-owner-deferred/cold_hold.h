/* SPDX-License-Identifier: MIT -- fixed Open cold GMU/GBIF hold. */
#ifndef OPEN_COLD_HOLD_H
#define OPEN_COLD_HOLD_H
#include <stdint.h>
enum cgh_bank {CGH_GPU,CGH_CORE,CGH_RSC};
enum cgh_status {CGH_OK,CGH_ARGUMENT,CGH_OWNER,CGH_IO_ERROR,CGH_NOT_COLD,CGH_FOREIGN,CGH_TIMEOUT,CGH_UNCERTAIN};
enum cgh_state {CGH_NEW,CGH_MUTATING,CGH_HELD,CGH_RELEASED,CGH_REFUSED,CGH_POISONED};
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
 int deferred; /* G730: GBIF bank unreadable (GX-domain down); hold without the halt handshake */
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
#endif
