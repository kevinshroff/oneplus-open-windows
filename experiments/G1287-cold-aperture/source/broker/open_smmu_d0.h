/* SPDX-License-Identifier: MIT -- Open SM8550, S0-only source-owned clock lease. */
#ifndef OPEN_SMMU_D0_H
#define OPEN_SMMU_D0_H
#include <stdint.h>
#include <stddef.h>
#define OSM_MAPS 6u
#define OSM_CLOCKS 4u
enum osm_status {OSM_OK=0,OSM_ARGUMENT=-1,OSM_OWNER=-2,OSM_IO=-3,OSM_POWER_OFF=-4,OSM_PARENT=-5,OSM_FOREIGN=-6,OSM_TIMEOUT=-7,OSM_BUSY=-8,OSM_UNCERTAIN=-9,OSM_OVERFLOW=-10};
enum osm_state {OSM_NEW,OSM_PREPARING,OSM_ACTIVE,OSM_SAFE_FAILED,OSM_RELEASING,OSM_POISONED,OSM_RELEASED};
struct osm_range {uint64_t pa;uint32_t bytes;unsigned writable;};
/* The real PnP owner supplies immutable translated START grants and serializes
 * every entry point at PASSIVE_LEVEL. owns() validates that same START/power
 * generation and exclusive ownership of these four clock-enable bits AND software exclusion of all other nonvolatile control-word writers during each RMW. This is
 * the new driver's own contract, NOT a requirement for an installed broker.
 * Map/unmap never imply powered MMIO access; reads/writes must return explicit
 * failure on incomplete/unknown operations. No callbacks run at raised IRQL. */
struct osm_ops {
 void *cookie;
 int (*owns)(void *,uint64_t generation);
 int (*grant)(void *,uint64_t generation,const struct osm_range *);
 int (*map)(void *,const struct osm_range *,uintptr_t *token);
 void (*unmap)(void *,uintptr_t,uint32_t);
 int (*read32)(void *,uintptr_t,uint32_t offset,uint32_t *);
 int (*write32)(void *,uintptr_t,uint32_t offset,uint32_t);
 void (*barrier)(void *);
 void (*delay_us)(void *,uint32_t);
 /* Zero only after this owner's clients, GPU/GMU DMA and outstanding SMMU
  * operations are stopped/drained. This core never performs a CB/TLB reset. */
 int (*drained)(void *,uint64_t generation);
 /* Fixed current parent query through actual OPBM owner; no hidden map. */
 int (*parent_votes)(void *,uint32_t *external,uint32_t *ap_vote);
};
struct osm_lease {
 struct osm_ops io;uint64_t generation;enum osm_state state;int error;
 uintptr_t maps[OSM_MAPS];unsigned mapped,refs,attempted,owned_mask,cleared_mask;
 uint32_t before[OSM_CLOCKS],expected[OSM_CLOCKS];
 /* owned_mask journals capture0->1 intent. AHB HALT_DELAY request acceptance
  * is distinct from BIT0 confirmation and is never physical GPU stop proof. */
 unsigned writes,polls;uint32_t last_cx,last_hw,last_root,last_cfg,last_id0;
 uint32_t last_branch[OSM_CLOCKS],delay_request_mask,bit0_confirmed_mask,reject_reason;
};
extern const struct osm_range osm_required_ranges[OSM_MAPS];
int osm_acquire(struct osm_lease *,const struct osm_ops *,uint64_t generation);
int osm_witness(struct osm_lease *,uint64_t generation);
int osm_release(struct osm_lease *,uint64_t generation);
/* Safe only when no register mutation occurred or final release succeeded. */
int osm_unmap_safe(struct osm_lease *);
#endif
