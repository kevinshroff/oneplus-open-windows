/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef G196_PREFLIGHT_H
#define G196_PREFLIGHT_H
#include "g190_backend.h"

/* Pure byte admission. No generation/lease, physical address, MMIO, SMMU,
 * stop/reset, allocation or backend-run operation is supplied by this module.
 * The qualified owner must copy these buffers under its current generation,
 * serialize access and retain them unchanged while consuming the result. */
typedef struct { const uint8_t *data; size_t bytes; } g196_bytes;
typedef struct {
    g196_bytes firmware_fdt; /* exact60399 bytes, optionally retained64KiB tail */
    g196_bytes global_smem_first,global_smem_second; /* full0xb0000 snapshots */
    g196_bytes command_db; /* actual bytes only: >=5464, never padded to128KiB */
    g196_bytes gmu_image;
} g196_inputs;
typedef enum {
    G196_INPUTS_MATCH, G196_ARGUMENT, G196_FDT, G196_SMEM, G196_SOC,
    G196_DB_LAYOUT, G196_DB_IDENTITY, G196_GMU, G196_BACKEND
} g196_status;
enum {
    G196_NEEDS_CHIP_SPEEDBIN=1u, G196_NEEDS_CURRENT_OWNER=2u,
    G196_NEEDS_POWER_CLOCK_LEASE=4u, G196_NEEDS_STOP_RUNDOWN=8u,
    G196_NEEDS_NATIVE4K_BACKING=16u, G196_NEEDS_STOPPED_BOARD=32u,
    G196_NEEDS_ACTUAL_ACKS=64u, G196_REQUIRED_NATIVE=127u
};
typedef struct {
    uint32_t declared_entries,declared_bytes,slave_tables,selected_resources;
} g196_db_fact;
typedef struct {
    uint32_t native_ready; /* always0; matching input bytes cannot grant access */
    uint32_t remaining_native; /* always G196_REQUIRED_NATIVE */
    uint32_t soc_id,revision,feature_code,source_sku;
    uint32_t soc_item_offset,smem_items;
    g196_db_fact command_db;
    g190_image image; /* references caller's pinned, immutable real image */
    AdrenoHfiStartupConfig policy;
    AdrenoFirmwareBlock blocks[32];
    size_t block_count;
} g196_preflight;

/* Output is committed only on success, and must not alias any input. */
g196_status g196_check_command_db(g196_bytes,g196_db_fact *);
g196_status g196_prepare(const g196_inputs *,g196_preflight *);
#endif
