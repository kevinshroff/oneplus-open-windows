/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#pragma once
#include "g190_backend.h"
#define G321_MAX_EXTENTS 16u
#define G321_LOG_BYTES 0x4000u
typedef enum {G321_CACHE,G321_PERSISTENT,G321_LOG,G321_HFI} g321_extent_kind;
typedef struct {uint32_t iova,bytes;g321_extent_kind kind;} g321_extent;
typedef struct {g321_extent extent[G321_MAX_EXTENTS];uint32_t count,log_index,hfi_index,total_bytes;} g321_plan;
/* Exact pinned stock image; metadata authorization follows reviewed Open
 * gen7 prealloc types1/7 and VMAs. TCM is MMIO, never a RAM/IOVA extent.
 * Caller provides image whose full SHA was checked; this function also checks
 * actual full-image SHA. On failure output remains unchanged. */
g190_status g321_plan_image(const g190_image *,g321_plan *);
