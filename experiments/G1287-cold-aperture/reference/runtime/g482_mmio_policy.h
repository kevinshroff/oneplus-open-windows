/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#pragma once
#ifndef OGO_GPU_MMIO_WRITECOMBINE
#define OGO_GPU_MMIO_WRITECOMBINE 0
#endif
#if OGO_GPU_MMIO_WRITECOMBINE != 0 && OGO_GPU_MMIO_WRITECOMBINE != 1
#error OGO_GPU_MMIO_WRITECOMBINE must be 0 or 1
#endif
/* G1322 changes only the assigned GPU register bank's requested CPU mapping.
 * This is Normal-NC on the observed Windows MAIR, not Device-nGnRE.
 * The actual leaf PTE must be checked: existing cache policy can override a
 * request. BO mappings, other banks and register-access barriers are separate. */
#if OGO_GPU_MMIO_WRITECOMBINE
#define G482_MAP_PROTECTION(bank) \
 (PAGE_READWRITE|((bank)==G482_GPU?PAGE_WRITECOMBINE:PAGE_NOCACHE))
#else
#define G482_MAP_PROTECTION(bank) (PAGE_NOCACHE|PAGE_READWRITE)
#endif
