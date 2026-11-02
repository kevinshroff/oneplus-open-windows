/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * G1318 source-parity trial only. Admission still requires all four zeros.
 * A zero read does not establish a write strobe, nor a missing-strobe cause. */
#ifndef G456_SECVID_ZERO_H
#define G456_SECVID_ZERO_H
#include "g456_tables.h"
#ifndef OGO_GPU_SECVID_ZERO_STORES
#define OGO_GPU_SECVID_ZERO_STORES 0
#endif
#if OGO_GPU_SECVID_ZERO_STORES != 0 && OGO_GPU_SECVID_ZERO_STORES != 1
#error OGO_GPU_SECVID_ZERO_STORES must be exactly 0 or 1
#endif
#if OGO_GPU_SECVID_ZERO_STORES
/* Linux/Sheng nonsecure policy order: TSB control, trusted base low/high, size.
 * Never substitute KGSL's Android secure-VA reservation for admitted zeros. */
static const uint32_t G456SecvidZeroStores[][2]={
 {G456_RBBM_SECVID_TSB_CNTL,0},
 {G456_RBBM_SECVID_TSB_TRUSTED_BASE_LO,0},
 {G456_RBBM_SECVID_TSB_TRUSTED_BASE_HI,0},
 {G456_RBBM_SECVID_TSB_TRUSTED_SIZE,0},
};
#define G456SecvidZeroStores_COUNT 4u
_Static_assert(sizeof(G456SecvidZeroStores)/sizeof(G456SecvidZeroStores[0])==4,"four SECVID stores only");
#endif
#endif
