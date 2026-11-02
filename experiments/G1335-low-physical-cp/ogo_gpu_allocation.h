/* G1335 placement hypothesis only. Configured SMMU OAS remains 36 bits. */
#ifndef OGO_GPU_ALLOCATION_H
#define OGO_GPU_ALLOCATION_H
#ifndef OGO_GPU_LOW_PHYSICAL
#define OGO_GPU_LOW_PHYSICAL 0
#endif
#if OGO_GPU_LOW_PHYSICAL != 0 && OGO_GPU_LOW_PHYSICAL != 1
#error OGO_GPU_LOW_PHYSICAL must be exactly 0 or 1
#endif
#if OGO_GPU_LOW_PHYSICAL
#define OGO_GPU_ALLOC_LIMIT (1ull<<32)
#else
#define OGO_GPU_ALLOC_LIMIT (1ull<<36)
#endif
#define OGO_GPU_ALLOC_HIGH (OGO_GPU_ALLOC_LIMIT-1)
#endif
