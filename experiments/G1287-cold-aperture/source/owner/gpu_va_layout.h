/* Fixed private CP BO layout. Compile-time discriminator only; no new authority.
 * Default preserves G1287. Explicit 1 selects the bounded G1311 lower39 trial. */
#ifndef OGO_GPU_VA_LAYOUT_H
#define OGO_GPU_VA_LAYOUT_H
#ifndef OGO_GPU_NONSECURE64_VA
#define OGO_GPU_NONSECURE64_VA 0
#endif
#if OGO_GPU_NONSECURE64_VA != 0 && OGO_GPU_NONSECURE64_VA != 1
#error OGO_GPU_NONSECURE64_VA must be exactly 0 or 1
#endif
#if OGO_GPU_NONSECURE64_VA
#define OGO_CP_VA_BASE 0x4000000000ull
#else
#define OGO_CP_VA_BASE 0xf0000000ull
#endif
#define OGO_CP_VA_INITIALIZER {OGO_CP_VA_BASE, OGO_CP_VA_BASE+0x8000ull, OGO_CP_VA_BASE+0x10000ull, OGO_CP_VA_BASE+0x30000ull}
_Static_assert((OGO_CP_VA_BASE & 0x7fffull)==0,"CP ring alignment");
_Static_assert(OGO_CP_VA_BASE+0x31000ull <= (1ull<<39),"fixed BOs fit lower39");
#endif
