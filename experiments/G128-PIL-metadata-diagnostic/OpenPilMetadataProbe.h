/* SPDX-License-Identifier: MIT */
#ifndef OPEN_PIL_METADATA_PROBE_H
#define OPEN_PIL_METADATA_PROBE_H
#define G128_MAGIC 0x314154454d383231ULL
#define G128_CFG_BYTES 568U
typedef struct {
 UINT32 Size,Version;
 UINT64 Magic;
 UINT64 Status[16];
 UINT64 ImageBase[2],ScmTableRva,ScmFunctionRva,SlotAttributes;
 UINT32 Flags,ScmABI,ImagesAttempted,RequestedPasStages;
 UINT64 CachedAddress[2],UncachedAddress[2],UncachedReleaseBytes[2];
 UINT8 InputDigest[32],ConfigDigest[2][32];
 UINT8 Config[2][G128_CFG_BYTES];
 UINT8 CachedDigest[2][32],UncachedDigest[2][32];
} G128_REPORT;
STATIC_ASSERT(sizeof(G128_REPORT)==1608,"G128 fixed report ABI");
/* Read-only protocol inspection plus two metadata/header helpers. No public
 * image load, PAS, shutdown, protocol replacement or DSP memory setup. */
EFI_STATUS OpenRunPilMetadataProbe(BOOLEAN PreflightReady);
#endif
