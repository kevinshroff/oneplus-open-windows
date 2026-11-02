/* SPDX-License-Identifier: MIT */
#ifndef G465_DDR_H
#define G465_DDR_H
#include <Uefi.h>
#define G465_DDR_REVISION 0x0000000000060000ULL
#define G465_DDR_DETAILS_BYTES 216u
typedef struct {
 UINT32 Size,Version;
 UINT64 Generation,LocateStatus,ProtocolRevision,DetailsStatus;
 UINT32 Attempted,Accepted,RawDeviceType,Manufacturer;
 UINT8 RawDetails[G465_DDR_DETAILS_BYTES];
} G465_DDR_REPORT;
STATIC_ASSERT(sizeof(G465_DDR_REPORT)==272,"G465 report size");
/* No entrypoint/provider loading, frequency operation, raw MMIO or SMC.
 * Generation is supplied by the actual owning checkpoint, not an attestation.
 * Caller must pin the included DDRInfoDxe identity and retain current BS owner.
 */
EFI_STATUS G465ReadCurrentDdr(UINT64 Generation,G465_DDR_REPORT*Report);
#endif
