/* SPDX-License-Identifier: MIT */
#ifndef G467_DDR_H
#define G467_DDR_H
#include "G465Ddr.h"
#pragma pack(push,1)
typedef struct {UINT32 Signature,Length;UINT8 Revision,Checksum,OemId[6];UINT64 OemTableId;UINT32 OemRevision,CreatorId,CreatorRevision;} G467_HEADER;
typedef struct {
 G467_HEADER Header;UINT32 Version,Stage;UINT64 Status;
 UINT64 OwnerImage,ProtocolPa,ProviderBase,ProviderBytes;
 UINT32 GetterRva,IdentityMask,Reserved;
 UINT8 NormalizedTextSha[32],ExpectedProviderFileSha[32];
 G465_DDR_REPORT Details;
} G467_DDR_REPORT;
#pragma pack(pop)
STATIC_ASSERT(sizeof(G467_DDR_REPORT)==432,"OGDD ABI");
/* No GPU prerequisite is derived here. Failure is an independent report. */
VOID G467CaptureDdr(EFI_HANDLE Owner,UINT64 Generation,G467_DDR_REPORT*);
#endif
