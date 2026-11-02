/* SPDX-License-Identifier: MIT */
#ifndef G401_PUBLISH_H
#define G401_PUBLISH_H
#include <Uefi.h>
#include "g401_transport.h"
#include "g403_platform.h"
typedef struct {
 UINT32 Prepared,Attempted,Stage,RemovedMask,InstalledMask,RootPublished;
 UINT32 RollbackAttempted,RollbackFailed;
 EFI_STATUS Status,RollbackStatus;
} G401_PUBLICATION_REPORT;
typedef struct {
 UINT32 Magic,Version,Bytes,Reserved;G401_REPORT Transport;G403_RESULT Sid;
 G401_PUBLICATION_REPORT Publication;UINT64 GateStatus,IoStatus;
} G401_FLOW_REPORT;
_Static_assert(sizeof(G401_FLOW_REPORT)==3480,"G423 OWTRv2 report ABI");
EFI_STATUS G401PreparePublication(G401_PUBLICATION_REPORT*);
EFI_STATUS G401PublishRoot(const G401_REPORT*,BOOLEAN,G403_GATE,void*,G401_PUBLICATION_REPORT*);
#endif
