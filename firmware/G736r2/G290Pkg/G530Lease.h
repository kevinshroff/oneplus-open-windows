#ifndef G530_LEASE_H
#define G530_LEASE_H
#include <Uefi.h>
#include <Protocol/EFIClock.h>
#include "g290_power_report.h"
#pragma pack(push,1)
typedef struct {
 UINT64 Bsp,DalClient,Head,RefNode,Next,RefOwner;
 UINT32 NodeFlags,DomainFlags,Bypass,Reserved;
 UINT16 NodeRef,NodeSupp,DomainRef,DomainSupp,ClientRef,ClientSupp;
 UINT32 Pad;
} G530_REF;
typedef struct {
 G290_ACPI_HEADER Header;UINT32 Version,Stage;UINT64 Status;
 UINT64 ImageBase,ClockId,Client;
 G530_REF Ref[2];
 UINT64 EnableStatus,IsOnStatus,IsEnabledStatus;
 UINT32 IsOn,IsEnabled,LeaseAccepted,BindStage;UINT8 TextSha[32];
 UINT32 PoolCheckedNodes[2];
} G530_REPORT;
#pragma pack(pop)
EFI_STATUS G530Bind(EFI_CLOCK_PROTOCOL*,UINTN*);
EFI_STATUS G530Before(EFI_CLOCK_PROTOCOL*);
EFI_STATUS G530After(EFI_CLOCK_PROTOCOL*,EFI_STATUS);
EFI_STATUS G530On(EFI_CLOCK_PROTOCOL*,UINT32);
VOID G530Init(VOID);
G530_REPORT *G530Report(VOID);
#endif
