#pragma once
#include "local_bank_native.h"
#include "ns_scope.h"
#include "open_smmu_activate_wdm.h"
static const GUID OpenLocalBankQueryGuid={0x55210b02,0xe218,0x4af0,{0x96,0x16,0x4b,0x24,0x81,0x52,0x00,0x19}};
typedef struct {
 INTERFACE Interface;PDEVICE_OBJECT ProviderPdo;
 NTSTATUS(*Reserve)(PVOID,OLB_NATIVE*,CGH_NATIVE*);
 NTSTATUS(*Qualify)(PVOID,OLB_NATIVE*,OLB_CLAIM*);
 NTSTATUS(*BindRequest)(PVOID,OLB_NATIVE*,OSMA_REQUEST*);
 NTSTATUS(*CheckBank)(PVOID,OLB_NATIVE*,const OSMA_REQUEST*);
 NTSTATUS(*PinProgramming)(PVOID,OLB_NATIVE*,const OSMA_REQUEST*);
 NTSTATUS(*ReleaseUnpublished)(PVOID,OLB_NATIVE*);
 NTSTATUS(*ConnectFault)(PVOID,OLB_NATIVE*,PVOID*);
 NTSTATUS(*CheckFault)(PVOID,OLB_NATIVE*,PVOID,const OSMA_REQUEST*);
 NTSTATUS(*DisconnectFaultUnpublished)(PVOID,OLB_NATIVE*,PVOID*);
 NTSTATUS(*EnterNs)(PVOID,OLB_NATIVE*,PVOID,PVOID,OPEN_NS_SCOPE*);
 NTSTATUS(*CheckNs)(PVOID,OLB_NATIVE*,PVOID,PVOID,const OPEN_NS_SCOPE*);
 NTSTATUS(*LeaveNs)(PVOID,PVOID,OPEN_NS_SCOPE*);
 NTSTATUS(*PromoteRuntime)(PVOID,OLB_NATIVE*,PVOID,PVOID,const OPEN_NS_SCOPE*,OSMA_NATIVE_IO*);
}OPEN_LOCAL_BANK_INTERFACE;
/* Source-owned kernel ABI only. Actual CGH/MMU1 objects/threads/token ledger
 * are verified; this is not a vendor ABI, user IOCTL or permission boolean. */
typedef struct {OPEN_LOCAL_BANK_INTERFACE Api;OLB_NATIVE Native;CGH_NATIVE*Hold;BOOLEAN QuerySucceeded,Bound;}OPEN_LOCAL_BANK_CLIENT;
NTSTATUS OpenLocalBankConnect(OPEN_LOCAL_BANK_CLIENT*,CGH_NATIVE*);
NTSTATUS OpenLocalBankDisconnectUnpublished(OPEN_LOCAL_BANK_CLIENT*);
