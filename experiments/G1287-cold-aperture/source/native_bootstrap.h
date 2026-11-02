#pragma once
#include "local_bank_interface.h"
#include "nc_visibility.h"
#include "aperture_policy.h"
struct _OAS_BOOTSTRAP;
typedef struct {
 PVOID Context;NTSTATUS(*Run)(PVOID,struct _OAS_BOOTSTRAP*);
 BOOLEAN Attempted,Completed;ULONG Transport;NTSTATUS Status;
 BOOLEAN DispatchKnown;ULONGLONG DispatchStatus;
 ULONGLONG OwnerGeneration,RunId,Generation,Serial,GpuId,GpuGeneration,GpuSerial;
 OAS_SCM_FRAME Frame;
}OAS_COLD_SETUP;
enum oas_state {OAS_CREATED,OAS_OPEN,OAS_ATTEMPTING,OAS_ACTIVE,OAS_RETAINED,OAS_CLOSED};
typedef struct _OAS_BOOTSTRAP {
 KMUTEX Operation;PETHREAD OperationThread;CGH_NATIVE*Hold;OPEN_LOCAL_BANK_CLIENT*Bank;PVOID Fault;
 OSMA_TABLE_BINDING*Tables;OSMA_NATIVE_IO Native;OPEN_NS_SCOPE Scope;
 BOOLEAN ColdConsumed;
 ULONGLONG ProviderGeneration,AllocationGeneration;ULONG BankIndex,Slot;enum oas_state State;NTSTATUS Status;
 OAS_COLD_SETUP Setup;
}OAS_BOOTSTRAP;
/* Moves actual inactive ledger; moves *FaultToken into this owned binding.
 * Bank/Hold storage and callback code remain pinned by the real caller. Every
 * created resource is returned through *out, including a retained failure. */
NTSTATUS OasTakeAndOpen(G321_INACTIVE_RUNTIME*,CGH_NATIVE*,OPEN_LOCAL_BANK_CLIENT*,PVOID*FaultToken,OAS_BOOTSTRAP**out);
/* Low-level synchronous transaction inside the still-held cold scope. On
 * failure caller must immediately abort unpublished state or retain/fail the
 * actual hold; use OasColdActivateFromInactive for the failure-complete prefix.
 * No dispatch invokes either function. */
NTSTATUS OasActivate(OAS_BOOTSTRAP*);
/* Only never-attempted candidate cleanup; no live DMA/disabled proof invented.
 * Reverse order: native/table candidate, actual IRQ token, bank, CGH reset-
 * hold release. Failed/armed/active object remains retained until reset. */
NTSTATUS OasAbortUnpublished(OAS_BOOTSTRAP*);

/* Actual failure-complete prefix for a future real Start/D0 worker. Consumes
 * known cold objects or returns the retained owner through out/caller ledger.
 * Success means actual SMMU activation only, never GMU/HFI/WDDM readiness. */
NTSTATUS OasColdActivateFromInactive(G321_INACTIVE_RUNTIME*,CGH_NATIVE*,OPEN_LOCAL_BANK_CLIENT*,PVOID*,OAS_BOOTSTRAP**);

NTSTATUS OasEnterFirmwareScope(OAS_BOOTSTRAP*);
NTSTATUS OasCurrentRuntime(OAS_BOOTSTRAP*);
NTSTATUS OasHandoffOwnedGbif(OAS_BOOTSTRAP*);
NTSTATUS OasLeaveFirmwareScope(OAS_BOOTSTRAP*,NTSTATUS ActualResult);

/* Real same-thread running command scope; never a stopped witness. */
NTSTATUS OasEnterRunningScope(OAS_BOOTSTRAP*);

NTSTATUS OasColdActivateFromInactiveSetup(G321_INACTIVE_RUNTIME*,CGH_NATIVE*,OPEN_LOCAL_BANK_CLIENT*,PVOID*,OAS_BOOTSTRAP**,const OAS_COLD_SETUP*);
