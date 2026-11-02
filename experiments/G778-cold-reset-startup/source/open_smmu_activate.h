/* SPDX-License-Identifier: MIT -- source-owned Open GMU SID5 activation core. */
#ifndef OPEN_SMMU_ACTIVATE_H
#define OPEN_SMMU_ACTIVATE_H
#include "open_smmu_handoff.h"
#include "vendor/ArmSmmu4KProgram.h"
enum osma_need {OSMA_CURRENT=1,OSMA_PHYSICAL_STOP=2,OSMA_BANK_STREAM=4,
 OSMA_SECURE_ACCESS=8,OSMA_TABLES_VISIBLE=16,OSMA_FAULT_HANDLER=32,OSMA_NS_BLOCK=64};
/* Existing real owner boundaries, not success flags. Each opaque handle must
 * be a retained actual producer reference. check verifies the current held
 * thread/generations, physical stop, exclusive bank+ASID+SID5 slot, secure NS
 * access, real audited/device-visible table pool, this fixed source-supported
 * cache/walk/bypass profile and installed bank fault handler.
 * It may not reenter this core or release the exclusion. No default producer
 * is supplied: inactive never-published RAM proofs DO NOT satisfy this ABI.
 * NsBlock check additionally owns dedicated NS-global configuration/quiescence
 * and the global fault IRQ/handler enabled by NSCR0 GFIE/GCFGFIE; a bank-only
 * fault handler cannot satisfy that whole-block scope. The existing Fault
 * reference must cover the actually enabled global and context IRQ lifetimes.
 * GMU SID5 does not require the unrelated G433 PAS13/ZAP result; optional Pas
 * is retained for a platform producer that genuinely requires its own service.
 */
typedef struct OSMA_PROOFS {
 void *Context;const void *D0,*Bank,*Security,*Tables,*Fault,*Pas,*NsBlock;
 uint64_t Generation,StopSerial;
 int (*check)(void *,const struct OSMA_PROOFS *,unsigned needs,
              unsigned sid,unsigned bank,unsigned asid,unsigned slot);
}OSMA_PROOFS;
typedef struct {
 ArmSmmu4KIo Io;OSMA_PROOFS Proof;
 const ArmSmmu4KConfig *TableConfig;const ArmSmmu4KResult *TableResult;
 unsigned Bank,Asid,Slot,PollBudget;
 int (*WaitOneUs)(void *IoCookie);
}OSMA_REQUEST;
enum osma_status {OSMA_OK,OSMA_ARGUMENT,OSMA_OWNER,OSMA_IO,OSMA_HANDOFF,
 OSMA_BANK_BUSY,OSMA_GLOBAL_REQUIRED,OSMA_MISMATCH,OSMA_TIMEOUT,OSMA_FAULT};
enum osma_phase {OSMA_NEW,OSMA_ADMITTED,OSMA_MUTATING,OSMA_ACTIVE,OSMA_DISABLED,OSMA_POISONED};
typedef struct {
 enum osma_phase Phase;enum osma_status Status;
 uint32_t Writes,Reads,Polls,MustRetain,ScopePinned,Fault;int LastOwnerStatus;
 uint32_t DesiredNscr0,BeforeSctlr,FinalS2cr,Bank,Asid,Slot;
 uint64_t ActivationStopSerial;OSMA_PROOFS BoundProof;void *IoIdentity;
 OSH_SNAPSHOT Before,Expected,After;OSH_REPORT Handoff;
 ArmSmmu4KContextImage Image,Readback;
}OSMA_SESSION;
/* Fresh session, owner holds/pins every handle/backing through completion or
 * reset. No retry after any attempted mutation failure; no automatic rollback.
 * Hardware writes exist in this implementation but no caller invokes it in
 * any composed driver. It does not start GMU/CP or declare graphics ready. */
enum osma_status OsmaActivate(OSMA_SESSION*,const OSMA_REQUEST*);
/* Caller re-proves actual physical stop, not inactive allocation serials.
 * Leaves owned SID5 fault-gated; confirms disabled+TLB completion. It does not
 * free a table, release bank/ASID/power/security/IRQ references or restore an
 * earlier foreign page table. Any uncertain failure remains sticky/retained. */
enum osma_status OsmaDisableStopped(OSMA_SESSION*,const OSMA_REQUEST*);
/* Source-owned pre-handoff fresh active image check, still requires real stop. */
enum osma_status OsmaWitnessActiveHeld(OSMA_SESSION*,const OSMA_REQUEST*);
#endif
