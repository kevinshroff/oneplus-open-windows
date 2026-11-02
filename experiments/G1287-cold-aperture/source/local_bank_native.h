/* Private source-project entrypoints, no user dispatch/IOCTL or vendor ABI. */
#pragma once
#include <ntifs.h>
#include "cold_hold_native.h"
#include "local_bank.h"
#include "open_smmu_activate.h"
typedef struct {PDEVICE_OBJECT Fdo;CGH_NATIVE *Hold;ULONGLONG Id,Generation,StopSerial;BOOLEAN Referenced,ProgramPinned;}OLB_NATIVE;
/* The caller supplies the actual referenced MMU1 FDO from its source owner,
 * not a PDO/physical address. This private binding is compiled inside that
 * owner; local_bank_interface.h supplies the source-only typed kernel DDI
 * and real retained-FileObject consumer. Current installed drivers do not
 * expose it, and no activation caller is automatically dispatched.
 * Keep this binding, Hold/Life/CGH code and MMU1 context/code pinned until
 * successful unpublished release, or reset after programming/uncertainty. */
NTSTATUS OlbNativeReserve(OLB_NATIVE*,PDEVICE_OBJECT,CGH_NATIVE*);
/* Preferred real constructor obtains MMU1 FDO from the retained GMU clock
 * FileObject; no object-manager lookup or caller-invented FDO needed. */
NTSTATUS OlbNativeReserveFromHold(OLB_NATIVE*,CGH_NATIVE*);
NTSTATUS OlbNativeQualify(OLB_NATIVE*,OLB_CLAIM*);
/* Sets only real bank/ASID/slot and Bank reference. Other OSMA proofs remain
 * caller-produced and mandatory. No security/table/IRQ/physical boolean set. */
NTSTATUS OlbNativeBindRequest(OLB_NATIVE*,OSMA_REQUEST*);
NTSTATUS OlbNativeCheckBank(OLB_NATIVE*,const OSMA_REQUEST*);
NTSTATUS OlbNativePinProgramming(OLB_NATIVE*,const OSMA_REQUEST*);
NTSTATUS OlbNativeReleaseUnpublished(OLB_NATIVE*);
