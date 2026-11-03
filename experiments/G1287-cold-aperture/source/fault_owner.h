#pragma once
#include <ntifs.h>
#include "local_bank_native.h"
/* Bootstrap scope CB2 only; actual local allocation must have selected2. */
typedef struct {ULONG Vector;KIRQL Irql;KAFFINITY Affinity;}OF_IRQ_GRANT;
#include "fault_policy.h"
typedef struct OF_OWNER OF_OWNER;
typedef struct {OF_OWNER*Owner;ULONG Index;}OF_ISR_CONTEXT;
struct OF_OWNER {OF_IRQ_GRANT Grant[3];BOOLEAN GrantsValid;PVOID Map[3];PKINTERRUPT Interrupt[3];KSPIN_LOCK Lock;KIRQL SyncIrql;ULONG KnownMask,UncertainMask;OF_ISR_CONTEXT Isr[3];OLB_NATIVE*Bank;ULONGLONG Generation;volatile LONG Armed;ULONG Retain,Connecting;OF_JOURNAL Journal;
#if OGO_GPU_FIRST_FAULT_TUPLE
 PVOID TupleOwner; /* Same nonpaged enclosing OSM_CONTEXT; ISR joined before free. */
#endif
};
/* W1C-only policy: invalid allones is fatal+no-store; zero not handled;
 * valid fault is latched fatal for startup and only observed status ACKed. */

