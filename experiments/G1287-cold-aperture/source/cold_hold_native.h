/* SPDX-License-Identifier: MIT */
#pragma once
#include <ntifs.h>
#include "g515_lifecycle.h"
#include "gmu_clock_consumer.h"
#include "cold_hold.h"
typedef struct {
 G515_LIFE *Life;G482_BINDING *Io;PETHREAD Thread;ULONGLONG Generation,ClockGeneration,Serial,ReleasedSerial;
 OPEN_GMU_CLOCK_BINDING Clock;CGH_HOLD Hold;BOOLEAN ScopeHeld,Poisoned,BootCommitted;
 NTSTATUS Status;
}CGH_NATIVE;
/* Called only by the real future OPEN0515 Start/D0 worker after G482Bind
 * and actual G515 START/D0 observation. Holds that source mutex through the
 * activation transaction. The current empty-CRS OPEN0549 cannot satisfy it. */
NTSTATUS CghNativeAcquire(CGH_NATIVE*,G515_LIFE*,G482_BINDING*);
NTSTATUS CghNativeCheck(CGH_NATIVE*);
NTSTATUS CghNativeReleaseToReset(CGH_NATIVE*);
/* One release after the actual cold release proof. This is not post-run
 * drain/stop; caller cannot start GMU and reuse this handle to drop clocks. */
NTSTATUS CghNativeLeave(CGH_NATIVE*);

/* Before the first G482 non-halt mutation, consume abort/drain eligibility.
 * Keeps real clock reference/exclusion; grants no SMMU/security/GMU-start right. */
NTSTATUS CghNativeCommitToBoot(CGH_NATIVE*);
NTSTATUS CghNativeCanDispose(CGH_NATIVE*);

/* Real post-lower-START worker observation, replacing the obsolete OGPR/
 * direct-clock G515 admission for this future split resource profile. */
NTSTATUS CghNativeObserveStarted(G515_LIFE*,G482_BINDING*);

/* Permanent removal, no MMIO. Cannot retire retained clocks/hold/boot state.
 * Sets Removed through the actual lifecycle lock before unmapping, so a
 * concurrent new START/acquire cannot enter between revoke and release. */
NTSTATUS CghNativeRetire(CGH_NATIVE*,G515_LIFE*,G482_BINDING*);

/* Actual composed child failure with retained resources: preserve physical
 * halt/clock journals, inhibit new work, and relinquish only caller's own
 * lifecycle software mutex. Never free/disconnect/clean hardware here. */
NTSTATUS CghNativeRetainFailure(CGH_NATIVE*,NTSTATUS);

/* Actual post-handoff current D0/clock/exclusion, explicitly NOT stopped. */
NTSTATUS CghNativeRuntimeCheck(CGH_NATIVE*);

NTSTATUS CghNativeUnhaltResetForBoot(CGH_NATIVE*,PVOID actual_bootstrap);
