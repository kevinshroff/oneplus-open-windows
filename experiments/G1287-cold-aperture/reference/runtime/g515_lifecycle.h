/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#pragma once
#include "g321_runtime.h"
#define G515_MISSING_NATIVE_POWER 1u
#define G515_MISSING_MANAGED_S1 2u
#define G515_MISSING_PHYSICAL_STOP 4u
#define G515_MISSING_BACKING 8u
#define G515_MISSING_PAS 16u
typedef struct {
 KMUTEX Lock;volatile LONG Inhibit;PDEVICE_OBJECT Pdo;G482_BINDING *Io;
 PETHREAD HeldThread;ULONGLONG Generation,ObservationGeneration,SampleTime;
 ULONG Missing,PowerSource,ChildRequests,LastChildUid,SampleMask,Value[7];
 NTSTATUS Status,PropertyStatus;DEVICE_POWER_STATE Requested;
 BOOLEAN Initialized,StartObserved,OsD0Candidate,PostEbsObserved,Removed;
} G515_LIFE;
NTSTATUS G515Initialize(G515_LIFE *,PDEVICE_OBJECT);
NTSTATUS G515StartObserved(G515_LIFE *,G482_BINDING *);
NTSTATUS G515PowerObserved(G515_LIFE *,ULONG DeviceUid,DEVICE_POWER_STATE);
NTSTATUS G515Revoke(G515_LIFE *,BOOLEAN remove);
NTSTATUS G515Dispose(G515_LIFE *);
/* Real awake scope. Success means current DDI/PDO scope + current clock/CX
 * samples under held mutex, never full GMU power/DMA/PAS authorization. */
NTSTATUS G515EnterAwake(G515_LIFE *,ULONGLONG);
NTSTATUS G515CheckAwake(G515_LIFE *,ULONGLONG);
VOID G515LeaveAwake(G515_LIFE *);
VOID G515BuildOwner(G515_LIFE *,G321_OWNER *);
