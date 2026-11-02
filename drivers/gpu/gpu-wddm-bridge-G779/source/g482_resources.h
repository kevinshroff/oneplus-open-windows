/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#pragma once
#include "a740_hal.h"
/* Four nonoverlapping RW device grants plus the source GCC RO clock page.
 * GMU CORE and CX_MISC are subviews of ONE map, never independent aliases. */
typedef enum {G482_GPU,G482_RSCC,G482_GMU,G482_PDC,G482_GCC,G482_BANKS} G482_BANK;
typedef struct {
 PVOID Cpu[G482_BANKS];PDEVICE_OBJECT Pdo;ULONG SeenMask,MappedMask,MissingMask,ObservedDescriptors;
 NTSTATUS Status;BOOLEAN Initialized,Bound;
} G482_BINDING;
VOID G482Initialize(G482_BINDING *);
NTSTATUS G482Bind(G482_BINDING *,PDEVICE_OBJECT,PCM_RESOURCE_LIST);
/* No master/owner may still use these mappings when release is called. The
 * adapter composition enforces actual fresh-stop before reaching this API. */
NTSTATUS G482Release(G482_BINDING *);
/* Internal assigned-resource accesses only. Callers hold the real existing
 * owner lease/rundown. No method discovers PA, maps on demand or grants D0. */
NTSTATUS G482GpuRead(G482_BINDING *,ULONG,PULONG);
NTSTATUS G482GpuWrite(G482_BINDING *,ULONG,ULONG);
NTSTATUS G482CoreRead(G482_BINDING *,ULONG,PULONG);
NTSTATUS G482CoreWrite(G482_BINDING *,ULONG,ULONG);
NTSTATUS G482TcmRead(G482_BINDING *,ULONG region,ULONG offset,PULONG);
NTSTATUS G482TcmWrite(G482_BINDING *,ULONG region,ULONG offset,ULONG);
NTSTATUS G482RscRead(G482_BINDING *,ULONG,PULONG);
NTSTATUS G482RscWrite(G482_BINDING *,ULONG,ULONG);
NTSTATUS G482PdcRead(G482_BINDING *,ULONG,PULONG);
NTSTATUS G482PdcWrite(G482_BINDING *,ULONG,ULONG);
NTSTATUS G482CxRead(G482_BINDING *,ULONG,PULONG);
NTSTATUS G482CxWrite(G482_BINDING *,ULONG,ULONG);
NTSTATUS G482ReadClock(G482_BINDING *,ULONGLONG,PULONG);
NTSTATUS G482RequirePoweredHandoff(G482_BINDING *);
