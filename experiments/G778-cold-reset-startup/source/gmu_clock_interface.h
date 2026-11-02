/* SPDX-License-Identifier: MIT. Trusted kernel project interface only. */
#ifndef OPEN_GMU_CLOCK_INTERFACE_H
#define OPEN_GMU_CLOCK_INTERFACE_H
#include "broker/open_clock_interface.h"
static const GUID OpenGmuClockQueryGuid={0x55210d06,0xe218,0x4af0,{0x96,0x16,0x4b,0x24,0x81,0x52,0x00,0x19}};
typedef struct {ULONG Size,Version,Branches[6],OwnedMask,DelayRequestMask,Bit0ConfirmedMask,RootCfg;ULONGLONG Generation;}OPEN_GMU_CLOCK_SNAPSHOT;
typedef struct {
 INTERFACE Interface;PDEVICE_OBJECT ProviderPdo;
 NTSTATUS (*Acquire)(PVOID,const OPEN_CLOCK_CLIENT*,ULONGLONG*);
 /* Caller already holds its actual cold physical exclusion. Drained callback
  * must bind the fresh cold/reset hardware proof and same held thread; a
  * private never-published RAM callback cannot satisfy this contract. */
 NTSTATUS (*ReleaseCold)(PVOID,ULONGLONG);
 /* Read-only Witness permits actual same-thread MMU1 owner-lock reentry,
  * so a future active proof can revalidate without recursively locking.
  * Acquire/ReleaseCold never permit reentry. */
 NTSTATUS (*Witness)(PVOID,ULONGLONG,OPEN_GMU_CLOCK_SNAPSHOT*);
}OPEN_GMU_CLOCK_INTERFACE;
#endif
