/* SPDX-License-Identifier: MIT
 * Same-module PMIC observer coordinator. Lock from route/prior-idle checks
 * through completion/data copy. Never hold across the persistent touch lease
 * or a sampling interval. An uncertain issued command poisons before unlock.
 */
#include <ntddk.h>
#include "g100_bus.h"
static KMUTEX BusMutex;
static volatile LONG Ready,Poisoned,Owners,PeakOwners;
static volatile LONG64 Acquires,Releases,Timeouts,Denied;
void G100BusInitialize(void)
{
 KeInitializeMutex(&BusMutex,0);InterlockedExchange(&Ready,1);
}
int G100BusAcquire(ULONG *held,int (*available)(void *),void *context)
{
 LARGE_INTEGER wait;NTSTATUS status;unsigned i;
 if(!held||*held||!available||KeGetCurrentIrql()!=PASSIVE_LEVEL||
    !InterlockedCompareExchange(&Ready,0,0)){InterlockedIncrement64(&Denied);return 0;}
 wait.QuadPart=-10000; /* cancellable one-millisecond slices; at most100 */
 for(i=0;i<100;i++){
  if(InterlockedCompareExchange(&Poisoned,0,0)||!available(context)){InterlockedIncrement64(&Denied);return 0;}
  status=KeWaitForSingleObject(&BusMutex,Executive,KernelMode,FALSE,&wait);
  if(status==STATUS_TIMEOUT)continue;
  if(status!=STATUS_SUCCESS){InterlockedIncrement64(&Denied);return 0;}
  if(InterlockedCompareExchange(&Poisoned,0,0)||!available(context)){
   KeReleaseMutex(&BusMutex,FALSE);InterlockedIncrement64(&Denied);return 0;
  }
  *held=1;InterlockedIncrement64(&Acquires);
  if(InterlockedIncrement(&Owners)!=1){InterlockedExchange(&Poisoned,1);G100BusRelease(held,1);return 0;}
  InterlockedExchange(&PeakOwners,1);return 1;
 }
 InterlockedIncrement64(&Timeouts);return 0;
}
void G100BusRelease(ULONG *held,int uncertain)
{
 if(!held||!*held){InterlockedExchange(&Poisoned,1);return;}
 if(uncertain)InterlockedExchange(&Poisoned,1);
 *held=0;InterlockedDecrement(&Owners);InterlockedIncrement64(&Releases);
 KeReleaseMutex(&BusMutex,FALSE);
}
void G100BusStatus(G100_BUS_STATUS *out)
{
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=1;
 out->Ready=(ULONG)InterlockedCompareExchange(&Ready,0,0);
 out->Poisoned=(ULONG)InterlockedCompareExchange(&Poisoned,0,0);
 out->Owners=(ULONG)InterlockedCompareExchange(&Owners,0,0);
 out->PeakOwners=(ULONG)InterlockedCompareExchange(&PeakOwners,0,0);
 out->Acquires=(ULONGLONG)InterlockedCompareExchange64(&Acquires,0,0);
 out->Releases=(ULONGLONG)InterlockedCompareExchange64(&Releases,0,0);
 out->Timeouts=(ULONGLONG)InterlockedCompareExchange64(&Timeouts,0,0);
 out->Denied=(ULONGLONG)InterlockedCompareExchange64(&Denied,0,0);
}
