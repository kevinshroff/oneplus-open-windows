/* SPDX-License-Identifier: MIT */
#ifndef G100_BUS_H
#define G100_BUS_H
/* One native module owns the shared observer. No user supplied addresses. */
void G100BusInitialize(void);
int G100BusAcquire(ULONG *held,int (*available)(void *),void *context);
void G100BusRelease(ULONG *held,int uncertain);
typedef struct {
 ULONG Size,Version,Ready,Poisoned,Owners,PeakOwners;
 ULONGLONG Acquires,Releases,Timeouts,Denied;
} G100_BUS_STATUS;
void G100BusStatus(G100_BUS_STATUS *out);
#endif
