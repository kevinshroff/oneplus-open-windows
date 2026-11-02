/* SPDX-License-Identifier: MIT */
#ifndef OPEN_BATTERY_MINICLASS_H
#define OPEN_BATTERY_MINICLASS_H
#include <ntddk.h>
#include <batclass.h>
#include "battery_cache.h"
typedef struct { FAST_MUTEX Lock; OB_CACHE State; } OPEN_BATTERY_PAIR;
typedef struct { OPEN_BATTERY_PAIR *Pair; ULONG Gauge; } OPEN_BATTERY_DEVICE;
/* Owner initializes this at PASSIVE_LEVEL and supplies one stable context per
 * gauge. No DriverEntry, root enumeration, battery class registration, IOCTL to
 * inject readings, resource mapping, timer or installation is supplied here.
 * The future PnP/resource owner must publish complete paired readings, call
 * ObTick at <=5-second intervals even on error, invalidate before surrendering
 * its lease and drain callbacks/notifications before class-device destruction.
 */
void OpenBatteryInitialize(OPEN_BATTERY_PAIR *);
int OpenBatteryBeginOwner(OPEN_BATTERY_PAIR *,uint64_t,ULONG *);
int OpenBatteryPublish(OPEN_BATTERY_PAIR *,const OB_BATCH *,ULONG *);
int OpenBatteryTick(OPEN_BATTERY_PAIR *,ULONG *);
int OpenBatteryInvalidate(OPEN_BATTERY_PAIR *,ULONG *);
NTSTATUS OpenBatteryCallbacks(OPEN_BATTERY_DEVICE *,BATTERY_MINIPORT_INFO *);
#endif
