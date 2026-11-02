/* SPDX-License-Identifier: MIT */
#ifndef OPEN_BATTERY_CACHE_H
#define OPEN_BATTERY_CACHE_H
#include <stdint.h>
#define OB_MAX_AGE_US UINT64_C(30000000)
#define OB_MAX_BATCH_US UINT64_C(2000000)
#define OB_ONLINE 1u
#define OB_DISCHARGING 2u
#define OB_CHARGING 4u
#define OB_CRITICAL 8u
enum { OB_OK, OB_ARGUMENT, OB_NO_DEVICE, OB_NOT_READY, OB_INVALID_DATA,
       OB_OLD_INPUT, OB_OLD_OWNER, OB_EXHAUSTED };
/* Internal producer contract, never a user IOCTL. Both gauges are one batch.
 * OwnerQualified requires an independently established live resource lease;
 * a completed G104 diagnostic does not establish that lease. Time is the
 * owner's interrupt-time clock, not the G104 performance-counter timestamps.
 * PowerKnown means ALL PowerState bits have qualified semantics, including
 * external power and manufacturer critical status. USB presence is insufficient.
 */
typedef struct {
 uint64_t OwnerEpoch, Sequence, BeginUs, EndUs;
 uint32_t OwnerQualified, Complete, Words[2][10], PowerKnown[2], PowerState[2];
} OB_BATCH;
typedef struct {
 uint32_t Tag, TemperatureTenthsKelvin, VoltageMv, RemainingMah, FullMah, Soc;
 int32_t RateMa;
 uint32_t PowerKnown, PowerState;
} OB_READING;
typedef struct { uint32_t Armed, PowerState, Low, High; } OB_NOTIFY;
typedef struct {
 uint64_t OwnerEpoch, LastSequence, EndUs;
 uint32_t Present, LastTag, Exhausted, PendingNotify;
 OB_READING Reading[2];
 OB_NOTIFY Notify[2];
} OB_CACHE;
/* Caller serializes every operation and delivers returned notification bits
 * outside its lock with its own live class-device/PnP rundown reference. */
void ObInitialize(OB_CACHE *);
int ObBeginOwner(OB_CACHE *, uint64_t epoch, uint32_t *notify);
void ObInvalidate(OB_CACHE *, uint32_t *notify);
int ObTick(OB_CACHE *, uint64_t now, uint32_t *notify);
int ObPublish(OB_CACHE *, const OB_BATCH *, uint64_t now, uint32_t *notify);
int ObQueryTag(OB_CACHE *, unsigned gauge, uint64_t now, uint32_t *tag);
int ObRead(OB_CACHE *, unsigned gauge, uint32_t tag, uint64_t now, OB_READING *);
int ObSetNotify(OB_CACHE *, unsigned gauge, uint32_t tag, uint64_t now,
                uint32_t state, uint32_t low, uint32_t high, uint32_t *notify);
int ObDisableNotify(OB_CACHE *, unsigned gauge);
#endif
