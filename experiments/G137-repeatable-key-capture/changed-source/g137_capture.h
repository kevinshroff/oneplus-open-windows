/* SPDX-License-Identifier: MIT */
#ifndef G137_CAPTURE_H
#define G137_CAPTURE_H
#include <stdint.h>
#define G137_CAPTURE_BYTES 139720u
#define G137_CAPTURE_SLOTS 32u
#define G137_STATE_MAGIC 0x3159454b37333147ULL /* G137KEY1 */
enum {G137_EMPTY=0,G137_BUSY=1,G137_READY=2,G137_FAULT=3};
typedef struct {
 uint32_t Phase,Count,Retired,SlotMaps;
 uint64_t CurrentNonce,LastRetiredNonce,TotalMaps,Used[G137_CAPTURE_SLOTS];
} G137_LEDGER;
typedef struct {
 uint32_t Size,Version;uint64_t Magic;
 uint32_t Phase,Captures,Retirements,Slots;
 uint64_t CurrentNonce,LastRetiredNonce,TotalMaps;
 uint32_t SlotMaps,Reserved;
} G137_STATE;
/* The owning WDF sequential queue serializes these calls. This core has no
 * hardware callbacks and does not reset an observer-bus poison/fault latch.
 * Retirement acknowledges byte-for-byte receipt, not external persistence;
 * the project client independently saves, syncs, reopens and verifies the file.
 */
void G137CaptureInit(G137_LEDGER *);
unsigned G137CaptureCanBegin(const G137_LEDGER *,uint64_t);
unsigned G137CaptureBegin(G137_LEDGER *,uint64_t);
unsigned G137CaptureComplete(G137_LEDGER *,uint32_t,unsigned);
unsigned G137CaptureRetire(G137_LEDGER *,uint64_t,const void *,const void *,uint32_t);
void G137CaptureState(const G137_LEDGER *,G137_STATE *);
#endif
