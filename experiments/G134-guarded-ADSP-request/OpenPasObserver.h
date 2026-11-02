/* SPDX-License-Identifier: MIT
 * One-shot diagnostic core. No protocol installation or direct MMIO/SMC.
 * Calls the supplied API; its hardware effects/latency belong to that API.
 * The firmware adapter must verify ownership/ABI, serialize calls on one CPU,
 * and restore its original protocol method. An underlying call can still hang.
 */
#ifndef OPEN_PAS_OBSERVER_H
#define OPEN_PAS_OBSERVER_H
typedef unsigned long long OP_U64;
typedef unsigned int OP_U32;
/* Forward the original PIL buffers:10 argument slots and4 result slots.
 * In particular, legacy SCM reads all10 slots even for a one-argument call. */
#ifndef OP_EFIAPI
#define OP_EFIAPI
#endif
#define OP_RECORDS 16u
#define OP_ERR(n) (0x8000000000000000ULL | (n))
typedef OP_U64 (OP_EFIAPI *OP_SIP)(void *,OP_U32,OP_U32,OP_U64 *,OP_U64 *);
typedef struct {
 OP_U32 Command,ParamId,ImageId,Entered;
 OP_U64 Arguments[3],OriginalStatus,Results[4],ReturnedStatus;
 OP_U32 Returned,Refusal;
} OP_RECORD;
typedef struct {
 OP_SIP Original;
 void *ExpectedThis;
 OP_U32 ABI,Active,Consumed,Busy,Fault,Count,Phase[2];
 OP_U32 AuthEnteredMask,AuthAcceptedMask;
 OP_RECORD Records[OP_RECORDS];
} OP_OBSERVER;
enum {OP_ABI_LEGACY=1,OP_ABI_ARMV8=2};
enum {OP_BAD_ARGUMENT=1,OP_REENTRANT=2,OP_CAPACITY=4,OP_TRANSPORT=8,
 OP_RESULT_HEADER=16,OP_SERVICE_RESULT=32,OP_SHUTDOWN=64,OP_ORDER=128};
void OpenPasInit(OP_OBSERVER *,OP_SIP,void *,OP_U32);
OP_U64 OpenPasArm(OP_OBSERVER *);
OP_U64 OpenPasDisarm(OP_OBSERVER *);
OP_U64 OpenPasCall(OP_OBSERVER *,void *,OP_U32,OP_U32,OP_U64 *,OP_U64 *);
#endif
