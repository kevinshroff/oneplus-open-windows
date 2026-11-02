/* SPDX-License-Identifier: MIT */
#ifndef G289_BOOT_VOTES_H
#define G289_BOOT_VOTES_H
#include <stddef.h>
#include "g200_clock.h"
#define G289_VOTES 13u
/* Exact NpaDxe10003. No method takes EFI This. The three unused arguments
 * in old decompiler scalar-request signatures are logging artifacts: original
 * 3558 consumes X0=handle, W1=request; wrapper14a4 forwards unchanged. */
typedef struct {uint32_t Type,Pad;union{uint32_t State;uint64_t Raw;}Data;}G289_QUERY;
typedef struct {
 uint64_t Version,Unused8;
 G200_STATUS(*Create)(const char*,const char*,uint32_t,uint32_t,void*,void**);
 uint64_t Unused24,Unused32;
 G200_STATUS(*Request)(void*,uint32_t);
 uint64_t Unused48Through104[8];
 G200_STATUS(*Available)(const char*,uint32_t*);
 uint64_t Unused120Through168[7];
 G200_STATUS(*Query)(const char*,uint32_t,G289_QUERY*,uint32_t*);
}G289_NPA;
_Static_assert(offsetof(G289_NPA,Create)==16,"NPA Create");
_Static_assert(offsetof(G289_NPA,Request)==40,"NPA scalar");
_Static_assert(offsetof(G289_NPA,Available)==112,"Corrected availability");
_Static_assert(offsetof(G289_NPA,Query)==176,"QueryByName");
_Static_assert(sizeof(G289_QUERY)==16&&offsetof(G289_QUERY,Data)==8,"query ABI");
typedef struct{const char*Resource;const char*Client;uint32_t Request;}G289_SPEC;
extern const G289_SPEC G289Specs[G289_VOTES];
typedef struct {
 uint64_t BootEpoch,OwnerEpoch;
 uint32_t Attempted,CreatedMask,IssuedMask,ReturnedMask,ObservedMask;
 uint32_t FailedIndex,Stage,RetainUntilReset;
 G200_STATUS FirstStatus;
 void*Handle[G289_VOTES];
 uint32_t CachedBefore[G289_VOTES],CachedAfter[G289_VOTES];
}G289_BOOT_VOTES;
/* One attempt per zeroed lifetime context; caller serializes NPA users and
 * earns current lease/pins/resource identity. Retain C and all clients even
 * after failure. No Complete/Delete/disable/retry API. Requests synchronously
 * enter the stock unbounded RPMh wait; an outer timeout cannot bound it.
 * Success means cached NPA aggregate >= fixed requests, NOT physical-on.
 * This primitive never releases PERST, publishes PCI, or accesses RC0.
 */
G200_STATUS G289BootVote(G289_BOOT_VOTES*,G289_NPA*,const G200_LEASE*);
/* EFI-only exact protocol locator, separate source adapter. */
G200_STATUS G289BindNpa(G289_NPA**);
#endif
