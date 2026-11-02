/* SPDX-License-Identifier: MIT
 * One-use verification of the original main loader's fixed89 extents.
 * The adapter must establish real target access/ownership before reads and
 * revalidate it after hashing. Callbacks may fail or fault; this code itself
 * performs no physical access, MMIO, PAS call, allocation or target write.
 */
#ifndef OPEN_MAIN_PAYLOAD_H
#define OPEN_MAIN_PAYLOAD_H
#include <Uefi.h>
#define OMP_EXTENTS 89U
#define OMP_CHUNK 4096U
typedef EFI_STATUS (EFIAPI *OMP_READ)(VOID *,UINT64,UINTN *,VOID *);
typedef unsigned (EFIAPI *OMP_PREDICATE)(VOID *);
typedef struct {
 UINT32 Index,Kind,Complete,Reserved;
 UINT64 Status,ReadBytes,FailureAddress;
 UINT8 Digest[32];
} OMP_EXTENT_RESULT;
typedef struct {
 UINT32 Size,Version,Attempted,Complete;
 UINT64 Status,ReadBytes,VerifiedBytes,LastAddress,LastRequest,LastActual,LastReadStatus,FailureAddress;
 UINT32 Fault,ReadCalls,OwnerChecks,AdmissionCalls,CompletedExtents,CompletedFiles,CompletedZeroTails,CurrentIndex;
 UINT32 Phase,Reserved[3];
 OMP_EXTENT_RESULT Extents[OMP_EXTENTS];
} OMP_REPORT;
typedef struct {
 UINT32 Initialized,Busy;
 OMP_READ Read;
 OMP_PREDICATE Admit,Owner;
 VOID *Context;
 OMP_REPORT Report;
 UINT8 Scratch[OMP_CHUNK];
} OMP_CHECKER;
enum {OMP_REENTRANT=1,OMP_OWNER=2,OMP_ADMISSION=4,OMP_READ_ERROR=8,
      OMP_READ_SIZE=16,OMP_HASH=32,OMP_ZERO=64,OMP_POST_ADMISSION=128};
enum {OMP_PRE=1,OMP_DATA=2,OMP_POST=3,OMP_DONE=4};
/* Caller supplies a zero-initialized, private state that outlives all callbacks.
 * Reinitializing a consumed state never opens another verification attempt. */
EFI_STATUS OpenMainPayloadInit(OMP_CHECKER *,OMP_READ,OMP_PREDICATE,OMP_PREDICATE,VOID *);
EFI_STATUS OpenMainPayloadVerify(OMP_CHECKER *);
#endif
