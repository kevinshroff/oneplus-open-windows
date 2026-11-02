/* SPDX-License-Identifier: MIT
 * Finite main-image experiment checks. No global DMA/stage2 ownership claim.
 * Read-only MMIO observations are not a production power-management lease.
 * Call after successful original MEM_SETUP, then on both sides of verification.
 * Serialized, one-use module; a failed attempt never opens another attempt.
 */
#ifndef OPEN_MAIN_ADMISSION_H
#define OPEN_MAIN_ADMISSION_H
#include <Uefi.h>
typedef VOID (*OPEN_MAIN_LOG)(CONST CHAR8 *,...);
typedef struct {
 UINT64 Status,CpuEl,CpuPages,AtQueries,FirstBad,ReadPar,WritePar;
 UINT32 Reason,Clock[5],HwVersion,Demura[2],MmioReads,MmioPages,Complete;
} OPEN_MAIN_CHECK;
typedef struct {
 UINT32 Size,Version,CopyAttempts,RefreshAttempts;
 UINT32 CopyGranted,AcceptedRefreshes,Fault,Reserved;
 UINT64 CopyStatus,RefreshStatus[2];
 OPEN_MAIN_CHECK Check[3];
} OPEN_MAIN_ADMISSION_REPORT;
enum {MAIN_SOURCE=1,MAIN_GCD=2,MAIN_MEMORY_MAP=4,MAIN_CPU=8,
 MAIN_MMIO_MAP=16,MAIN_CLOCK=32,MAIN_VERSION=64,MAIN_DEMURA=128,
 MAIN_ARGUMENT=256,MAIN_BUDGET=512,MAIN_REENTRY=1024};
enum {OMA_SEQUENCE=1,OMA_REENTRANT=2,OMA_CHECK=4};
EFI_STATUS OpenMainAdmissionInit(VOID);
EFI_STATUS OpenMainAuthorizeCopy(BOOLEAN,OPEN_MAIN_LOG);
EFI_STATUS OpenMainRefreshAdmission(BOOLEAN,OPEN_MAIN_LOG);
CONST OPEN_MAIN_ADMISSION_REPORT *OpenGetMainAdmissionReport(VOID);
#endif
