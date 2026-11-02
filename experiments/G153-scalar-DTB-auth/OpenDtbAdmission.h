/* SPDX-License-Identifier: MIT
 * Finite DTB-only experiment checks. No global DMA/stage2 ownership claim.
 * Read-only MMIO observations are not a production power-management lease.
 */
#ifndef OPEN_DTB_ADMISSION_H
#define OPEN_DTB_ADMISSION_H
#include <Uefi.h>
typedef VOID (*OPEN_DTB_LOG)(CONST CHAR8 *,...);
typedef struct {
 UINT64 Status,CpuEl,CpuPages,AtQueries,FirstBad,ReadPar,WritePar;
 UINT32 Reason,Clock[5],HwVersion,Demura[2],MmioReads,MmioPages,Complete;
} OPEN_DTB_CHECK;
typedef struct {
 UINT32 Size,Version,CopyAttempts,PayloadAttempts;
 UINT32 CopyGranted,PayloadHashed,PayloadMatched,HashOutcome;
 UINT64 CopyStatus,PayloadStatus;
 OPEN_DTB_CHECK Check[3];
 UINT8 Digest[32];
} OPEN_DTB_ADMISSION_REPORT;
enum {DTB_SOURCE=1,DTB_GCD=2,DTB_MEMORY_MAP=4,DTB_CPU=8,
 DTB_MMIO_MAP=16,DTB_CLOCK=32,DTB_VERSION=64,DTB_DEMURA=128,
 DTB_ARGUMENT=256,DTB_BUDGET=512};
EFI_STATUS OpenDtbAdmissionInit(VOID);
EFI_STATUS OpenDtbAuthorizeCopy(BOOLEAN,OPEN_DTB_LOG);
EFI_STATUS OpenDtbVerifyPayload(BOOLEAN,OPEN_DTB_LOG);
CONST OPEN_DTB_ADMISSION_REPORT *OpenGetDtbAdmissionReport(VOID);
#endif
