/* SPDX-License-Identifier: MIT */
#ifndef OPEN_GUARDED_ADSP_H
#define OPEN_GUARDED_ADSP_H
#include <Uefi.h>
#include "OpenKernelFootprint.h"
#include "OpenDspAdmission.h"
#define G134_MAGIC 0x3150534434333147ULL
typedef struct {
 UINT32 Size,Version;
 UINT64 Magic,Status[8],FinalStatus,ScmSlot,OriginalMethod,WrapperMethod,CpuEl;
 UINT64 CpuPages,CpuQueries,CpuFirstBad,CpuReadPar,CpuWritePar;
 UINT32 Flags,PilRequests,Count,Fault,Phase[2],AuthEnteredMask,AuthAcceptedMask;
 UINT32 CpuRefusal,GopCount,HookStores,FatalRestore;
 OP_RECORD Records[OP_RECORDS];
} G134_REPORT;
EFI_STATUS OpenRunGuardedAdsp(BOOLEAN SourceReady,OPEN_KERNEL_REPORT,BOOLEAN *MayContinue);
CONST G134_REPORT *OpenGetGuardedAdspReport(VOID);
#endif
