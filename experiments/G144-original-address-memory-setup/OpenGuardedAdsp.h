/* SPDX-License-Identifier: MIT */
#ifndef OPEN_GUARDED_ADSP_H
#define OPEN_GUARDED_ADSP_H
#include <Uefi.h>
#include "OpenKernelFootprint.h"
#include "OpenDspAdmission.h"
#include "OpenScmErrorCapture.h"
#define G136_MAGIC 0x3150534436333147ULL
typedef struct {
 UINT32 Size,Version;
 UINT64 Magic,Status[8],FinalStatus,ScmSlot,OriginalMethod,WrapperMethod,CpuEl;
 UINT64 CpuPages,CpuQueries,CpuFirstBad,CpuReadPar,CpuWritePar;
 UINT32 Flags,PilRequests,Count,Fault,Phase[2],AuthEnteredMask,AuthAcceptedMask;
 UINT32 CpuRefusal,GopCount,HookStores,FatalRestore;
 OP_RECORD Records[OP_RECORDS];
} G136_REPORT;
EFI_STATUS OpenRunGuardedAdsp(BOOLEAN SourceReady,OPEN_KERNEL_REPORT,BOOLEAN *MayContinue);
CONST G136_REPORT *OpenGetGuardedAdspReport(VOID);
CONST OL_REPORT *OpenGetScmErrorReport(VOID);
#endif
