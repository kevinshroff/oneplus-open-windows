/* SPDX-License-Identifier: MIT */
#ifndef OPEN_GUARDED_ADSP_H
#define OPEN_GUARDED_ADSP_H
#include <Uefi.h>
#include "OpenKernelFootprint.h"
#include "OpenDspAdmission.h"
#include "OpenScmErrorCapture.h"
#include "OpenDtbAdmission.h"
#include "OpenMainAdmission.h"
#include "OpenMainPayload.h"
#define G151_MAGIC 0x3150534431353147ULL
typedef struct {
 UINT32 Size,Version;
 UINT64 Magic,Status[8],FinalStatus,ScmSlot,OriginalMethod,WrapperMethod,CpuEl;
 UINT64 CpuPages,CpuQueries,CpuFirstBad,CpuReadPar,CpuWritePar;
 UINT32 Flags,PilRequests,Count,Fault,Phase[2],AuthEnteredMask,AuthAcceptedMask;
 UINT32 CpuRefusal,GopCount,HookStores,FatalRestore;
 OP_RECORD Records[OP_RECORDS];
 OPEN_DTB_ADMISSION_REPORT Dtb;
 UINT32 MainEnabled,DtbLoadReturned,DtbPublicSuccess,DtbPublicComplete;
 UINT64 DtbMarkerStatus;
 UINT32 MainLoadReturned,MainPublicSuccess,Reserved[2];
 OPEN_MAIN_ADMISSION_REPORT Main;
 OMP_REPORT Payload;
} G151_REPORT;
EFI_STATUS OpenRunGuardedAdsp(BOOLEAN SourceReady,OPEN_KERNEL_REPORT,BOOLEAN *MayContinue);
CONST G151_REPORT *OpenGetGuardedAdspReport(VOID);
CONST OL_REPORT *OpenGetScmErrorReport(VOID);
#endif
