/* Standalone addition. No existing G182 executable is rebuilt or modified. */
#include <Uefi.h>
#include <Guid/EventGroup.h>
#include <Library/UefiBootServicesTableLib.h>
#include "G203Dispatch.h"
STATIC EFI_EVENT mReady,mAfter,mWork;
STATIC BOOLEAN mReadySeen,mBridgeSeen,mWorkSeen;

STATIC VOID EFIAPI ClearWork(EFI_EVENT Event,VOID *Context)
{
 (VOID)Event;(VOID)Context;
 OpenCoverHandoffRecordSchedule(G203_WORK_ENTERED,EFI_SUCCESS);
 if(mWorkSeen)return;mWorkSeen=TRUE;
 OpenCoverHandoffReadyAttempt();
}
STATIC VOID EFIAPI AfterBridge(EFI_EVENT Event,VOID *Context)
{
 EFI_STATUS status;(VOID)Event;(VOID)Context;
 OpenCoverHandoffRecordSchedule(G203_BRIDGE_ENTERED,EFI_SUCCESS);
 if(mBridgeSeen)return;mBridgeSeen=TRUE;
 /* At TPL_CALLBACK, the ordinary work event is queued, not run inline. It
  * joins the tail behind the already queued BDS PostReady callback. */
 status=gBS->SignalEvent(mWork);
 OpenCoverHandoffRecordSchedule(G203_WORK_SIGNALED,status);
}
STATIC VOID EFIAPI PrimaryReady(EFI_EVENT Event,VOID *Context)
{
 EFI_STATUS status;(VOID)Event;(VOID)Context;
 OpenCoverHandoffRecordSchedule(G203_READY_ENTERED,EFI_SUCCESS);
 if(mReadySeen)return;mReadySeen=TRUE;
 /* BDS already published OPRES182 before console connection. Append the
  * report now so the original SSDT order/index remains intact. */
 status=OpenPublishCoverHandoffReport();
 OpenCoverHandoffRecordSchedule(G203_REPORT_PUBLISHED,status);
 if(EFI_ERROR(status))return;
 /* BDS has registered PostReady by the time it signals the primary group. */
 status=gBS->CreateEventEx(EVT_NOTIFY_SIGNAL,TPL_CALLBACK,AfterBridge,NULL,&gEfiEventAfterReadyToBootGuid,&mAfter);
 OpenCoverHandoffRecordSchedule(G203_AFTER_CREATED,status);
}
EFI_STATUS EFIAPI G203DriverEntry(EFI_HANDLE ImageHandle,EFI_SYSTEM_TABLE *SystemTable)
{
 EFI_STATUS status;(VOID)ImageHandle;(VOID)SystemTable;
 /* Preparation allocates only owned NVS and notifications; the report table
  * is appended at Ready. Hardware profile, full tables, MMIO and pixels are
  * checked only in the actual operation. */
 status=OpenPrepareCoverHandoff();OpenCoverHandoffRecordSchedule(G203_PREPARED,status);
 if(EFI_ERROR(status))return EFI_SUCCESS;
 status=gBS->CreateEvent(EVT_NOTIFY_SIGNAL,TPL_CALLBACK,ClearWork,NULL,&mWork);
 OpenCoverHandoffRecordSchedule(G203_WORK_CREATED,status);
 if(EFI_ERROR(status))return EFI_SUCCESS;
 status=gBS->CreateEventEx(EVT_NOTIFY_SIGNAL,TPL_CALLBACK,PrimaryReady,NULL,&gEfiEventReadyToBootGuid,&mReady);
 OpenCoverHandoffRecordSchedule(G203_READY_CREATED,status);
 /* Keep the module resident for any already registered report/observer
  * callbacks, including a preparation/scheduling failure. No unload entry. */
 return EFI_SUCCESS;
}
