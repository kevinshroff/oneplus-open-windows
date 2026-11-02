/* SPDX-License-Identifier: MIT
 * One device-owned finite session on a dedicated PASSIVE system thread.
 * No request/user buffer survives dispatch. Stop/close/suspend join the owner
 * before VHF deletion, buffer release or loss of D0. Hardware access is denied
 * after surprise-removal observation. This is still a fixed-platform prototype.
 */
#include <ntifs.h>
#include <wdf.h>
#include <aux_klib.h>
#include <vhf.h>
#include "g92hid_baseline.h"
#include "g92hid_protocol.h"
#include "g92hid_report.h"
#include "g92_input.h"
#include "g92_hwapi.h"

typedef struct {
 VHFHANDLE Handle;KMUTEX Control;ULONG ControlInitialized;
 HANDLE Thread;WDFFILEOBJECT OwnerFile;G92_TRIAL*Result;
 volatile LONG D0,Started,CreateStatus,StartStatus,Entries,Exits,Features,LiveAttempts,LastSubmit;
 volatile LONG State,StopReason,Starts,HardwareCalls,ResultReady,Outcome,StopChecks,StopSeen,Inhibit,ThreadJoined,Phase,PollCycles,ThreadCreateStatus,Removed,StopRequests;
 volatile LONG64 Sequence,BeginUs,EndUs,StopUs;
 G92_INPUT Live;ULONG LastHardwareCode,LiveComplete;
}G92HID_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(G92HID_CONTEXT,G92HIDContext)
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD G92HIDAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP G92HIDCleanup;
EVT_WDF_DEVICE_D0_ENTRY G92HIDD0Entry;
EVT_WDF_DEVICE_D0_EXIT G92HIDD0Exit;
EVT_WDF_DEVICE_SELF_MANAGED_IO_INIT G92HIDIoInit;
EVT_WDF_DEVICE_SELF_MANAGED_IO_SUSPEND G92HIDSuspend;
EVT_WDF_DEVICE_SELF_MANAGED_IO_RESTART G92HIDRestart;
EVT_WDF_DEVICE_SURPRISE_REMOVAL G92HIDSurprise;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G92HIDControl;
EVT_WDF_DEVICE_FILE_CREATE G92HIDFileCreate;
EVT_WDF_FILE_CLEANUP G92HIDFileCleanup;
EVT_VHF_ASYNC_OPERATION G92HIDFeature;
static ULONG Counter(volatile LONG*p){return(ULONG)InterlockedCompareExchange(p,0,0);}
static ULONGLONG TimeValue(volatile LONG64*p){return(ULONGLONG)InterlockedCompareExchange64(p,0,0);}
static void OwnerLock(G92HID_CONTEXT*c){NTSTATUS s=KeWaitForSingleObject(&c->Control,Executive,KernelMode,FALSE,NULL);NT_ASSERT(s==STATUS_SUCCESS);UNREFERENCED_PARAMETER(s);}
static void OwnerUnlock(G92HID_CONTEXT*c){KeReleaseMutex(&c->Control,FALSE);}
static int Available(void*x){return !Counter(&((G92HID_CONTEXT*)x)->Removed);}
static int StopRequested(void*x)
{
 G92HID_CONTEXT*c=x;InterlockedIncrement(&c->StopChecks);
 InterlockedExchange(&c->Phase,c->Result->Trial.Touch.Stage);InterlockedExchange(&c->PollCycles,c->Result->Trial.Touch.Poll.Cycles);
 if(!Counter(&c->StopReason))return 0;InterlockedIncrement(&c->StopSeen);return 1;
}
static void SessionStatus(G92HID_CONTEXT*c,G92_SESSION*out)
{
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=1;out->Magic=G92HID_MAGIC;
 out->State=Counter(&c->State);out->StopReason=Counter(&c->StopReason);out->Starts=Counter(&c->Starts);out->HardwareCalls=Counter(&c->HardwareCalls);out->ResultReady=Counter(&c->ResultReady);out->Outcome=Counter(&c->Outcome);out->StopChecks=Counter(&c->StopChecks);out->StopSeen=Counter(&c->StopSeen);out->Inhibit=Counter(&c->Inhibit);out->ThreadJoined=Counter(&c->ThreadJoined);out->Phase=Counter(&c->Phase);out->PollCycles=Counter(&c->PollCycles);out->ThreadCreateStatus=Counter(&c->ThreadCreateStatus);
 out->BeginUs=TimeValue(&c->BeginUs);out->EndUs=TimeValue(&c->EndUs);out->StopUs=TimeValue(&c->StopUs);out->StopRequests=Counter(&c->StopRequests);
}
static VOID Status(G92HID_CONTEXT*c,G92HID_STATUS*out)
{
 UCHAR table[sizeof(G92HIDExpectedDsdt)];ULONG bytes=0;RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=G92HID_ABI;out->Magic=G92HID_MAGIC;
 out->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);out->Irql=KeGetCurrentIrql();
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);if(NT_SUCCESS(RtlGetVersion(&version)))out->KernelBuild=version.dwBuildNumber;
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);out->FirmwareBytes=bytes;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G92HIDExpectedDsdt,sizeof(table))==sizeof(table))out->FirmwareMatch=1;
 out->D0=Counter(&c->D0);out->Started=Counter(&c->Started);out->CreateStatus=Counter(&c->CreateStatus);out->StartStatus=Counter(&c->StartStatus);out->Entries=Counter(&c->Entries);out->Exits=Counter(&c->Exits);out->Features=Counter(&c->Features);out->LiveAttempts=Counter(&c->LiveAttempts);out->LastSubmit=Counter(&c->LastSubmit);
 out->MaxContacts=G92HID_CONTACTS;out->MaxX=G92HID_RAW_X_MAX;out->MaxY=G92HID_RAW_Y_MAX;out->ReportBytes=G92HID_REPORT_BYTES;out->DescriptorBytes=G92HIDDescriptorBytes;
 /* The worker is the only writer of Live. Publish its frozen state only after
  * the interlocked DONE transition; do not race non-atomic input structures. */
 if(Counter(&c->State)==G92_OWNER_DONE){out->ReportsAccepted=c->Live.SubmitAccepted;out->LiveComplete=c->LiveComplete;out->LiveError=c->LastHardwareCode?c->LastHardwareCode:c->Live.Error;out->StopAttempts=c->Live.StopAttempts;out->StopAccepted=c->Live.StopAccepted;out->AcceptedMask=c->Live.Accepted.Mask;out->AcceptedGeneration=c->Live.Accepted.Generation;out->ReportsSubmitted=c->Live.SubmitAttempts;}
 out->Sequence=(ULONGLONG)InterlockedIncrement64(&c->Sequence);RtlCopyMemory(out->BuildId,"G92-stream1",sizeof("G92-stream1"));
}
VOID G92HIDFeature(PVOID context,VHFOPERATIONHANDLE operation,PVOID operationContext,PHID_XFER_PACKET packet)
{
 G92HID_CONTEXT*c=context;uint32_t written=0;NTSTATUS status=STATUS_NOT_SUPPORTED;UNREFERENCED_PARAMETER(operationContext);
 InterlockedIncrement(&c->Features);
 if(packet&&G92HIDGetFeature(packet->reportId,packet->reportBuffer,packet->reportBufferLen,&written)){packet->reportBufferLen=written;status=STATUS_SUCCESS;}
 VhfAsyncOperationComplete(operation,status);
}
static int G92HIDSubmit(void*context,const uint8_t bytes[64])
{
 G92HID_CONTEXT*c=context;HID_XFER_PACKET packet;NTSTATUS status;
 if(!c->Handle||!Counter(&c->D0)||!Counter(&c->Started))return 0;
 RtlZeroMemory(&packet,sizeof(packet));packet.reportBuffer=(PUCHAR)bytes;packet.reportBufferLen=64;packet.reportId=1;
 status=VhfReadReportSubmit(c->Handle,&packet);InterlockedExchange(&c->LastSubmit,status);return NT_SUCCESS(status);
}
static int G92HIDStage(void*context,const uint8_t*raw,uint32_t n,uint64_t at)
{
 G92HID_CONTEXT*c=context;if(!c->Handle||!Counter(&c->D0)||!Counter(&c->Started))return 0;
 return G92InputStage(&c->Live,raw,n,(uint16_t)(at/100));
}
static int G92HIDPublish(void*context,const uint8_t*raw,uint32_t n)
{
 G92HID_CONTEXT*c=context;G92_INPUT_IO io={c,G92HIDSubmit};
 if(!c->Handle||!Counter(&c->D0)||!Counter(&c->Started))return 0;
 return G92InputPublish(&c->Live,&io,raw,n);
}

static void RequestStop(G92HID_CONTEXT*c,ULONG reason)
{
 ULONG state=Counter(&c->State);ULONGLONG at;
 if(state!=G92_OWNER_QUEUED&&state!=G92_OWNER_RUNNING)return;
 InterlockedIncrement(&c->StopRequests);at=G92HardwareTimeUs();
 if(InterlockedCompareExchange(&c->StopReason,reason,0)==0)InterlockedExchange64(&c->StopUs,(LONG64)at);
}
/* Caller holds Control. The worker never acquires Control, and its kernel
 * handle is created/closed only under this mutex. A join waits for actual
 * thread termination, not merely a result-ready event. */
static NTSTATUS Join(G92HID_CONTEXT*c,ULONG reason)
{
 NTSTATUS s;RequestStop(c,reason);if(!c->Thread)return STATUS_SUCCESS;
 s=ZwWaitForSingleObject(c->Thread,FALSE,NULL);if(s!=STATUS_SUCCESS)return s;
 s=ZwClose(c->Thread);if(!NT_SUCCESS(s))return s;
 c->Thread=NULL;c->OwnerFile=NULL;InterlockedExchange(&c->ThreadJoined,1);return STATUS_SUCCESS;
}
static VOID Worker(PVOID context)
{
 G92HID_CONTEXT*c=context;G92_TRIAL*t=c->Result;G92_STREAM_IO stream={c,G92HIDStage,G92HIDPublish,StopRequested,Available};G92_INPUT_IO input={c,G92HIDSubmit};int released,restored;ULONG outcome;
 InterlockedExchange(&c->State,G92_OWNER_RUNNING);InterlockedIncrement(&c->LiveAttempts);
 if(Counter(&c->StopReason)||!Available(c)){
  RtlZeroMemory(t,sizeof(*t));G92HardwareStatus(&t->Status);t->Trial.Power.Code=1010;t->Trial.SafeRelease=1;
  InterlockedIncrement(&c->StopSeen);outcome=G92_OUTCOME_CANCELLED_BEFORE_HARDWARE;
 }else{
  InterlockedIncrement(&c->HardwareCalls);G92HardwareTrial(t,&stream);outcome=G92_OUTCOME_FAILED;
 }
 released=G92InputStop(&c->Live,&input,(uint16_t)(G92HardwareTimeUs()/100));
 c->LastHardwareCode=t->Trial.Power.Code;
 restored=t->Attempt&&t->FixedRegistersUnchanged&&t->Trial.SafeRelease&&t->Trial.Power.Restored&&!t->Trial.Power.RestoreError&&t->Trial.Spi.Restored&&!t->Trial.Spi.RestoreError&&t->Trial.Spi.Engine.Restored&&!t->Trial.Spi.Engine.RestoreError&&t->Trial.Touch.Restored&&!t->Trial.Touch.RestoreError;
 c->LiveComplete=released&&!c->Live.Error&&restored&&t->Trial.Power.Code==0&&t->Trial.Touch.Code==0&&t->Trial.Touch.Poll.Code==0&&t->Trial.Touch.Poll.Limit==G92_NATIVE_CYCLES&&t->Trial.Touch.Poll.Cycles==G92_NATIVE_CYCLES;
 if(c->LiveComplete)outcome=G92_OUTCOME_COMPLETE;
 else if(released&&!c->Live.Error&&restored&&Counter(&c->StopReason)&&t->Trial.Touch.Code==G92_TOUCH_CANCELLED)outcome=G92_OUTCOME_CANCELLED;
 InterlockedExchange(&c->Outcome,outcome);InterlockedExchange(&c->Phase,t->Trial.Touch.Stage);InterlockedExchange(&c->PollCycles,t->Trial.Touch.Poll.Cycles);InterlockedExchange64(&c->EndUs,(LONG64)G92HardwareTimeUs());
 InterlockedExchange(&c->ResultReady,1);InterlockedExchange(&c->State,G92_OWNER_DONE);
 PsTerminateSystemThread(STATUS_SUCCESS);
}
static NTSTATUS Start(G92HID_CONTEXT*c,WDFFILEOBJECT file)
{
 G92HID_STATUS identity;OBJECT_ATTRIBUTES attributes;NTSTATUS s;
 Status(c,&identity);if(!identity.FirmwareMatch||identity.Processors!=8||identity.KernelBuild!=26300||identity.Irql!=PASSIVE_LEVEL)return STATUS_NOT_SUPPORTED;
 if(!identity.D0||!identity.Started||!c->Handle||!c->Result||!file||Counter(&c->Inhibit)||!Available(c))return STATUS_DEVICE_NOT_READY;
 if(Counter(&c->State)!=G92_OWNER_IDLE||InterlockedCompareExchange(&c->Starts,1,0)!=0)return STATUS_QUOTA_EXCEEDED;
 c->OwnerFile=file;InterlockedExchange64(&c->BeginUs,(LONG64)G92HardwareTimeUs());InterlockedExchange(&c->State,G92_OWNER_QUEUED);
 InitializeObjectAttributes(&attributes,NULL,OBJ_KERNEL_HANDLE,NULL,NULL);
 s=PsCreateSystemThread(&c->Thread,SYNCHRONIZE,&attributes,NULL,NULL,Worker,c);InterlockedExchange(&c->ThreadCreateStatus,s);
 if(!NT_SUCCESS(s)){c->Thread=NULL;c->OwnerFile=NULL;InterlockedExchange(&c->Outcome,G92_OUTCOME_FAILED);InterlockedExchange(&c->State,G92_OWNER_DONE);}
 return s;
}
VOID G92HIDControl(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 G92HID_CONTEXT*c=G92HIDContext(WdfIoQueueGetDevice(queue));G92HID_REQUEST*in;PVOID out;NTSTATUS status;ULONG_PTR information=0;size_t needed;int hw;
 hw=code==G92_IOCTL_STATUS||code==G92_IOCTL_SNAPSHOT||code==G92_IOCTL_PMIC||code==G92_IOCTL_POWER;
 if(!hw&&code!=G92HID_IOCTL_STATUS&&code!=G92HID_IOCTL_SESSION&&code!=G92HID_IOCTL_START&&code!=G92HID_IOCTL_STOP){status=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inputBytes!=sizeof(*in)){status=STATUS_INVALID_PARAMETER;goto done;}
 status=WdfRequestRetrieveInputBuffer(request,sizeof(*in),(PVOID*)&in,NULL);if(!NT_SUCCESS(status))goto done;
 if(in->Size!=sizeof(*in)||in->Version!=1||in->Magic!=(hw?G92_MAGIC:G92HID_MAGIC)){status=STATUS_INVALID_PARAMETER;goto done;}
 needed=code==G92HID_IOCTL_STATUS?sizeof(G92HID_STATUS):!hw?sizeof(G92_SESSION):code==G92_IOCTL_STATUS?sizeof(G92_STATUS):code==G92_IOCTL_SNAPSHOT?sizeof(G92_SNAPSHOT):code==G92_IOCTL_PMIC?sizeof(G92_PMIC):sizeof(G92_TRIAL);
 if(outputBytes<needed){status=STATUS_BUFFER_TOO_SMALL;goto done;}
 status=WdfRequestRetrieveOutputBuffer(request,needed,&out,NULL);if(!NT_SUCCESS(status))goto done;
 OwnerLock(c);
 if(code==G92HID_IOCTL_STATUS){Status(c,out);status=STATUS_SUCCESS;}
 else if(code==G92HID_IOCTL_SESSION){SessionStatus(c,out);status=STATUS_SUCCESS;}
 else if(code==G92HID_IOCTL_START){status=Start(c,WdfRequestGetFileObject(request));if(NT_SUCCESS(status))SessionStatus(c,out);}
 else if(code==G92HID_IOCTL_STOP){status=Join(c,G92_STOP_EXPLICIT);if(NT_SUCCESS(status))SessionStatus(c,out);}
 else if(code==G92_IOCTL_POWER){
  /* This old function number retrieves a frozen result. It never powers. */
  if(!Counter(&c->ResultReady)||Counter(&c->State)!=G92_OWNER_DONE)status=STATUS_DEVICE_NOT_READY;
  else{status=Join(c,G92_STOP_NONE);if(NT_SUCCESS(status))RtlCopyMemory(out,c->Result,sizeof(*c->Result));}
 }else if(code==G92_IOCTL_STATUS){G92HardwareStatus(out);status=STATUS_SUCCESS;}
 else if(Counter(&c->State)==G92_OWNER_QUEUED||Counter(&c->State)==G92_OWNER_RUNNING)status=STATUS_DEVICE_BUSY;
 else if(Counter(&c->Inhibit)||!Counter(&c->D0)||!Available(c))status=STATUS_DEVICE_NOT_READY;
 else{
  G92_STREAM_IO stream={c,G92HIDStage,G92HIDPublish,StopRequested,Available};
  if(code==G92_IOCTL_SNAPSHOT)status=G92HardwareSnapshot(out,&stream);
  else{G92HardwarePmic(out,&stream);status=STATUS_SUCCESS;}
 }
 OwnerUnlock(c);if(NT_SUCCESS(status))information=needed;
 done:WdfRequestCompleteWithInformation(request,status,information);
}
NTSTATUS G92HIDD0Entry(WDFDEVICE device,WDF_POWER_DEVICE_STATE previous)
{
 G92HID_CONTEXT*c=G92HIDContext(device);UNREFERENCED_PARAMETER(previous);OwnerLock(c);InterlockedIncrement(&c->Entries);InterlockedExchange(&c->D0,1);if(Available(c))InterlockedExchange(&c->Inhibit,0);OwnerUnlock(c);return STATUS_SUCCESS;
}
NTSTATUS G92HIDD0Exit(WDFDEVICE device,WDF_POWER_DEVICE_STATE target)
{
 G92HID_CONTEXT*c=G92HIDContext(device);NTSTATUS s;UNREFERENCED_PARAMETER(target);OwnerLock(c);InterlockedExchange(&c->Inhibit,1);s=Join(c,G92_STOP_D0_EXIT);if(NT_SUCCESS(s)){InterlockedExchange(&c->D0,0);InterlockedIncrement(&c->Exits);}OwnerUnlock(c);return s;
}
NTSTATUS G92HIDIoInit(WDFDEVICE device)
{
 G92HID_CONTEXT*c=G92HIDContext(device);NTSTATUS status=VhfStart(c->Handle);InterlockedExchange(&c->StartStatus,status);if(NT_SUCCESS(status))InterlockedExchange(&c->Started,1);return status;
}
NTSTATUS G92HIDSuspend(WDFDEVICE device)
{
 G92HID_CONTEXT*c=G92HIDContext(device);NTSTATUS s;OwnerLock(c);InterlockedExchange(&c->Inhibit,1);s=Join(c,G92_STOP_SUSPEND);OwnerUnlock(c);return s;
}
NTSTATUS G92HIDRestart(WDFDEVICE device)
{
 G92HID_CONTEXT*c=G92HIDContext(device);OwnerLock(c);if(Counter(&c->D0)&&Available(c))InterlockedExchange(&c->Inhibit,0);OwnerUnlock(c);return STATUS_SUCCESS;
}
VOID G92HIDSurprise(WDFDEVICE device)
{
 G92HID_CONTEXT*c=G92HIDContext(device);InterlockedExchange(&c->Removed,1);OwnerLock(c);InterlockedExchange(&c->Inhibit,1);Join(c,G92_STOP_SURPRISE);OwnerUnlock(c);
}
VOID G92HIDCleanup(WDFOBJECT object)
{
 G92HID_CONTEXT*c=G92HIDContext((WDFDEVICE)object);NTSTATUS status;if(!c->ControlInitialized)return;
 OwnerLock(c);InterlockedExchange(&c->Inhibit,1);status=Join(c,G92_STOP_CLEANUP);NT_ASSERT(NT_SUCCESS(status));
 if(NT_SUCCESS(status)){InterlockedExchange(&c->Started,0);if(c->Handle){VhfDelete(c->Handle,TRUE);c->Handle=NULL;}if(c->Result){ExFreePoolWithTag(c->Result,'85GO');c->Result=NULL;}}
 OwnerUnlock(c);
}
VOID G92HIDFileCreate(WDFDEVICE device,WDFREQUEST request,WDFFILEOBJECT file)
{
 PUNICODE_STRING name=WdfFileObjectGetFileName(file);UNREFERENCED_PARAMETER(device);WdfRequestComplete(request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);
}
VOID G92HIDFileCleanup(WDFFILEOBJECT file)
{
 G92HID_CONTEXT*c=G92HIDContext(WdfFileObjectGetDevice(file));OwnerLock(c);if(c->OwnerFile==file)Join(c,G92_STOP_CLOSE);OwnerUnlock(c);
}
NTSTATUS G92HIDAdd(WDFDRIVER driver,PWDFDEVICE_INIT init)
{
 WDF_OBJECT_ATTRIBUTES attributes;WDF_PNPPOWER_EVENT_CALLBACKS power;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG files;
 WDFDEVICE device;G92HID_CONTEXT*c;G92HID_STATUS identity;VHF_CONFIG config;NTSTATUS status;UNREFERENCED_PARAMETER(driver);
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&files,G92HIDFileCreate,WDF_NO_EVENT_CALLBACK,G92HIDFileCleanup);WdfDeviceInitSetFileObjectConfig(init,&files,WDF_NO_OBJECT_ATTRIBUTES);
 WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&power);power.EvtDeviceD0Entry=G92HIDD0Entry;power.EvtDeviceD0Exit=G92HIDD0Exit;power.EvtDeviceSelfManagedIoInit=G92HIDIoInit;power.EvtDeviceSelfManagedIoSuspend=G92HIDSuspend;power.EvtDeviceSelfManagedIoRestart=G92HIDRestart;power.EvtDeviceSurpriseRemoval=G92HIDSurprise;WdfDeviceInitSetPnpPowerEventCallbacks(init,&power);
 WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes,G92HID_CONTEXT);attributes.ExecutionLevel=WdfExecutionLevelPassive;attributes.SynchronizationScope=WdfSynchronizationScopeNone;attributes.EvtCleanupCallback=G92HIDCleanup;
 status=WdfDeviceCreate(&init,&attributes,&device);if(!NT_SUCCESS(status))return status;c=G92HIDContext(device);KeInitializeMutex(&c->Control,0);c->ControlInitialized=1;
 c->CreateStatus=c->StartStatus=c->LastSubmit=STATUS_DEVICE_NOT_READY;Status(c,&identity);
 if(!identity.FirmwareMatch||identity.Processors!=8||identity.KernelBuild!=26300||identity.Irql!=PASSIVE_LEVEL)return STATUS_NOT_SUPPORTED;
 c->Result=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*c->Result),'85GO');if(!c->Result)return STATUS_INSUFFICIENT_RESOURCES;RtlZeroMemory(c->Result,sizeof(*c->Result));
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfTrue;queue.EvtIoDeviceControl=G92HIDControl;
 status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))return status;
 status=WdfDeviceCreateDeviceInterface(device,&G92HIDInterface,NULL);if(!NT_SUCCESS(status))return status;
 VHF_CONFIG_INIT(&config,WdfDeviceWdmGetDeviceObject(device),(USHORT)G92HIDDescriptorBytes,G92HIDDescriptor);config.VhfClientContext=c;config.EvtVhfAsyncOperationGetFeature=G92HIDFeature;
 {static WCHAR ids[]=L"OPENLAB\\ONEPLUSOPENTOUCHG92\0";config.HardwareIDs=ids;config.HardwareIDsLength=(USHORT)sizeof(ids);}
 status=VhfCreate(&config,&c->Handle);InterlockedExchange(&c->CreateStatus,status);return status;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING path)
{
 WDF_DRIVER_CONFIG config;NTSTATUS status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 WDF_DRIVER_CONFIG_INIT(&config,G92HIDAdd);return WdfDriverCreate(object,path,WDF_NO_OBJECT_ATTRIBUTES,&config,WDF_NO_HANDLE);
}
