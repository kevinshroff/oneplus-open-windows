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
#include "g96hid_baseline.h"
#include "g96hid_protocol.h"
#include "g96hid_report.h"
#include "g96_input.h"
#include "g96_hwapi.h"

typedef struct {
 VHFHANDLE Handle;KMUTEX Control;ULONG ControlInitialized;
 HANDLE Thread;WDFFILEOBJECT OwnerFile;G96_TRIAL*Result;
 volatile LONG D0,Started,CreateStatus,StartStatus,Entries,Exits,Features,LiveAttempts,LastSubmit;
 volatile LONG State,StopReason,Starts,HardwareCalls,ResultReady,Outcome,StopChecks,StopSeen,Inhibit,ThreadJoined,Phase,PollCycles,ThreadCreateStatus,Removed,StopRequests;
 volatile LONG64 Sequence,BeginUs,EndUs,StopUs;
 G96_INPUT Live;ULONG LastHardwareCode,LiveComplete,CycleLimit;volatile LONG DiagSubmitted,DiagAccepted;
}G96HID_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(G96HID_CONTEXT,G96HIDContext)
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD G96HIDAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP G96HIDCleanup;
EVT_WDF_DEVICE_D0_ENTRY G96HIDD0Entry;
EVT_WDF_DEVICE_D0_EXIT G96HIDD0Exit;
EVT_WDF_DEVICE_SELF_MANAGED_IO_INIT G96HIDIoInit;
EVT_WDF_DEVICE_SELF_MANAGED_IO_SUSPEND G96HIDSuspend;
EVT_WDF_DEVICE_SELF_MANAGED_IO_RESTART G96HIDRestart;
EVT_WDF_DEVICE_SURPRISE_REMOVAL G96HIDSurprise;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G96HIDControl;
EVT_WDF_DEVICE_FILE_CREATE G96HIDFileCreate;
EVT_WDF_FILE_CLEANUP G96HIDFileCleanup;
EVT_VHF_ASYNC_OPERATION G96HIDFeature;
static ULONG Counter(volatile LONG*p){return(ULONG)InterlockedCompareExchange(p,0,0);}
static ULONGLONG TimeValue(volatile LONG64*p){return(ULONGLONG)InterlockedCompareExchange64(p,0,0);}
static void OwnerLock(G96HID_CONTEXT*c){NTSTATUS s=KeWaitForSingleObject(&c->Control,Executive,KernelMode,FALSE,NULL);NT_ASSERT(s==STATUS_SUCCESS);UNREFERENCED_PARAMETER(s);}
static void OwnerUnlock(G96HID_CONTEXT*c){KeReleaseMutex(&c->Control,FALSE);}
static int Available(void*x){return !Counter(&((G96HID_CONTEXT*)x)->Removed);}
static int StopRequested(void*x)
{
 G96HID_CONTEXT*c=x;InterlockedIncrement(&c->StopChecks);
 InterlockedExchange(&c->Phase,c->Result->Trial.Touch.Stage);InterlockedExchange(&c->PollCycles,c->Result->Trial.Touch.Poll.Cycles);
 if(!Counter(&c->StopReason))return 0;InterlockedIncrement(&c->StopSeen);return 1;
}
static void SessionStatus(G96HID_CONTEXT*c,G96_SESSION*out)
{
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=1;out->Magic=G96HID_MAGIC;
 out->State=Counter(&c->State);out->StopReason=Counter(&c->StopReason);out->Starts=Counter(&c->Starts);out->HardwareCalls=Counter(&c->HardwareCalls);out->ResultReady=Counter(&c->ResultReady);out->Outcome=Counter(&c->Outcome);out->StopChecks=Counter(&c->StopChecks);out->StopSeen=Counter(&c->StopSeen);out->Inhibit=Counter(&c->Inhibit);out->ThreadJoined=Counter(&c->ThreadJoined);out->Phase=Counter(&c->Phase);out->PollCycles=Counter(&c->PollCycles);out->ThreadCreateStatus=Counter(&c->ThreadCreateStatus);
 out->BeginUs=TimeValue(&c->BeginUs);out->EndUs=TimeValue(&c->EndUs);out->StopUs=TimeValue(&c->StopUs);out->StopRequests=Counter(&c->StopRequests);
}
static VOID Status(G96HID_CONTEXT*c,G96HID_STATUS*out)
{
 UCHAR table[sizeof(G96HIDExpectedDsdt)];ULONG bytes=0;RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=G96HID_ABI;out->Magic=G96HID_MAGIC;
 out->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);out->Irql=KeGetCurrentIrql();
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);if(NT_SUCCESS(RtlGetVersion(&version)))out->KernelBuild=version.dwBuildNumber;
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);out->FirmwareBytes=bytes;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G96HIDExpectedDsdt,sizeof(table))==sizeof(table))out->FirmwareMatch=1;
 out->D0=Counter(&c->D0);out->Started=Counter(&c->Started);out->CreateStatus=Counter(&c->CreateStatus);out->StartStatus=Counter(&c->StartStatus);out->Entries=Counter(&c->Entries);out->Exits=Counter(&c->Exits);out->Features=Counter(&c->Features);out->LiveAttempts=Counter(&c->LiveAttempts);out->LastSubmit=Counter(&c->LastSubmit);
 out->MaxContacts=G96HID_CONTACTS;out->MaxX=G96HID_RAW_X_MAX;out->MaxY=G96HID_RAW_Y_MAX;out->ReportBytes=G96HID_REPORT_BYTES;out->DescriptorBytes=G96HIDDescriptorBytes;
 /* The worker is the only writer of Live. Publish its frozen state only after
  * the interlocked DONE transition; do not race non-atomic input structures. */
 if(Counter(&c->State)==G96_OWNER_DONE){out->ReportsAccepted=c->Live.SubmitAccepted;out->LiveComplete=c->LiveComplete;out->LiveError=c->LastHardwareCode?c->LastHardwareCode:c->Live.Error;out->StopAttempts=c->Live.StopAttempts;out->StopAccepted=c->Live.StopAccepted;out->AcceptedMask=c->Live.Accepted.Mask;out->AcceptedGeneration=c->Live.Accepted.Generation;out->ReportsSubmitted=c->Live.SubmitAttempts;}
 if(Counter(&c->State)!=G96_OWNER_DONE){out->ReportsAccepted=Counter(&c->DiagAccepted);out->ReportsSubmitted=Counter(&c->DiagSubmitted);}
 out->Sequence=(ULONGLONG)InterlockedIncrement64(&c->Sequence);RtlCopyMemory(out->BuildId,"G96-stream1",sizeof("G96-stream1"));
}
VOID G96HIDFeature(PVOID context,VHFOPERATIONHANDLE operation,PVOID operationContext,PHID_XFER_PACKET packet)
{
 G96HID_CONTEXT*c=context;uint32_t written=0;NTSTATUS status=STATUS_NOT_SUPPORTED;UNREFERENCED_PARAMETER(operationContext);
 InterlockedIncrement(&c->Features);
 if(packet&&G96HIDGetFeature(packet->reportId,packet->reportBuffer,packet->reportBufferLen,&written)){packet->reportBufferLen=written;status=STATUS_SUCCESS;}
 VhfAsyncOperationComplete(operation,status);
}
static int G96HIDSubmit(void*context,const uint8_t bytes[64])
{
 G96HID_CONTEXT*c=context;HID_XFER_PACKET packet;NTSTATUS status;
 if(!c->Handle||!Counter(&c->D0)||!Counter(&c->Started))return 0;
 RtlZeroMemory(&packet,sizeof(packet));packet.reportBuffer=(PUCHAR)bytes;packet.reportBufferLen=64;packet.reportId=1;
 InterlockedIncrement(&c->DiagSubmitted);status=VhfReadReportSubmit(c->Handle,&packet);if(NT_SUCCESS(status))InterlockedIncrement(&c->DiagAccepted);InterlockedExchange(&c->LastSubmit,status);return NT_SUCCESS(status);
}
static int G96HIDStage(void*context,const uint8_t*raw,uint32_t n,uint64_t at)
{
 G96HID_CONTEXT*c=context;if(!c->Handle||!Counter(&c->D0)||!Counter(&c->Started))return 0;
 return G96InputStage(&c->Live,raw,n,(uint16_t)(at/100));
}
static int G96HIDPublish(void*context,const uint8_t*raw,uint32_t n)
{
 G96HID_CONTEXT*c=context;G96_INPUT_IO io={c,G96HIDSubmit};
 if(!c->Handle||!Counter(&c->D0)||!Counter(&c->Started))return 0;
 return G96InputPublish(&c->Live,&io,raw,n);
}

static void RequestStop(G96HID_CONTEXT*c,ULONG reason)
{
 ULONG state=Counter(&c->State);ULONGLONG at;
 if(state!=G96_OWNER_QUEUED&&state!=G96_OWNER_RUNNING)return;
 InterlockedIncrement(&c->StopRequests);at=G96HardwareTimeUs();
 if(InterlockedCompareExchange(&c->StopReason,reason,0)==0)InterlockedExchange64(&c->StopUs,(LONG64)at);
}
/* Caller holds Control. The worker never acquires Control, and its kernel
 * handle is created/closed only under this mutex. A join waits for actual
 * thread termination, not merely a result-ready event. */
static NTSTATUS Join(G96HID_CONTEXT*c,ULONG reason)
{
 NTSTATUS s;RequestStop(c,reason);if(!c->Thread)return STATUS_SUCCESS;
 s=ZwWaitForSingleObject(c->Thread,FALSE,NULL);if(s!=STATUS_SUCCESS)return s;
 s=ZwClose(c->Thread);if(!NT_SUCCESS(s))return s;
 c->Thread=NULL;c->OwnerFile=NULL;InterlockedExchange(&c->ThreadJoined,1);return STATUS_SUCCESS;
}
static VOID Worker(PVOID context)
{
 G96HID_CONTEXT*c=context;G96_TRIAL*t=c->Result;G96_STREAM_IO stream={c,G96HIDStage,G96HIDPublish,StopRequested,Available,c->CycleLimit};G96_INPUT_IO input={c,G96HIDSubmit};int released,restored;ULONG outcome;
 InterlockedExchange(&c->State,G96_OWNER_RUNNING);InterlockedIncrement(&c->LiveAttempts);
 if(Counter(&c->StopReason)||!Available(c)){
  RtlZeroMemory(t,sizeof(*t));G96HardwareStatus(&t->Status);t->Trial.Power.Code=1010;t->Trial.SafeRelease=1;
  InterlockedIncrement(&c->StopSeen);outcome=G96_OUTCOME_CANCELLED_BEFORE_HARDWARE;
 }else{
  InterlockedIncrement(&c->HardwareCalls);G96HardwareTrial(t,&stream);outcome=G96_OUTCOME_FAILED;
 }
 released=G96InputStop(&c->Live,&input,(uint16_t)(G96HardwareTimeUs()/100));
 c->LastHardwareCode=t->Trial.Power.Code;
 restored=t->Attempt&&t->FixedRegistersUnchanged&&t->Trial.SafeRelease&&t->Trial.Power.Restored&&!t->Trial.Power.RestoreError&&t->Trial.Spi.Restored&&!t->Trial.Spi.RestoreError&&t->Trial.Spi.Engine.Restored&&!t->Trial.Spi.Engine.RestoreError&&t->Trial.Touch.Restored&&!t->Trial.Touch.RestoreError;
 c->LiveComplete=released&&!c->Live.Error&&restored&&t->Trial.Power.Code==0&&t->Trial.Touch.Code==0&&t->Trial.Touch.Poll.Code==0&&t->Trial.Touch.Poll.Limit==c->CycleLimit&&t->Trial.Touch.Poll.Cycles==c->CycleLimit;
 if(c->LiveComplete)outcome=G96_OUTCOME_COMPLETE;
 else if(released&&!c->Live.Error&&restored&&Counter(&c->StopReason)&&t->Trial.Touch.Code==G96_TOUCH_CANCELLED)outcome=G96_OUTCOME_CANCELLED;
 InterlockedExchange(&c->Outcome,outcome);InterlockedExchange(&c->Phase,t->Trial.Touch.Stage);InterlockedExchange(&c->PollCycles,t->Trial.Touch.Poll.Cycles);InterlockedExchange64(&c->EndUs,(LONG64)G96HardwareTimeUs());
 InterlockedExchange(&c->ResultReady,1);InterlockedExchange(&c->State,G96_OWNER_DONE);
 PsTerminateSystemThread(STATUS_SUCCESS);
}
static NTSTATUS Start(G96HID_CONTEXT*c,WDFFILEOBJECT file,ULONG cycles)
{
 G96HID_STATUS identity;OBJECT_ATTRIBUTES attributes;NTSTATUS s;
 if(cycles!=G96_NATIVE_CYCLES&&cycles!=G96_PLAY_CYCLES)return STATUS_INVALID_PARAMETER;
 Status(c,&identity);if(!identity.FirmwareMatch||identity.Processors!=8||identity.KernelBuild!=26300||identity.Irql!=PASSIVE_LEVEL)return STATUS_NOT_SUPPORTED;
 if(!identity.D0||!identity.Started||!c->Handle||!c->Result||!file||Counter(&c->Inhibit)||!Available(c))return STATUS_DEVICE_NOT_READY;
 if(Counter(&c->State)!=G96_OWNER_IDLE||InterlockedCompareExchange(&c->Starts,1,0)!=0)return STATUS_QUOTA_EXCEEDED;
 c->CycleLimit=cycles;c->OwnerFile=file;InterlockedExchange64(&c->BeginUs,(LONG64)G96HardwareTimeUs());InterlockedExchange(&c->State,G96_OWNER_QUEUED);
 InitializeObjectAttributes(&attributes,NULL,OBJ_KERNEL_HANDLE,NULL,NULL);
 s=PsCreateSystemThread(&c->Thread,SYNCHRONIZE,&attributes,NULL,NULL,Worker,c);InterlockedExchange(&c->ThreadCreateStatus,s);
 if(!NT_SUCCESS(s)){c->Thread=NULL;c->OwnerFile=NULL;InterlockedExchange(&c->Outcome,G96_OUTCOME_FAILED);InterlockedExchange(&c->State,G96_OWNER_DONE);}
 return s;
}
VOID G96HIDControl(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 G96HID_CONTEXT*c=G96HIDContext(WdfIoQueueGetDevice(queue));G96HID_REQUEST*in;PVOID out;NTSTATUS status;ULONG_PTR information=0;size_t needed;int hw;
 hw=code==G96_IOCTL_STATUS||code==G96_IOCTL_SNAPSHOT||code==G96_IOCTL_PMIC||code==G96_IOCTL_POWER;
 if(!hw&&code!=G96HID_IOCTL_STATUS&&code!=G96HID_IOCTL_SESSION&&code!=G96HID_IOCTL_START&&code!=G96HID_IOCTL_STOP&&code!=G96HID_IOCTL_PLAY){status=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inputBytes!=sizeof(*in)){status=STATUS_INVALID_PARAMETER;goto done;}
 status=WdfRequestRetrieveInputBuffer(request,sizeof(*in),(PVOID*)&in,NULL);if(!NT_SUCCESS(status))goto done;
 if(in->Size!=sizeof(*in)||in->Version!=1||in->Magic!=(hw?G96_MAGIC:G96HID_MAGIC)){status=STATUS_INVALID_PARAMETER;goto done;}
 needed=code==G96HID_IOCTL_STATUS?sizeof(G96HID_STATUS):!hw?sizeof(G96_SESSION):code==G96_IOCTL_STATUS?sizeof(G96_STATUS):code==G96_IOCTL_SNAPSHOT?sizeof(G96_SNAPSHOT):code==G96_IOCTL_PMIC?sizeof(G96_PMIC):sizeof(G96_TRIAL);
 if(outputBytes<needed){status=STATUS_BUFFER_TOO_SMALL;goto done;}
 status=WdfRequestRetrieveOutputBuffer(request,needed,&out,NULL);if(!NT_SUCCESS(status))goto done;
 OwnerLock(c);
 if(code==G96HID_IOCTL_STATUS){Status(c,out);status=STATUS_SUCCESS;}
 else if(code==G96HID_IOCTL_SESSION){SessionStatus(c,out);status=STATUS_SUCCESS;}
 else if(code==G96HID_IOCTL_START||code==G96HID_IOCTL_PLAY){status=Start(c,WdfRequestGetFileObject(request),code==G96HID_IOCTL_PLAY?G96_PLAY_CYCLES:G96_NATIVE_CYCLES);if(NT_SUCCESS(status))SessionStatus(c,out);}
 else if(code==G96HID_IOCTL_STOP){status=Join(c,G96_STOP_EXPLICIT);if(NT_SUCCESS(status))SessionStatus(c,out);}
 else if(code==G96_IOCTL_POWER){
  /* This old function number retrieves a frozen result. It never powers. */
  if(!Counter(&c->ResultReady)||Counter(&c->State)!=G96_OWNER_DONE)status=STATUS_DEVICE_NOT_READY;
  else{status=Join(c,G96_STOP_NONE);if(NT_SUCCESS(status))RtlCopyMemory(out,c->Result,sizeof(*c->Result));}
 }else if(code==G96_IOCTL_STATUS){G96HardwareStatus(out);status=STATUS_SUCCESS;}
 else if(Counter(&c->State)==G96_OWNER_QUEUED||Counter(&c->State)==G96_OWNER_RUNNING)status=STATUS_DEVICE_BUSY;
 else if(Counter(&c->Inhibit)||!Counter(&c->D0)||!Available(c))status=STATUS_DEVICE_NOT_READY;
 else{
  G96_STREAM_IO stream={c,G96HIDStage,G96HIDPublish,StopRequested,Available,c->CycleLimit};
  if(code==G96_IOCTL_SNAPSHOT)status=G96HardwareSnapshot(out,&stream);
  else{G96HardwarePmic(out,&stream);status=STATUS_SUCCESS;}
 }
 OwnerUnlock(c);if(NT_SUCCESS(status))information=needed;
 done:WdfRequestCompleteWithInformation(request,status,information);
}
NTSTATUS G96HIDD0Entry(WDFDEVICE device,WDF_POWER_DEVICE_STATE previous)
{
 G96HID_CONTEXT*c=G96HIDContext(device);UNREFERENCED_PARAMETER(previous);OwnerLock(c);InterlockedIncrement(&c->Entries);InterlockedExchange(&c->D0,1);if(Available(c))InterlockedExchange(&c->Inhibit,0);OwnerUnlock(c);return STATUS_SUCCESS;
}
NTSTATUS G96HIDD0Exit(WDFDEVICE device,WDF_POWER_DEVICE_STATE target)
{
 G96HID_CONTEXT*c=G96HIDContext(device);NTSTATUS s;UNREFERENCED_PARAMETER(target);OwnerLock(c);InterlockedExchange(&c->Inhibit,1);s=Join(c,G96_STOP_D0_EXIT);if(NT_SUCCESS(s)){InterlockedExchange(&c->D0,0);InterlockedIncrement(&c->Exits);}OwnerUnlock(c);return s;
}
NTSTATUS G96HIDIoInit(WDFDEVICE device)
{
 G96HID_CONTEXT*c=G96HIDContext(device);NTSTATUS status=VhfStart(c->Handle);InterlockedExchange(&c->StartStatus,status);if(NT_SUCCESS(status))InterlockedExchange(&c->Started,1);return status;
}
NTSTATUS G96HIDSuspend(WDFDEVICE device)
{
 G96HID_CONTEXT*c=G96HIDContext(device);NTSTATUS s;OwnerLock(c);InterlockedExchange(&c->Inhibit,1);s=Join(c,G96_STOP_SUSPEND);OwnerUnlock(c);return s;
}
NTSTATUS G96HIDRestart(WDFDEVICE device)
{
 G96HID_CONTEXT*c=G96HIDContext(device);OwnerLock(c);if(Counter(&c->D0)&&Available(c))InterlockedExchange(&c->Inhibit,0);OwnerUnlock(c);return STATUS_SUCCESS;
}
VOID G96HIDSurprise(WDFDEVICE device)
{
 G96HID_CONTEXT*c=G96HIDContext(device);InterlockedExchange(&c->Removed,1);OwnerLock(c);InterlockedExchange(&c->Inhibit,1);Join(c,G96_STOP_SURPRISE);OwnerUnlock(c);
}
VOID G96HIDCleanup(WDFOBJECT object)
{
 G96HID_CONTEXT*c=G96HIDContext((WDFDEVICE)object);NTSTATUS status;if(!c->ControlInitialized)return;
 OwnerLock(c);InterlockedExchange(&c->Inhibit,1);status=Join(c,G96_STOP_CLEANUP);NT_ASSERT(NT_SUCCESS(status));
 if(NT_SUCCESS(status)){InterlockedExchange(&c->Started,0);if(c->Handle){VhfDelete(c->Handle,TRUE);c->Handle=NULL;}if(c->Result){ExFreePoolWithTag(c->Result,'85GO');c->Result=NULL;}}
 OwnerUnlock(c);
}
VOID G96HIDFileCreate(WDFDEVICE device,WDFREQUEST request,WDFFILEOBJECT file)
{
 PUNICODE_STRING name=WdfFileObjectGetFileName(file);UNREFERENCED_PARAMETER(device);WdfRequestComplete(request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);
}
VOID G96HIDFileCleanup(WDFFILEOBJECT file)
{
 G96HID_CONTEXT*c=G96HIDContext(WdfFileObjectGetDevice(file));OwnerLock(c);if(c->OwnerFile==file)Join(c,G96_STOP_CLOSE);OwnerUnlock(c);
}
NTSTATUS G96HIDAdd(WDFDRIVER driver,PWDFDEVICE_INIT init)
{
 WDF_OBJECT_ATTRIBUTES attributes;WDF_PNPPOWER_EVENT_CALLBACKS power;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG files;
 WDFDEVICE device;G96HID_CONTEXT*c;G96HID_STATUS identity;VHF_CONFIG config;NTSTATUS status;UNREFERENCED_PARAMETER(driver);
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&files,G96HIDFileCreate,WDF_NO_EVENT_CALLBACK,G96HIDFileCleanup);WdfDeviceInitSetFileObjectConfig(init,&files,WDF_NO_OBJECT_ATTRIBUTES);
 WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&power);power.EvtDeviceD0Entry=G96HIDD0Entry;power.EvtDeviceD0Exit=G96HIDD0Exit;power.EvtDeviceSelfManagedIoInit=G96HIDIoInit;power.EvtDeviceSelfManagedIoSuspend=G96HIDSuspend;power.EvtDeviceSelfManagedIoRestart=G96HIDRestart;power.EvtDeviceSurpriseRemoval=G96HIDSurprise;WdfDeviceInitSetPnpPowerEventCallbacks(init,&power);
 WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes,G96HID_CONTEXT);attributes.ExecutionLevel=WdfExecutionLevelPassive;attributes.SynchronizationScope=WdfSynchronizationScopeNone;attributes.EvtCleanupCallback=G96HIDCleanup;
 status=WdfDeviceCreate(&init,&attributes,&device);if(!NT_SUCCESS(status))return status;c=G96HIDContext(device);KeInitializeMutex(&c->Control,0);c->ControlInitialized=1;
 c->CreateStatus=c->StartStatus=c->LastSubmit=STATUS_DEVICE_NOT_READY;Status(c,&identity);
 if(!identity.FirmwareMatch||identity.Processors!=8||identity.KernelBuild!=26300||identity.Irql!=PASSIVE_LEVEL)return STATUS_NOT_SUPPORTED;
 c->Result=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*c->Result),'85GO');if(!c->Result)return STATUS_INSUFFICIENT_RESOURCES;RtlZeroMemory(c->Result,sizeof(*c->Result));
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfTrue;queue.EvtIoDeviceControl=G96HIDControl;
 status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))return status;
 status=WdfDeviceCreateDeviceInterface(device,&G96HIDInterface,NULL);if(!NT_SUCCESS(status))return status;
 VHF_CONFIG_INIT(&config,WdfDeviceWdmGetDeviceObject(device),(USHORT)G96HIDDescriptorBytes,G96HIDDescriptor);config.VhfClientContext=c;config.EvtVhfAsyncOperationGetFeature=G96HIDFeature;
 {static WCHAR ids[]=L"OPENLAB\\ONEPLUSOPENTOUCHG96\0";config.HardwareIDs=ids;config.HardwareIDsLength=(USHORT)sizeof(ids);}
 status=VhfCreate(&config,&c->Handle);InterlockedExchange(&c->CreateStatus,status);return status;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING path)
{
 WDF_DRIVER_CONFIG config;NTSTATUS status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 WDF_DRIVER_CONFIG_INIT(&config,G96HIDAdd);return WdfDriverCreate(object,path,WDF_NO_OBJECT_ATTRIBUTES,&config,WDF_NO_HANDLE);
}
