/* SPDX-License-Identifier: MIT
 * G55 bounded replay of four saved physical reports into an owned receiver.
 * No MMIO, controller, raw storage, chip configuration or firmware access.
 * Native dispatch consumes one replay lifetime budget, including on failure.
 */
#include <ntddk.h>
#include <wdf.h>
#include <aux_klib.h>
#include <vhf.h>
#include "g55_baseline.h"
#include "g55_protocol.h"
#include "g55_report.h"
#include "g55_replay.h"

typedef struct {
 VHFHANDLE Handle;
 volatile LONG D0,Started,CreateStatus,StartStatus,Entries,Exits,Features,ReplayAttempts,ReplayAccepted,LastSubmit;
 volatile LONG64 Sequence;
 G55_STATE AcceptedState;G55_REPLAY_RESULT Replay;
} G55_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(G55_CONTEXT,G55Context)
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD G55Add;
EVT_WDF_OBJECT_CONTEXT_CLEANUP G55Cleanup;
EVT_WDF_DEVICE_D0_ENTRY G55D0Entry;
EVT_WDF_DEVICE_D0_EXIT G55D0Exit;
EVT_WDF_DEVICE_SELF_MANAGED_IO_INIT G55IoInit;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G55Control;
EVT_WDF_DEVICE_FILE_CREATE G55FileCreate;
EVT_VHF_ASYNC_OPERATION G55Feature;
static ULONG Counter(volatile LONG*p){return(ULONG)InterlockedCompareExchange(p,0,0);}
static VOID Status(G55_CONTEXT*c,G55_STATUS*out)
{
 UCHAR table[sizeof(G55ExpectedDsdt)];ULONG bytes=0;RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=G55_ABI;out->Magic=G55_MAGIC;
 out->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);out->Irql=KeGetCurrentIrql();
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);if(NT_SUCCESS(RtlGetVersion(&version)))out->KernelBuild=version.dwBuildNumber;
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);out->FirmwareBytes=bytes;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G55ExpectedDsdt,sizeof(table))==sizeof(table))out->FirmwareMatch=1;
 out->D0=Counter(&c->D0);out->Started=Counter(&c->Started);out->CreateStatus=Counter(&c->CreateStatus);out->StartStatus=Counter(&c->StartStatus);
 out->Entries=Counter(&c->Entries);out->Exits=Counter(&c->Exits);out->Features=Counter(&c->Features);out->ReplayAttempts=Counter(&c->ReplayAttempts);out->ReplayAccepted=Counter(&c->ReplayAccepted);out->LastSubmit=Counter(&c->LastSubmit);
 out->MaxContacts=G55_CONTACTS;out->MaxX=G55_RAW_X_MAX;out->MaxY=G55_RAW_Y_MAX;out->ReportBytes=G55_REPORT_BYTES;out->DescriptorBytes=G55DescriptorBytes;out->MappingQualified=0;
 out->ReplayComplete=c->Replay.Complete;out->ReplayError=c->Replay.Error;out->CleanupAttempted=c->Replay.CleanupAttempted;out->CleanupAccepted=c->Replay.CleanupAccepted;out->AcceptedMask=c->AcceptedState.Mask;out->AcceptedGeneration=c->AcceptedState.Generation;out->ReplaySubmitted=c->Replay.Submitted;
 out->Sequence=(ULONGLONG)InterlockedIncrement64(&c->Sequence);RtlCopyMemory(out->BuildId,"G55-replay1",sizeof("G55-replay1"));
}
VOID G55Feature(PVOID context,VHFOPERATIONHANDLE operation,PVOID operationContext,PHID_XFER_PACKET packet)
{
 G55_CONTEXT*c=context;uint32_t written=0;NTSTATUS status=STATUS_NOT_SUPPORTED;UNREFERENCED_PARAMETER(operationContext);
 InterlockedIncrement(&c->Features);
 if(packet&&G55GetFeature(packet->reportId,packet->reportBuffer,packet->reportBufferLen,&written)){packet->reportBufferLen=written;status=STATUS_SUCCESS;}
 VhfAsyncOperationComplete(operation,status);
}
static int G55Submit(void*context,const uint8_t bytes[64])
{
 G55_CONTEXT*c=context;HID_XFER_PACKET packet;NTSTATUS status;
 if(!c->Handle||!Counter(&c->D0)||!Counter(&c->Started))return 0;
 RtlZeroMemory(&packet,sizeof(packet));packet.reportBuffer=(PUCHAR)bytes;packet.reportBufferLen=64;packet.reportId=1;
 status=VhfReadReportSubmit(c->Handle,&packet);InterlockedExchange(&c->LastSubmit,status);return NT_SUCCESS(status);
}
static int G55Wait(void*context)
{
 LARGE_INTEGER interval;UNREFERENCED_PARAMETER(context);interval.QuadPart=-250000;
 return NT_SUCCESS(KeDelayExecutionThread(KernelMode,FALSE,&interval));
}
static uint16_t G55Scan(void*context){UNREFERENCED_PARAMETER(context);return(uint16_t)(KeQueryInterruptTime()/1000u);}
VOID G55Control(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 WDFDEVICE device=WdfIoQueueGetDevice(queue);G55_CONTEXT*c=G55Context(device);G55_REQUEST*in;G55_STATUS*out,identity;NTSTATUS status;ULONG_PTR information=0;
 if(code!=G55_IOCTL_STATUS&&code!=G55_IOCTL_REPLAY){status=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inputBytes!=sizeof(G55_REQUEST)){status=STATUS_INVALID_PARAMETER;goto done;}
 status=WdfRequestRetrieveInputBuffer(request,sizeof(*in),(PVOID*)&in,NULL);if(!NT_SUCCESS(status))goto done;
 if(in->Size!=sizeof(*in)||in->Version!=G55_ABI||in->Magic!=G55_MAGIC){status=STATUS_INVALID_PARAMETER;goto done;}
 if(outputBytes<sizeof(G55_STATUS)){status=STATUS_BUFFER_TOO_SMALL;goto done;}
 status=WdfRequestRetrieveOutputBuffer(request,sizeof(*out),(PVOID*)&out,NULL);if(!NT_SUCCESS(status))goto done;
 if(code==G55_IOCTL_REPLAY){
  G55_REPLAY_IO io;Status(c,&identity);
  if(!identity.FirmwareMatch||identity.Processors!=8||identity.KernelBuild!=26100||identity.Irql!=PASSIVE_LEVEL){status=STATUS_NOT_SUPPORTED;goto done;}
  if(!identity.D0||!identity.Started||!c->Handle){status=STATUS_DEVICE_NOT_READY;goto done;}
  if(InterlockedCompareExchange(&c->ReplayAttempts,1,0)!=0){status=STATUS_QUOTA_EXCEEDED;goto done;}
  io.Context=c;io.Submit=G55Submit;io.Wait25ms=G55Wait;io.Scan100us=G55Scan;
  G55Replay(&c->AcceptedState,&io,&c->Replay);
  InterlockedExchange(&c->ReplayAccepted,(LONG)c->Replay.Accepted);
  /* The response includes accepted count and last submit status. Receiver
   * observations are independently required; acceptance is not delivery. */
 }
 Status(c,out);information=sizeof(*out);status=STATUS_SUCCESS;
 done:WdfRequestCompleteWithInformation(request,status,information);
}
NTSTATUS G55D0Entry(WDFDEVICE device,WDF_POWER_DEVICE_STATE previous)
{
 G55_CONTEXT*c=G55Context(device);UNREFERENCED_PARAMETER(previous);InterlockedIncrement(&c->Entries);InterlockedExchange(&c->D0,1);return STATUS_SUCCESS;
}
NTSTATUS G55D0Exit(WDFDEVICE device,WDF_POWER_DEVICE_STATE target)
{
 G55_CONTEXT*c=G55Context(device);UNREFERENCED_PARAMETER(target);InterlockedExchange(&c->D0,0);InterlockedIncrement(&c->Exits);return STATUS_SUCCESS;
}
NTSTATUS G55IoInit(WDFDEVICE device)
{
 G55_CONTEXT*c=G55Context(device);NTSTATUS status=VhfStart(c->Handle);InterlockedExchange(&c->StartStatus,status);if(NT_SUCCESS(status))InterlockedExchange(&c->Started,1);return status;
}
VOID G55Cleanup(WDFOBJECT object)
{
 G55_CONTEXT*c=G55Context((WDFDEVICE)object);InterlockedExchange(&c->Started,0);
 if(c->Handle){VhfDelete(c->Handle,TRUE);c->Handle=NULL;}
}
VOID G55FileCreate(WDFDEVICE device,WDFREQUEST request,WDFFILEOBJECT file)
{
 PUNICODE_STRING name=WdfFileObjectGetFileName(file);UNREFERENCED_PARAMETER(device);WdfRequestComplete(request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);
}
NTSTATUS G55Add(WDFDRIVER driver,PWDFDEVICE_INIT init)
{
 WDF_OBJECT_ATTRIBUTES attributes;WDF_PNPPOWER_EVENT_CALLBACKS power;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG files;
 WDFDEVICE device;G55_CONTEXT*c;G55_STATUS identity;VHF_CONFIG config;NTSTATUS status;UNREFERENCED_PARAMETER(driver);
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&files,G55FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);WdfDeviceInitSetFileObjectConfig(init,&files,WDF_NO_OBJECT_ATTRIBUTES);
 WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&power);power.EvtDeviceD0Entry=G55D0Entry;power.EvtDeviceD0Exit=G55D0Exit;power.EvtDeviceSelfManagedIoInit=G55IoInit;WdfDeviceInitSetPnpPowerEventCallbacks(init,&power);
 WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes,G55_CONTEXT);attributes.ExecutionLevel=WdfExecutionLevelPassive;attributes.SynchronizationScope=WdfSynchronizationScopeDevice;attributes.EvtCleanupCallback=G55Cleanup;
 status=WdfDeviceCreate(&init,&attributes,&device);if(!NT_SUCCESS(status))return status;c=G55Context(device);
 c->CreateStatus=c->StartStatus=c->LastSubmit=STATUS_DEVICE_NOT_READY;Status(c,&identity);
 if(!identity.FirmwareMatch||identity.Processors!=8||identity.KernelBuild!=26100||identity.Irql!=PASSIVE_LEVEL)return STATUS_NOT_SUPPORTED;
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfTrue;queue.EvtIoDeviceControl=G55Control;
 status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))return status;
 status=WdfDeviceCreateDeviceInterface(device,&G55Interface,NULL);if(!NT_SUCCESS(status))return status;
 VHF_CONFIG_INIT(&config,WdfDeviceWdmGetDeviceObject(device),(USHORT)G55DescriptorBytes,G55Descriptor);config.VhfClientContext=c;config.EvtVhfAsyncOperationGetFeature=G55Feature;
 {static WCHAR ids[]=L"OPENLAB\\ONEPLUSOPENTOUCHG55\0";config.HardwareIDs=ids;config.HardwareIDsLength=(USHORT)sizeof(ids);}
 status=VhfCreate(&config,&c->Handle);InterlockedExchange(&c->CreateStatus,status);return status;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING path)
{
 WDF_DRIVER_CONFIG config;NTSTATUS status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 WDF_DRIVER_CONFIG_INIT(&config,G55Add);return WdfDriverCreate(object,path,WDF_NO_OBJECT_ATTRIBUTES,&config,WDF_NO_HANDLE);
}
