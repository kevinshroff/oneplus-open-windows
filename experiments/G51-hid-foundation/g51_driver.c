/* SPDX-License-Identifier: MIT
 * PnP touchscreen source for later verified Goodix reports. This milestone
 * has no controller/MMIO/storage access and submits only one zero-contact
 * report on explicit administrative request. Live mapping is unqualified.
 */
#include <ntddk.h>
#include <wdf.h>
#include <aux_klib.h>
#include <vhf.h>
#include "g51_baseline.h"
#include "g51_protocol.h"
#include "g51_report.h"

typedef struct {
 VHFHANDLE Handle;
 volatile LONG D0,Started,CreateStatus,StartStatus,Entries,Exits,Features,EmptyAttempts,EmptyAccepted,LastSubmit;
 volatile LONG64 Sequence;
} G51_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(G51_CONTEXT,G51Context)
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD G51Add;
EVT_WDF_OBJECT_CONTEXT_CLEANUP G51Cleanup;
EVT_WDF_DEVICE_D0_ENTRY G51D0Entry;
EVT_WDF_DEVICE_D0_EXIT G51D0Exit;
EVT_WDF_DEVICE_SELF_MANAGED_IO_INIT G51IoInit;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G51Control;
EVT_WDF_DEVICE_FILE_CREATE G51FileCreate;
EVT_VHF_ASYNC_OPERATION G51Feature;
static ULONG Counter(volatile LONG*p){return(ULONG)InterlockedCompareExchange(p,0,0);}
static VOID Status(G51_CONTEXT*c,G51_STATUS*out)
{
 UCHAR table[sizeof(G51ExpectedDsdt)];ULONG bytes=0;RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=G51_ABI;out->Magic=G51_MAGIC;
 out->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);out->Irql=KeGetCurrentIrql();
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);if(NT_SUCCESS(RtlGetVersion(&version)))out->KernelBuild=version.dwBuildNumber;
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);out->FirmwareBytes=bytes;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G51ExpectedDsdt,sizeof(table))==sizeof(table))out->FirmwareMatch=1;
 out->D0=Counter(&c->D0);out->Started=Counter(&c->Started);out->CreateStatus=Counter(&c->CreateStatus);out->StartStatus=Counter(&c->StartStatus);
 out->Entries=Counter(&c->Entries);out->Exits=Counter(&c->Exits);out->Features=Counter(&c->Features);out->EmptyAttempts=Counter(&c->EmptyAttempts);out->EmptyAccepted=Counter(&c->EmptyAccepted);out->LastSubmit=Counter(&c->LastSubmit);
 out->MaxContacts=G51_CONTACTS;out->MaxX=G51_RAW_X_MAX;out->MaxY=G51_RAW_Y_MAX;out->ReportBytes=G51_REPORT_BYTES;out->DescriptorBytes=G51DescriptorBytes;out->MappingQualified=0;
 out->Sequence=(ULONGLONG)InterlockedIncrement64(&c->Sequence);RtlCopyMemory(out->BuildId,"G51-hid-1",sizeof("G51-hid-1"));
}
VOID G51Feature(PVOID context,VHFOPERATIONHANDLE operation,PVOID operationContext,PHID_XFER_PACKET packet)
{
 G51_CONTEXT*c=context;uint32_t written=0;NTSTATUS status=STATUS_NOT_SUPPORTED;UNREFERENCED_PARAMETER(operationContext);
 InterlockedIncrement(&c->Features);
 if(packet&&G51GetFeature(packet->reportId,packet->reportBuffer,packet->reportBufferLen,&written)){packet->reportBufferLen=written;status=STATUS_SUCCESS;}
 VhfAsyncOperationComplete(operation,status);
}
VOID G51Control(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 WDFDEVICE device=WdfIoQueueGetDevice(queue);G51_CONTEXT*c=G51Context(device);G51_REQUEST*in;G51_STATUS*out,identity;NTSTATUS status;ULONG_PTR information=0;
 if(code!=G51_IOCTL_STATUS&&code!=G51_IOCTL_EMPTY){status=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inputBytes!=sizeof(G51_REQUEST)){status=STATUS_INVALID_PARAMETER;goto done;}
 status=WdfRequestRetrieveInputBuffer(request,sizeof(*in),(PVOID*)&in,NULL);if(!NT_SUCCESS(status))goto done;
 if(in->Size!=sizeof(*in)||in->Version!=G51_ABI||in->Magic!=G51_MAGIC){status=STATUS_INVALID_PARAMETER;goto done;}
 if(outputBytes<sizeof(G51_STATUS)){status=STATUS_BUFFER_TOO_SMALL;goto done;}
 status=WdfRequestRetrieveOutputBuffer(request,sizeof(*out),(PVOID*)&out,NULL);if(!NT_SUCCESS(status))goto done;
 if(code==G51_IOCTL_EMPTY){
  UCHAR bytes[G51_REPORT_BYTES];HID_XFER_PACKET packet;Status(c,&identity);
  if(!identity.FirmwareMatch||identity.Processors!=8||identity.KernelBuild!=26100||identity.Irql!=PASSIVE_LEVEL){status=STATUS_NOT_SUPPORTED;goto done;}
  if(!identity.D0||!identity.Started||!c->Handle){status=STATUS_DEVICE_NOT_READY;goto done;}
  if(InterlockedCompareExchange(&c->EmptyAttempts,1,0)!=0){status=STATUS_QUOTA_EXCEEDED;goto done;}
  G51EmptyReport(bytes,0);if(!G51IsEmptyReport(bytes,sizeof(bytes))){status=STATUS_DATA_ERROR;InterlockedExchange(&c->LastSubmit,status);goto done;}
  RtlZeroMemory(&packet,sizeof(packet));packet.reportBuffer=bytes;packet.reportBufferLen=sizeof(bytes);packet.reportId=1;
  status=VhfReadReportSubmit(c->Handle,&packet);InterlockedExchange(&c->LastSubmit,status);if(NT_SUCCESS(status))InterlockedIncrement(&c->EmptyAccepted);
  /* Return the submit result in a fixed status response, including failures.
   * The no-contact lifetime budget is never reset or retried automatically. */
 }
 Status(c,out);information=sizeof(*out);status=STATUS_SUCCESS;
 done:WdfRequestCompleteWithInformation(request,status,information);
}
NTSTATUS G51D0Entry(WDFDEVICE device,WDF_POWER_DEVICE_STATE previous)
{
 G51_CONTEXT*c=G51Context(device);UNREFERENCED_PARAMETER(previous);InterlockedIncrement(&c->Entries);InterlockedExchange(&c->D0,1);return STATUS_SUCCESS;
}
NTSTATUS G51D0Exit(WDFDEVICE device,WDF_POWER_DEVICE_STATE target)
{
 G51_CONTEXT*c=G51Context(device);UNREFERENCED_PARAMETER(target);InterlockedExchange(&c->D0,0);InterlockedIncrement(&c->Exits);return STATUS_SUCCESS;
}
NTSTATUS G51IoInit(WDFDEVICE device)
{
 G51_CONTEXT*c=G51Context(device);NTSTATUS status=VhfStart(c->Handle);InterlockedExchange(&c->StartStatus,status);if(NT_SUCCESS(status))InterlockedExchange(&c->Started,1);return status;
}
VOID G51Cleanup(WDFOBJECT object)
{
 G51_CONTEXT*c=G51Context((WDFDEVICE)object);InterlockedExchange(&c->Started,0);
 if(c->Handle){VhfDelete(c->Handle,TRUE);c->Handle=NULL;}
}
VOID G51FileCreate(WDFDEVICE device,WDFREQUEST request,WDFFILEOBJECT file)
{
 PUNICODE_STRING name=WdfFileObjectGetFileName(file);UNREFERENCED_PARAMETER(device);WdfRequestComplete(request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);
}
NTSTATUS G51Add(WDFDRIVER driver,PWDFDEVICE_INIT init)
{
 WDF_OBJECT_ATTRIBUTES attributes;WDF_PNPPOWER_EVENT_CALLBACKS power;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG files;
 WDFDEVICE device;G51_CONTEXT*c;G51_STATUS identity;VHF_CONFIG config;NTSTATUS status;UNREFERENCED_PARAMETER(driver);
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&files,G51FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);WdfDeviceInitSetFileObjectConfig(init,&files,WDF_NO_OBJECT_ATTRIBUTES);
 WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&power);power.EvtDeviceD0Entry=G51D0Entry;power.EvtDeviceD0Exit=G51D0Exit;power.EvtDeviceSelfManagedIoInit=G51IoInit;WdfDeviceInitSetPnpPowerEventCallbacks(init,&power);
 WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes,G51_CONTEXT);attributes.ExecutionLevel=WdfExecutionLevelPassive;attributes.SynchronizationScope=WdfSynchronizationScopeDevice;attributes.EvtCleanupCallback=G51Cleanup;
 status=WdfDeviceCreate(&init,&attributes,&device);if(!NT_SUCCESS(status))return status;c=G51Context(device);
 c->CreateStatus=c->StartStatus=c->LastSubmit=STATUS_DEVICE_NOT_READY;Status(c,&identity);
 if(!identity.FirmwareMatch||identity.Processors!=8||identity.KernelBuild!=26100||identity.Irql!=PASSIVE_LEVEL)return STATUS_NOT_SUPPORTED;
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfTrue;queue.EvtIoDeviceControl=G51Control;
 status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))return status;
 status=WdfDeviceCreateDeviceInterface(device,&G51Interface,NULL);if(!NT_SUCCESS(status))return status;
 VHF_CONFIG_INIT(&config,WdfDeviceWdmGetDeviceObject(device),(USHORT)G51DescriptorBytes,G51Descriptor);config.VhfClientContext=c;config.EvtVhfAsyncOperationGetFeature=G51Feature;
 status=VhfCreate(&config,&c->Handle);InterlockedExchange(&c->CreateStatus,status);return status;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING path)
{
 WDF_DRIVER_CONFIG config;NTSTATUS status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 WDF_DRIVER_CONFIG_INIT(&config,G51Add);return WdfDriverCreate(object,path,WDF_NO_OBJECT_ATTRIBUTES,&config,WDF_NO_HANDLE);
}
