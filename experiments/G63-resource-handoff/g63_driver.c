/* SPDX-License-Identifier: MIT
 * ACPI resource handoff recorder. This driver never maps or accesses hardware,
 * connects an ISR, starts DMA, votes power/clocks or exposes an SPB controller.
 * It records the actual lists passed to this device by KMDF, under one lock.
 */
#include <ntifs.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g63_capture.h"
#include "g63_binding.h"
static const GUID G63Interface={0x01404e15,0xc240,0x46c1,{0x94,0xf4,0x1e,0x97,0xa1,0x65,0x63,0x71}};
typedef struct{KMUTEX Lock;G63_REPORT Report;}G63_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(G63_CONTEXT,G63Context)
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD G63Add;
EVT_WDF_DEVICE_PREPARE_HARDWARE G63Prepare;
EVT_WDF_DEVICE_RELEASE_HARDWARE G63Release;
EVT_WDF_DEVICE_D0_ENTRY G63D0Entry;
EVT_WDF_DEVICE_D0_EXIT G63D0Exit;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G63Control;
EVT_WDF_DEVICE_FILE_CREATE G63FileCreate;
_Static_assert(sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR)==20,"Pinned ARM64 WDK descriptor ABI");
_Static_assert(G63_IOCTL_QUERY==CTL_CODE(FILE_DEVICE_UNKNOWN,0x9f0,METHOD_BUFFERED,FILE_READ_ACCESS),"IOCTL ABI");
static void G63Lock(G63_CONTEXT*c){NTSTATUS s=KeWaitForSingleObject(&c->Lock,Executive,KernelMode,FALSE,NULL);NT_ASSERT(s==STATUS_SUCCESS);UNREFERENCED_PARAMETER(s);}
static void G63Unlock(G63_CONTEXT*c){KeReleaseMutex(&c->Lock,FALSE);}
static NTSTATUS Identity(G63_REPORT*r)
{
 UCHAR table[sizeof(G63ExpectedDsdt)];ULONG bytes=0;RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(r,sizeof(*r));r->Size=sizeof(*r);r->Version=1;r->Magic=G63_MAGIC;r->Capacity=G63_CAPACITY;r->DescriptorBytes=sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR);
 r->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);r->Irql=KeGetCurrentIrql();RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);status=RtlGetVersion(&version);if(NT_SUCCESS(status))r->KernelBuild=version.dwBuildNumber;
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);r->FirmwareBytes=bytes;r->FirmwareStatus=status;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G63ExpectedDsdt,sizeof(table))==sizeof(table))r->FirmwareMatch=1;
 return r->Processors==8&&r->Irql==PASSIVE_LEVEL&&r->KernelBuild==26100&&r->FirmwareMatch?STATUS_SUCCESS:STATUS_NOT_SUPPORTED;
}
NTSTATUS G63Prepare(WDFDEVICE device,WDFCMRESLIST raw,WDFCMRESLIST translated)
{
 G63_CONTEXT*c=G63Context(device);ULONG i,n=WdfCmResourceListGetCount(raw),t=WdfCmResourceListGetCount(translated);G63Lock(c);G63CaptureBegin(&c->Report,n,t,sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
 for(i=0;i<n&&i<G63_CAPACITY;i++)G63CaptureRow(&c->Report,0,i,WdfCmResourceListGetDescriptor(raw,i));
 for(i=0;i<t&&i<G63_CAPACITY;i++)G63CaptureRow(&c->Report,1,i,WdfCmResourceListGetDescriptor(translated,i));
 G63CaptureEnd(&c->Report);G63Unlock(c);return STATUS_SUCCESS;
}
NTSTATUS G63Release(WDFDEVICE device,WDFCMRESLIST translated)
{
 G63_CONTEXT*c=G63Context(device);UNREFERENCED_PARAMETER(translated);G63Lock(c);c->Report.ReleaseCalls++;c->Report.CaptureComplete=0;G63Unlock(c);return STATUS_SUCCESS;
}
NTSTATUS G63D0Entry(WDFDEVICE device,WDF_POWER_DEVICE_STATE previous)
{
 G63_CONTEXT*c=G63Context(device);UNREFERENCED_PARAMETER(previous);G63Lock(c);c->Report.D0Entries++;c->Report.InD0=1;G63Unlock(c);return STATUS_SUCCESS;
}
NTSTATUS G63D0Exit(WDFDEVICE device,WDF_POWER_DEVICE_STATE target)
{
 G63_CONTEXT*c=G63Context(device);UNREFERENCED_PARAMETER(target);G63Lock(c);c->Report.D0Exits++;c->Report.InD0=0;G63Unlock(c);return STATUS_SUCCESS;
}
VOID G63FileCreate(WDFDEVICE device,WDFREQUEST request,WDFFILEOBJECT file)
{
 PUNICODE_STRING name=WdfFileObjectGetFileName(file);UNREFERENCED_PARAMETER(device);WdfRequestComplete(request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);
}
VOID G63Control(WDFQUEUE queue,WDFREQUEST request,size_t output,size_t input,ULONG code)
{
 G63_CONTEXT*c=G63Context(WdfIoQueueGetDevice(queue));G63_REQUEST*in;G63_REPORT*out;NTSTATUS status;
 if(code!=G63_IOCTL_QUERY){WdfRequestComplete(request,STATUS_INVALID_DEVICE_REQUEST);return;}
 if(input!=sizeof(*in)||output!=sizeof(*out)){WdfRequestComplete(request,STATUS_INFO_LENGTH_MISMATCH);return;}
 status=WdfRequestRetrieveInputBuffer(request,sizeof(*in),(PVOID*)&in,NULL);if(!NT_SUCCESS(status)){WdfRequestComplete(request,status);return;}
 if(in->Size!=sizeof(*in)||in->Version!=1||in->Magic!=G63_MAGIC){WdfRequestComplete(request,STATUS_INVALID_PARAMETER);return;}
 status=WdfRequestRetrieveOutputBuffer(request,sizeof(*out),(PVOID*)&out,NULL);if(!NT_SUCCESS(status)){WdfRequestComplete(request,status);return;}
 G63Lock(c);RtlCopyMemory(out,&c->Report,sizeof(*out));G63Unlock(c);WdfRequestCompleteWithInformation(request,STATUS_SUCCESS,sizeof(*out));
}
NTSTATUS G63Add(WDFDRIVER driver,PWDFDEVICE_INIT init)
{
 WDF_OBJECT_ATTRIBUTES attr;WDF_PNPPOWER_EVENT_CALLBACKS power;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG files;WDFDEVICE device;G63_CONTEXT*c;G63_REPORT identity;NTSTATUS status;UNREFERENCED_PARAMETER(driver);
 status=Identity(&identity);if(!NT_SUCCESS(status))return status;
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&files,G63FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);WdfDeviceInitSetFileObjectConfig(init,&files,WDF_NO_OBJECT_ATTRIBUTES);
 WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&power);power.EvtDevicePrepareHardware=G63Prepare;power.EvtDeviceReleaseHardware=G63Release;power.EvtDeviceD0Entry=G63D0Entry;power.EvtDeviceD0Exit=G63D0Exit;WdfDeviceInitSetPnpPowerEventCallbacks(init,&power);
 WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attr,G63_CONTEXT);attr.ExecutionLevel=WdfExecutionLevelPassive;attr.SynchronizationScope=WdfSynchronizationScopeNone;status=WdfDeviceCreate(&init,&attr,&device);if(!NT_SUCCESS(status))return status;
 c=G63Context(device);KeInitializeMutex(&c->Lock,0);RtlCopyMemory(&c->Report,&identity,sizeof(identity));
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfTrue;queue.EvtIoDeviceControl=G63Control;status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))return status;
 return WdfDeviceCreateDeviceInterface(device,&G63Interface,NULL);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING path)
{
 WDF_DRIVER_CONFIG config;NTSTATUS status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;WDF_DRIVER_CONFIG_INIT(&config,G63Add);return WdfDriverCreate(object,path,WDF_NO_OBJECT_ATTRIBUTES,&config,WDF_NO_HANDLE);
}
