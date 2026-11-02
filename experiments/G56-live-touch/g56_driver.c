/* SPDX-License-Identifier: MIT
 * Live Goodix -> accepted-state HID -> VHF source. The hardware API permits
 * one bounded powered episode and restores the exact qualified baseline.
 * No captured packet fixtures or software replay path are linked here.
 */
#include <ntddk.h>
#include <wdf.h>
#include <aux_klib.h>
#include <vhf.h>
#include "g56hid_baseline.h"
#include "g56hid_protocol.h"
#include "g56hid_report.h"
#include "g56_input.h"
#include "g56_hwapi.h"

typedef struct {
 VHFHANDLE Handle;
 volatile LONG D0,Started,CreateStatus,StartStatus,Entries,Exits,Features,LiveAttempts,LastSubmit;
 volatile LONG64 Sequence;
 G56_INPUT Live;ULONG LastHardwareCode,LiveComplete;
} G56HID_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(G56HID_CONTEXT,G56HIDContext)
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD G56HIDAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP G56HIDCleanup;
EVT_WDF_DEVICE_D0_ENTRY G56HIDD0Entry;
EVT_WDF_DEVICE_D0_EXIT G56HIDD0Exit;
EVT_WDF_DEVICE_SELF_MANAGED_IO_INIT G56HIDIoInit;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G56HIDControl;
EVT_WDF_DEVICE_FILE_CREATE G56HIDFileCreate;
EVT_VHF_ASYNC_OPERATION G56HIDFeature;
static ULONG Counter(volatile LONG*p){return(ULONG)InterlockedCompareExchange(p,0,0);}
static VOID Status(G56HID_CONTEXT*c,G56HID_STATUS*out)
{
 UCHAR table[sizeof(G56HIDExpectedDsdt)];ULONG bytes=0;RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=G56HID_ABI;out->Magic=G56HID_MAGIC;
 out->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);out->Irql=KeGetCurrentIrql();
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);if(NT_SUCCESS(RtlGetVersion(&version)))out->KernelBuild=version.dwBuildNumber;
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);out->FirmwareBytes=bytes;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G56HIDExpectedDsdt,sizeof(table))==sizeof(table))out->FirmwareMatch=1;
 out->D0=Counter(&c->D0);out->Started=Counter(&c->Started);out->CreateStatus=Counter(&c->CreateStatus);out->StartStatus=Counter(&c->StartStatus);
 out->Entries=Counter(&c->Entries);out->Exits=Counter(&c->Exits);out->Features=Counter(&c->Features);out->LiveAttempts=Counter(&c->LiveAttempts);out->ReportsAccepted=c->Live.SubmitAccepted;out->LastSubmit=Counter(&c->LastSubmit);
 out->MaxContacts=G56HID_CONTACTS;out->MaxX=G56HID_RAW_X_MAX;out->MaxY=G56HID_RAW_Y_MAX;out->ReportBytes=G56HID_REPORT_BYTES;out->DescriptorBytes=G56HIDDescriptorBytes;out->MappingQualified=0;
 out->LiveComplete=c->LiveComplete;out->LiveError=c->LastHardwareCode?c->LastHardwareCode:c->Live.Error;out->StopAttempts=c->Live.StopAttempts;out->StopAccepted=c->Live.StopAccepted;out->AcceptedMask=c->Live.Accepted.Mask;out->AcceptedGeneration=c->Live.Accepted.Generation;out->ReportsSubmitted=c->Live.SubmitAttempts;
 out->Sequence=(ULONGLONG)InterlockedIncrement64(&c->Sequence);RtlCopyMemory(out->BuildId,"G56-live1",sizeof("G56-live1"));
}
VOID G56HIDFeature(PVOID context,VHFOPERATIONHANDLE operation,PVOID operationContext,PHID_XFER_PACKET packet)
{
 G56HID_CONTEXT*c=context;uint32_t written=0;NTSTATUS status=STATUS_NOT_SUPPORTED;UNREFERENCED_PARAMETER(operationContext);
 InterlockedIncrement(&c->Features);
 if(packet&&G56HIDGetFeature(packet->reportId,packet->reportBuffer,packet->reportBufferLen,&written)){packet->reportBufferLen=written;status=STATUS_SUCCESS;}
 VhfAsyncOperationComplete(operation,status);
}
static int G56HIDSubmit(void*context,const uint8_t bytes[64])
{
 G56HID_CONTEXT*c=context;HID_XFER_PACKET packet;NTSTATUS status;
 if(!c->Handle||!Counter(&c->D0)||!Counter(&c->Started))return 0;
 RtlZeroMemory(&packet,sizeof(packet));packet.reportBuffer=(PUCHAR)bytes;packet.reportBufferLen=64;packet.reportId=1;
 status=VhfReadReportSubmit(c->Handle,&packet);InterlockedExchange(&c->LastSubmit,status);return NT_SUCCESS(status);
}
static int G56HIDStage(void*context,const uint8_t*raw,uint32_t n,uint64_t at)
{
 G56HID_CONTEXT*c=context;if(!c->Handle||!Counter(&c->D0)||!Counter(&c->Started))return 0;
 return G56InputStage(&c->Live,raw,n,(uint16_t)(at/100));
}
static int G56HIDPublish(void*context,const uint8_t*raw,uint32_t n)
{
 G56HID_CONTEXT*c=context;G56_INPUT_IO io={c,G56HIDSubmit};
 if(!c->Handle||!Counter(&c->D0)||!Counter(&c->Started))return 0;
 return G56InputPublish(&c->Live,&io,raw,n);
}
VOID G56HIDControl(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 WDFDEVICE device=WdfIoQueueGetDevice(queue);G56HID_CONTEXT*c=G56HIDContext(device);G56HID_REQUEST*in;PVOID out;G56HID_STATUS identity;NTSTATUS status;ULONG_PTR information=0;size_t needed;int hw;
 hw=code==G56_IOCTL_STATUS||code==G56_IOCTL_SNAPSHOT||code==G56_IOCTL_PMIC||code==G56_IOCTL_POWER;
 if(!hw&&code!=G56HID_IOCTL_STATUS){status=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inputBytes!=sizeof(*in)){status=STATUS_INVALID_PARAMETER;goto done;}
 status=WdfRequestRetrieveInputBuffer(request,sizeof(*in),(PVOID*)&in,NULL);if(!NT_SUCCESS(status))goto done;
 if(in->Size!=sizeof(*in)||in->Version!=1||in->Magic!=(hw?G56_MAGIC:G56HID_MAGIC)){status=STATUS_INVALID_PARAMETER;goto done;}
 needed=!hw?sizeof(G56HID_STATUS):code==G56_IOCTL_STATUS?sizeof(G56_STATUS):code==G56_IOCTL_SNAPSHOT?sizeof(G56_SNAPSHOT):code==G56_IOCTL_PMIC?sizeof(G56_PMIC):sizeof(G56_TRIAL);
 if(outputBytes<needed){status=STATUS_BUFFER_TOO_SMALL;goto done;}
 status=WdfRequestRetrieveOutputBuffer(request,needed,&out,NULL);if(!NT_SUCCESS(status))goto done;
 if(!hw){Status(c,out);status=STATUS_SUCCESS;}
 else if(code==G56_IOCTL_STATUS){G56HardwareStatus(out);status=STATUS_SUCCESS;}
 else if(code==G56_IOCTL_SNAPSHOT)status=G56HardwareSnapshot(out);
 else if(code==G56_IOCTL_PMIC){G56HardwarePmic(out);status=STATUS_SUCCESS;}
 else{
  G56_TRIAL*trial=out;G56_STREAM_IO stream={c,G56HIDStage,G56HIDPublish};G56_INPUT_IO input={c,G56HIDSubmit};int released;
  Status(c,&identity);
  if(!identity.FirmwareMatch||identity.Processors!=8||identity.KernelBuild!=26100||identity.Irql!=PASSIVE_LEVEL){status=STATUS_NOT_SUPPORTED;goto done;}
  if(!identity.D0||!identity.Started||!c->Handle){status=STATUS_DEVICE_NOT_READY;goto done;}
  G56HardwareTrial(trial,&stream);
  if(trial->Attempt){
   InterlockedIncrement(&c->LiveAttempts);released=G56InputStop(&c->Live,&input,(uint16_t)(G56HardwareTimeUs()/100));
   c->LastHardwareCode=trial->Trial.Power.Code;
   c->LiveComplete=released&&!c->Live.Error&&trial->Trial.Power.Code==0&&trial->Trial.Power.Restored&&trial->FixedRegistersUnchanged&&trial->Trial.Touch.Restored&&trial->Trial.Touch.Poll.Code==0&&trial->Trial.Touch.Poll.Limit==100&&trial->Trial.Touch.Poll.Cycles==100;
  }
  status=STATUS_SUCCESS;
 }
 if(NT_SUCCESS(status))information=needed;
 done:WdfRequestCompleteWithInformation(request,status,information);
}
NTSTATUS G56HIDD0Entry(WDFDEVICE device,WDF_POWER_DEVICE_STATE previous)
{
 G56HID_CONTEXT*c=G56HIDContext(device);UNREFERENCED_PARAMETER(previous);InterlockedIncrement(&c->Entries);InterlockedExchange(&c->D0,1);return STATUS_SUCCESS;
}
NTSTATUS G56HIDD0Exit(WDFDEVICE device,WDF_POWER_DEVICE_STATE target)
{
 G56HID_CONTEXT*c=G56HIDContext(device);UNREFERENCED_PARAMETER(target);InterlockedExchange(&c->D0,0);InterlockedIncrement(&c->Exits);return STATUS_SUCCESS;
}
NTSTATUS G56HIDIoInit(WDFDEVICE device)
{
 G56HID_CONTEXT*c=G56HIDContext(device);NTSTATUS status=VhfStart(c->Handle);InterlockedExchange(&c->StartStatus,status);if(NT_SUCCESS(status))InterlockedExchange(&c->Started,1);return status;
}
VOID G56HIDCleanup(WDFOBJECT object)
{
 G56HID_CONTEXT*c=G56HIDContext((WDFDEVICE)object);InterlockedExchange(&c->Started,0);
 if(c->Handle){VhfDelete(c->Handle,TRUE);c->Handle=NULL;}
}
VOID G56HIDFileCreate(WDFDEVICE device,WDFREQUEST request,WDFFILEOBJECT file)
{
 PUNICODE_STRING name=WdfFileObjectGetFileName(file);UNREFERENCED_PARAMETER(device);WdfRequestComplete(request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);
}
NTSTATUS G56HIDAdd(WDFDRIVER driver,PWDFDEVICE_INIT init)
{
 WDF_OBJECT_ATTRIBUTES attributes;WDF_PNPPOWER_EVENT_CALLBACKS power;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG files;
 WDFDEVICE device;G56HID_CONTEXT*c;G56HID_STATUS identity;VHF_CONFIG config;NTSTATUS status;UNREFERENCED_PARAMETER(driver);
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&files,G56HIDFileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);WdfDeviceInitSetFileObjectConfig(init,&files,WDF_NO_OBJECT_ATTRIBUTES);
 WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&power);power.EvtDeviceD0Entry=G56HIDD0Entry;power.EvtDeviceD0Exit=G56HIDD0Exit;power.EvtDeviceSelfManagedIoInit=G56HIDIoInit;WdfDeviceInitSetPnpPowerEventCallbacks(init,&power);
 WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes,G56HID_CONTEXT);attributes.ExecutionLevel=WdfExecutionLevelPassive;attributes.SynchronizationScope=WdfSynchronizationScopeDevice;attributes.EvtCleanupCallback=G56HIDCleanup;
 status=WdfDeviceCreate(&init,&attributes,&device);if(!NT_SUCCESS(status))return status;c=G56HIDContext(device);
 c->CreateStatus=c->StartStatus=c->LastSubmit=STATUS_DEVICE_NOT_READY;Status(c,&identity);
 if(!identity.FirmwareMatch||identity.Processors!=8||identity.KernelBuild!=26100||identity.Irql!=PASSIVE_LEVEL)return STATUS_NOT_SUPPORTED;
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfTrue;queue.EvtIoDeviceControl=G56HIDControl;
 status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))return status;
 status=WdfDeviceCreateDeviceInterface(device,&G56HIDInterface,NULL);if(!NT_SUCCESS(status))return status;
 VHF_CONFIG_INIT(&config,WdfDeviceWdmGetDeviceObject(device),(USHORT)G56HIDDescriptorBytes,G56HIDDescriptor);config.VhfClientContext=c;config.EvtVhfAsyncOperationGetFeature=G56HIDFeature;
 {static WCHAR ids[]=L"OPENLAB\\ONEPLUSOPENTOUCHG56\0";config.HardwareIDs=ids;config.HardwareIDsLength=(USHORT)sizeof(ids);}
 status=VhfCreate(&config,&c->Handle);InterlockedExchange(&c->CreateStatus,status);return status;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING path)
{
 WDF_DRIVER_CONFIG config;NTSTATUS status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 WDF_DRIVER_CONFIG_INIT(&config,G56HIDAdd);return WdfDriverCreate(object,path,WDF_NO_OBJECT_ATTRIBUTES,&config,WDF_NO_HANDLE);
}
