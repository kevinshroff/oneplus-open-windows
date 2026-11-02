/* SPDX-License-Identifier: MIT
 * Resource-owned bounded primary GENI identity consumer. The clock lease is
 * internal to one synchronous operation. No GENI write, IRQ registration, DMA,
 * GPIO or supply operation. This is not a functional SPI controller.
 */
#include <ntifs.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g70_consumer.h"
#include "g70_binding.h"
static const GUID G70Interface={0x2f1df03e,0xa4ab,0x4e14,{0xa5,0x87,0x32,0xaf,0x76,0xb2,0x39,0x70}};
typedef struct {WDFWAITLOCK Lock;PUCHAR Map[4];volatile LONG Gone;G70_REPORT Report;}G70_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(G70_CONTEXT,G70Context)
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD G70Add;
EVT_WDF_DEVICE_PREPARE_HARDWARE G70Prepare;
EVT_WDF_DEVICE_RELEASE_HARDWARE G70Release;
EVT_WDF_DEVICE_D0_ENTRY G70D0Entry;
EVT_WDF_DEVICE_D0_EXIT G70D0Exit;
EVT_WDF_DEVICE_SURPRISE_REMOVAL G70Surprise;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G70Control;
EVT_WDF_DEVICE_FILE_CREATE G70FileCreate;
_Static_assert(sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR)==20,"ARM64 WDK CM ABI");
_Static_assert(G70_IOCTL_QUERY==CTL_CODE(FILE_DEVICE_UNKNOWN,0x9f7,METHOD_BUFFERED,FILE_READ_ACCESS),"query IOCTL");
_Static_assert(G70_IOCTL_CYCLE==CTL_CODE(FILE_DEVICE_UNKNOWN,0x9f8,METHOD_BUFFERED,FILE_READ_ACCESS|FILE_WRITE_ACCESS),"cycle IOCTL");
static void G70Lock(G70_CONTEXT*c){NTSTATUS s=WdfWaitLockAcquire(c->Lock,NULL);NT_ASSERT(NT_SUCCESS(s));UNREFERENCED_PARAMETER(s);}
static void G70Unlock(G70_CONTEXT*c){WdfWaitLockRelease(c->Lock);}
static int Available(void*x){G70_CONTEXT*c=x;return !InterlockedCompareExchange(&c->Gone,0,0)&&c->Report.InD0&&c->Report.ResourceOK&&c->Report.MappingMask==15;}
static int Read(void*x,uint32_t reg,uint32_t*v)
{
 G70_CONTEXT*c=x;if(reg>=6||!Available(c))return 0;
 *v=READ_REGISTER_ULONG((volatile ULONG*)(c->Map[G70RegisterPage[reg]]+G70RegisterOffset[reg]));return 1;
}
static int Write(void*x,uint32_t reg,uint32_t value)
{
 G70_CONTEXT*c=x;if(reg||!Available(c)||(value&~G70_VOTE_MASK)!=0x40002380)return 0;
 WRITE_REGISTER_ULONG((volatile ULONG*)(c->Map[2]+8),value);return 1;
}
static void Wait(void*x){UNREFERENCED_PARAMETER(x);KeStallExecutionProcessor(1);}
static int ReadEngine(void*x,uint32_t reg,uint32_t*v)
{
 G70_CONTEXT*c=x;if(reg>=10||!v||!Available(c)||!c->Report.Clock.Active||c->Report.Clock.Phase!=4)return 0;
 *v=READ_REGISTER_ULONG((volatile ULONG*)(c->Map[3]+G70EngineOffset[reg]));return 1;
}
static G70_CLOCK_IO Io(G70_CONTEXT*c){G70_CLOCK_IO io={c,Available,Read,Write,Wait};return io;}
static void Unmap(G70_CONTEXT*c)
{
 int i;for(i=3;i>=0;i--)if(c->Map[i]){MmUnmapIoSpace(c->Map[i],G70MapBytes[i]);c->Map[i]=NULL;c->Report.MappingMask&=~(1u<<i);c->Report.UnmapCalls++;}
}
static NTSTATUS Identity(G70_REPORT*r)
{
 UCHAR table[sizeof(G70ExpectedDsdt)];ULONG bytes=0;RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(r,sizeof(*r));r->Size=sizeof(*r);r->Version=1;r->Magic=G70_MAGIC;r->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);r->Irql=KeGetCurrentIrql();RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);status=RtlGetVersion(&version);if(NT_SUCCESS(status))r->KernelBuild=version.dwBuildNumber;
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);r->FirmwareBytes=bytes;r->FirmwareStatus=status;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G70ExpectedDsdt,sizeof(table))==sizeof(table))r->FirmwareMatch=1;
 return r->Processors==8&&r->Irql==PASSIVE_LEVEL&&r->KernelBuild==26100&&r->FirmwareMatch?STATUS_SUCCESS:STATUS_NOT_SUPPORTED;
}
NTSTATUS G70Prepare(WDFDEVICE device,WDFCMRESLIST raw,WDFCMRESLIST translated)
{
 G70_CONTEXT*c=G70Context(device);G70_REPORT*r=&c->Report;ULONG i;uint32_t index[4];NTSTATUS status=STATUS_DEVICE_CONFIGURATION_ERROR;
 G70Lock(c);r->PrepareCalls++;r->RawCount=WdfCmResourceListGetCount(raw);r->TranslatedCount=WdfCmResourceListGetCount(translated);
 if(r->MappingMask||r->InD0||r->Clock.DirtyMask||r->Clock.Active||InterlockedCompareExchange(&c->Gone,0,0))goto done;
 r->ResourceOK=0;RtlZeroMemory(r->Raw,sizeof(r->Raw));RtlZeroMemory(r->Translated,sizeof(r->Translated));
 if(r->RawCount!=5||r->TranslatedCount!=5)goto done;
 for(i=0;i<5;i++){
  PCM_PARTIAL_RESOURCE_DESCRIPTOR a=WdfCmResourceListGetDescriptor(raw,i),b=WdfCmResourceListGetDescriptor(translated,i);
  if(!a||!b)goto done;RtlCopyMemory(r->Raw[i],a,20);RtlCopyMemory(r->Translated[i],b,20);
 }
 if(!G70ValidateControllerResources(r->Raw,r->Translated,index))goto done;
 for(i=0;i<4;i++){
  PCM_PARTIAL_RESOURCE_DESCRIPTOR descriptor=WdfCmResourceListGetDescriptor(translated,index[i]);
  r->MapCalls++;c->Map[i]=MmMapIoSpaceEx(descriptor->u.Memory.Start,descriptor->u.Memory.Length,PAGE_READWRITE|PAGE_NOCACHE);
  if(!c->Map[i]){status=STATUS_INSUFFICIENT_RESOURCES;Unmap(c);goto done;}r->MappingMask|=1u<<i;
 }
 r->ResourceOK=1;status=STATUS_SUCCESS;
 done:G70Unlock(c);return status;
}
NTSTATUS G70D0Entry(WDFDEVICE device,WDF_POWER_DEVICE_STATE previous)
{
 G70_CONTEXT*c=G70Context(device);NTSTATUS s=STATUS_DEVICE_NOT_READY;UNREFERENCED_PARAMETER(previous);G70Lock(c);
 if(c->Report.ResourceOK&&c->Report.MappingMask==15&&!InterlockedCompareExchange(&c->Gone,0,0)){c->Report.InD0=1;c->Report.D0Entries++;s=STATUS_SUCCESS;}G70Unlock(c);return s;
}
NTSTATUS G70D0Exit(WDFDEVICE device,WDF_POWER_DEVICE_STATE target)
{
 G70_CONTEXT*c=G70Context(device);NTSTATUS s=STATUS_SUCCESS;UNREFERENCED_PARAMETER(target);G70Lock(c);c->Report.InD0=0;c->Report.D0Exits++;
 if(c->Report.Clock.DirtyMask||c->Report.Clock.Active||(c->Report.Clock.Writes&&!c->Report.Clock.Restored))s=STATUS_DEVICE_HARDWARE_ERROR;
 G70Unlock(c);return s;
}
NTSTATUS G70Release(WDFDEVICE device,WDFCMRESLIST translated)
{
 G70_CONTEXT*c=G70Context(device);UNREFERENCED_PARAMETER(translated);G70Lock(c);c->Report.InD0=0;c->Report.ResourceOK=0;c->Report.ReleaseCalls++;Unmap(c);G70Unlock(c);return STATUS_SUCCESS;
}
VOID G70Surprise(WDFDEVICE device)
{
 G70_CONTEXT*c=G70Context(device);InterlockedExchange(&c->Gone,1);G70Lock(c);c->Report.Removed=1;G70Unlock(c);
}
VOID G70FileCreate(WDFDEVICE device,WDFREQUEST request,WDFFILEOBJECT file)
{
 PUNICODE_STRING name=WdfFileObjectGetFileName(file);UNREFERENCED_PARAMETER(device);WdfRequestComplete(request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);
}
VOID G70Control(WDFQUEUE queue,WDFREQUEST request,size_t output,size_t input,ULONG code)
{
 G70_CONTEXT*c=G70Context(WdfIoQueueGetDevice(queue));G70_REQUEST*in;G70_REPORT*out;uint64_t nonce;NTSTATUS status;
 if(code!=G70_IOCTL_QUERY&&code!=G70_IOCTL_CYCLE){WdfRequestComplete(request,STATUS_INVALID_DEVICE_REQUEST);return;}
 if(input!=sizeof(*in)||output!=sizeof(*out)){WdfRequestComplete(request,STATUS_INFO_LENGTH_MISMATCH);return;}
 status=WdfRequestRetrieveInputBuffer(request,sizeof(*in),(PVOID*)&in,NULL);if(!NT_SUCCESS(status)){WdfRequestComplete(request,status);return;}
 if(in->Size!=sizeof(*in)||in->Version!=1||in->Magic!=G70_MAGIC||(code==G70_IOCTL_QUERY?in->Nonce!=0:in->Nonce==0)){WdfRequestComplete(request,STATUS_INVALID_PARAMETER);return;}nonce=in->Nonce;
 status=WdfRequestRetrieveOutputBuffer(request,sizeof(*out),(PVOID*)&out,NULL);if(!NT_SUCCESS(status)){WdfRequestComplete(request,status);return;}
 G70Lock(c);
 if(code==G70_IOCTL_CYCLE){
  if(!Available(c)){status=STATUS_DEVICE_NOT_READY;goto done;}
  if(c->Report.CycleAttempts){status=STATUS_QUOTA_EXCEEDED;goto done;}
  c->Report.CycleAttempts++;G70_CLOCK_IO io=Io(c);
  G70_CONSUMER_IO consumer={io,ReadEngine};G70Consume(&consumer,&c->Report.Clock,&c->Report.Probe,nonce);
 }
 c->Report.Removed=(ULONG)InterlockedCompareExchange(&c->Gone,0,0);RtlCopyMemory(out,&c->Report,sizeof(*out));status=STATUS_SUCCESS;
 done:G70Unlock(c);WdfRequestCompleteWithInformation(request,status,NT_SUCCESS(status)?sizeof(*out):0);
}
NTSTATUS G70Add(WDFDRIVER driver,PWDFDEVICE_INIT init)
{
 WDF_OBJECT_ATTRIBUTES attr;WDF_PNPPOWER_EVENT_CALLBACKS power;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG files;WDFDEVICE device;G70_CONTEXT*c;G70_REPORT identity;NTSTATUS status;UNREFERENCED_PARAMETER(driver);
 status=Identity(&identity);if(!NT_SUCCESS(status))return status;
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&files,G70FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);WdfDeviceInitSetFileObjectConfig(init,&files,WDF_NO_OBJECT_ATTRIBUTES);
 WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&power);power.EvtDevicePrepareHardware=G70Prepare;power.EvtDeviceReleaseHardware=G70Release;power.EvtDeviceD0Entry=G70D0Entry;power.EvtDeviceD0Exit=G70D0Exit;power.EvtDeviceSurpriseRemoval=G70Surprise;WdfDeviceInitSetPnpPowerEventCallbacks(init,&power);
 WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attr,G70_CONTEXT);attr.ExecutionLevel=WdfExecutionLevelPassive;attr.SynchronizationScope=WdfSynchronizationScopeNone;status=WdfDeviceCreate(&init,&attr,&device);if(!NT_SUCCESS(status))return status;c=G70Context(device);RtlCopyMemory(&c->Report,&identity,sizeof(identity));
 WDF_OBJECT_ATTRIBUTES_INIT(&attr);attr.ParentObject=device;status=WdfWaitLockCreate(&attr,&c->Lock);if(!NT_SUCCESS(status))return status;
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfTrue;queue.EvtIoDeviceControl=G70Control;status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))return status;
 return WdfDeviceCreateDeviceInterface(device,&G70Interface,NULL);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING path)
{
 WDF_DRIVER_CONFIG config;NTSTATUS status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;WDF_DRIVER_CONFIG_INIT(&config,G70Add);return WdfDriverCreate(object,path,WDF_NO_OBJECT_ATTRIBUTES,&config,WDF_NO_HANDLE);
}
