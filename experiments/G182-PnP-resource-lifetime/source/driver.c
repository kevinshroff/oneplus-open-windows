/* PnP resource-lifetime qualifier. This version maps only the exact assigned
 * ranges and performs NO register read/write, GLINK, sensor or battery action.
 * Resource assignment/D0 observation is not production hardware qualification. */
#include <ntifs.h>
#include <wdf.h>
#include <aux_klib.h>
#include "resources.h"
#include "binding.h"
#define OP182_MAGIC UINT64_C(0x315352323831474f)
#define OP182_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN,0xb10,METHOD_BUFFERED,FILE_READ_ACCESS)
typedef struct {uint32_t Size,Version;uint64_t Magic,Nonce;uint32_t Count,Reserved;}OP182_REQUEST;
typedef struct {
 uint32_t Size,Version;uint64_t Magic,Now100ns,D0Epoch,PrepareEpoch,ReleaseCalls,MapCalls,UnmapCalls;
 uint32_t KernelBuild,Cpus,Irql,Prepared,D0Active,MapCount,ValidationCode,LastStatus,FirmwareMatch,ProducerQualified,Reserved[2];
}OP182_STATUS_DATA;
C_ASSERT(sizeof(OP182_REQUEST)==32);C_ASSERT(sizeof(OP182_STATUS_DATA)==112);
typedef struct {WDFWAITLOCK Lock;OP182_STATUS_DATA Data;PVOID Maps[OP182_RESOURCE_COUNT];}OP182_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(OP182_CONTEXT,Op182Context)
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD Op182Add;
EVT_WDF_DEVICE_PREPARE_HARDWARE Op182Prepare;
EVT_WDF_DEVICE_RELEASE_HARDWARE Op182Release;
EVT_WDF_DEVICE_D0_ENTRY Op182D0Entry;
EVT_WDF_DEVICE_D0_EXIT Op182D0Exit;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL Op182Control;
EVT_WDF_DEVICE_FILE_CREATE Op182FileCreate;
static const GUID Interface={0x8fa58182,0xfd04,0x4f21,{0x9f,0x08,0xa3,0x04,0xc1,0xbd,0x01,0x82}};
static void Op182Lock(OP182_CONTEXT*c){NTSTATUS s=WdfWaitLockAcquire(c->Lock,NULL);NT_ASSERT(NT_SUCCESS(s));UNREFERENCED_PARAMETER(s);}
static void Op182Unlock(OP182_CONTEXT*c){WdfWaitLockRelease(c->Lock);}
static int Identity(OP182_CONTEXT*c)
{
 UCHAR dsdt[sizeof(ClnExpectedDsdt)];ULONG got=0;RTL_OSVERSIONINFOW v={0};
 c->Data.KernelBuild=0;c->Data.Cpus=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);c->Data.Irql=KeGetCurrentIrql();v.dwOSVersionInfoSize=sizeof(v);
 if(NT_SUCCESS(RtlGetVersion(&v)))c->Data.KernelBuild=v.dwBuildNumber;
 NTSTATUS s=AuxKlibGetSystemFirmwareTable(0x41435049,0x54445344,dsdt,sizeof(dsdt),&got);
 c->Data.FirmwareMatch=NT_SUCCESS(s)&&got==sizeof(dsdt)&&RtlCompareMemory(dsdt,ClnExpectedDsdt,sizeof(dsdt))==sizeof(dsdt);
 return c->Data.Cpus==8&&c->Data.Irql==PASSIVE_LEVEL&&c->Data.KernelBuild==26100&&c->Data.FirmwareMatch;
}
static int NoManagedRam(void)
{
 PPHYSICAL_MEMORY_RANGE ranges=MmGetPhysicalMemoryRangesEx2(NULL,0);int valid=0;if(!ranges)return 0;
 for(unsigned i=0;i<512;i++){
  uint64_t a=(uint64_t)ranges[i].BaseAddress.QuadPart,n=(uint64_t)ranges[i].NumberOfBytes.QuadPart;
  if(!n){valid=1;break;}if(n>UINT64_MAX-a)break;
  for(unsigned j=0;j<OP182_RESOURCE_COUNT;j++)if(a<OP182Expected[j].Base+OP182Expected[j].Bytes&&OP182Expected[j].Base<a+n)goto done;
 }
 done:ExFreePool(ranges);return valid;
}
static void Unmap(OP182_CONTEXT*c)
{
 c->Data.ProducerQualified=0;c->Data.D0Active=0;c->Data.Prepared=0;
 for(unsigned n=OP182_RESOURCE_COUNT;n;n--)if(c->Maps[n-1]){
  MmUnmapIoSpace(c->Maps[n-1],OP182Expected[n-1].Bytes);c->Maps[n-1]=NULL;c->Data.UnmapCalls++;c->Data.MapCount--;
 }
}
static uint32_t Convert(WDFCMRESLIST list,OP182_RESOURCE*out)
{
 if(WdfCmResourceListGetCount(list)!=OP182_RESOURCE_COUNT)return 10;
 for(unsigned i=0;i<OP182_RESOURCE_COUNT;i++){
  PCM_PARTIAL_RESOURCE_DESCRIPTOR d=WdfCmResourceListGetDescriptor(list,i);
  if(!d||d->Type!=CmResourceTypeMemory)return 11;
  if(d->Flags&~CM_RESOURCE_MEMORY_READ_ONLY)return 12;
  out[i]=(OP182_RESOURCE){(uint64_t)d->u.Memory.Start.QuadPart,d->u.Memory.Length,
   !(d->Flags&CM_RESOURCE_MEMORY_READ_ONLY),0,d->ShareDisposition};
 }
 return 0;
}
NTSTATUS Op182Prepare(WDFDEVICE device,WDFCMRESLIST raw,WDFCMRESLIST translated)
{
 OP182_CONTEXT*c=Op182Context(device);OP182_RESOURCE r[OP182_RESOURCE_COUNT],t[OP182_RESOURCE_COUNT];NTSTATUS status=STATUS_DEVICE_CONFIGURATION_ERROR;Op182Lock(c);
 if(c->Data.MapCount||c->Data.Prepared){status=STATUS_INVALID_DEVICE_STATE;goto done;}
 if(c->Data.MapCalls>UINT64_MAX-OP182_RESOURCE_COUNT||c->Data.UnmapCalls>UINT64_MAX-OP182_RESOURCE_COUNT){status=STATUS_INTEGER_OVERFLOW;goto done;}
 if(c->Data.PrepareEpoch==UINT64_MAX){status=STATUS_INTEGER_OVERFLOW;goto done;}c->Data.PrepareEpoch++;
 c->Data.ValidationCode=0;
 if(!Identity(c)){c->Data.ValidationCode=20;goto done;}
 c->Data.ValidationCode=Convert(raw,r);if(c->Data.ValidationCode)goto done;
 c->Data.ValidationCode=Convert(translated,t);if(c->Data.ValidationCode)goto done;
 c->Data.ValidationCode=Op182Validate(r,t,OP182_RESOURCE_COUNT);if(c->Data.ValidationCode)goto done;
 if(!NoManagedRam()){c->Data.ValidationCode=21;goto done;}
 for(unsigned i=0;i<OP182_RESOURCE_COUNT;i++){
  PHYSICAL_ADDRESS a;a.QuadPart=(LONGLONG)OP182Expected[i].Base;
  ULONG protection=(OP182Expected[i].Write?PAGE_READWRITE:PAGE_READONLY)|(OP182Expected[i].Cache?0:PAGE_NOCACHE);
  c->Data.MapCalls++;c->Maps[i]=MmMapIoSpaceEx(a,OP182Expected[i].Bytes,protection);
  if(!c->Maps[i]){c->Data.ValidationCode=22;status=STATUS_INSUFFICIENT_RESOURCES;Unmap(c);goto done;}c->Data.MapCount++;
 }
 c->Data.Prepared=1;status=STATUS_SUCCESS;
 done:c->Data.LastStatus=(ULONG)status;Op182Unlock(c);return status;
}
NTSTATUS Op182Release(WDFDEVICE device,WDFCMRESLIST resources)
{
 UNREFERENCED_PARAMETER(resources);OP182_CONTEXT*c=Op182Context(device);Op182Lock(c);ULONG before=c->Data.MapCount;Unmap(c);if(c->Data.ReleaseCalls!=UINT64_MAX)c->Data.ReleaseCalls++;
 DbgPrintEx(DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL,"G182 release maps_before=%lu maps_after=%lu map_calls=%I64u unmap_calls=%I64u releases=%I64u prepared=%lu producer=%lu\n",before,c->Data.MapCount,c->Data.MapCalls,c->Data.UnmapCalls,c->Data.ReleaseCalls,c->Data.Prepared,c->Data.ProducerQualified);
 Op182Unlock(c);return STATUS_SUCCESS;
}
NTSTATUS Op182D0Entry(WDFDEVICE device,WDF_POWER_DEVICE_STATE previous)
{
 UNREFERENCED_PARAMETER(previous);OP182_CONTEXT*c=Op182Context(device);NTSTATUS s=STATUS_DEVICE_NOT_READY;Op182Lock(c);
 if(c->Data.Prepared&&c->Data.MapCount==OP182_RESOURCE_COUNT&&c->Data.D0Epoch!=UINT64_MAX){c->Data.D0Epoch++;c->Data.D0Active=1;s=STATUS_SUCCESS;}
 /* Future producer admission must independently qualify power/bus readiness.
  * This resource-only probe never marks battery ownership/semantics ready. */
 c->Data.ProducerQualified=0;c->Data.LastStatus=(ULONG)s;Op182Unlock(c);return s;
}
NTSTATUS Op182D0Exit(WDFDEVICE device,WDF_POWER_DEVICE_STATE next)
{
 UNREFERENCED_PARAMETER(next);OP182_CONTEXT*c=Op182Context(device);Op182Lock(c);c->Data.ProducerQualified=0;c->Data.D0Active=0;Op182Unlock(c);return STATUS_SUCCESS;
}
VOID Op182Control(WDFQUEUE queue,WDFREQUEST request,size_t outBytes,size_t inBytes,ULONG code)
{
 OP182_REQUEST*input,in;OP182_STATUS_DATA*out;NTSTATUS s;ULONG_PTR bytes=0;
 if(code!=OP182_STATUS){s=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inBytes!=sizeof(in)){s=STATUS_INVALID_PARAMETER;goto done;}
 s=WdfRequestRetrieveInputBuffer(request,sizeof(in),(PVOID*)&input,NULL);if(!NT_SUCCESS(s))goto done;in=*input;
 if(in.Size!=sizeof(in)||in.Version!=1||in.Magic!=OP182_MAGIC||in.Nonce||in.Count||in.Reserved){s=STATUS_INVALID_PARAMETER;goto done;}
 if(outBytes!=sizeof(*out)){s=STATUS_BUFFER_TOO_SMALL;goto done;}
 s=WdfRequestRetrieveOutputBuffer(request,sizeof(*out),(PVOID*)&out,NULL);if(!NT_SUCCESS(s))goto done;
 OP182_CONTEXT*c=Op182Context(WdfIoQueueGetDevice(queue));Op182Lock(c);c->Data.Now100ns=KeQueryInterruptTime();c->Data.Irql=KeGetCurrentIrql();RtlCopyMemory(out,&c->Data,sizeof(*out));Op182Unlock(c);s=STATUS_SUCCESS;bytes=sizeof(*out);
 done:WdfRequestCompleteWithInformation(request,s,bytes);
}
VOID Op182FileCreate(WDFDEVICE device,WDFREQUEST request,WDFFILEOBJECT file)
{
 UNREFERENCED_PARAMETER(device);PUNICODE_STRING name=WdfFileObjectGetFileName(file);WdfRequestComplete(request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);
}
NTSTATUS Op182Add(WDFDRIVER driver,PWDFDEVICE_INIT init)
{
 UNREFERENCED_PARAMETER(driver);WDFDEVICE device;WDF_OBJECT_ATTRIBUTES attr;WDF_PNPPOWER_EVENT_CALLBACKS pnp;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG file;NTSTATUS s;
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnp);pnp.EvtDevicePrepareHardware=Op182Prepare;pnp.EvtDeviceReleaseHardware=Op182Release;pnp.EvtDeviceD0Entry=Op182D0Entry;pnp.EvtDeviceD0Exit=Op182D0Exit;WdfDeviceInitSetPnpPowerEventCallbacks(init,&pnp);
 WDF_FILEOBJECT_CONFIG_INIT(&file,Op182FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);WdfDeviceInitSetFileObjectConfig(init,&file,WDF_NO_OBJECT_ATTRIBUTES);
 WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attr,OP182_CONTEXT);attr.ExecutionLevel=WdfExecutionLevelPassive;attr.SynchronizationScope=WdfSynchronizationScopeNone;
 s=WdfDeviceCreate(&init,&attr,&device);if(!NT_SUCCESS(s))return s;
 OP182_CONTEXT*c=Op182Context(device);c->Data.Size=sizeof(c->Data);c->Data.Version=1;c->Data.Magic=OP182_MAGIC;
 WDF_OBJECT_ATTRIBUTES_INIT(&attr);attr.ParentObject=device;s=WdfWaitLockCreate(&attr,&c->Lock);if(!NT_SUCCESS(s))return s;
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfFalse;queue.EvtIoDeviceControl=Op182Control;s=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(s))return s;
 return WdfDeviceCreateDeviceInterface(device,&Interface,NULL);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING path)
{
 WDF_DRIVER_CONFIG config;WDF_DRIVER_CONFIG_INIT(&config,Op182Add);NTSTATUS s=AuxKlibInitialize();if(!NT_SUCCESS(s))return s;return WdfDriverCreate(object,path,WDF_NO_OBJECT_ATTRIBUTES,&config,WDF_NO_HANDLE);
}
