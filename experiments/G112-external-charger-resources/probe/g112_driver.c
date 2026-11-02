/* SPDX-License-Identifier: MIT
 * Demand-loaded, one-shot, read-only battery-controller resource diagnostic.
 * Driver load and STATUS/RESULT never map hardware. No hardware writes or bus transactions.
 */
#include <ntifs.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g112_binding.h"
#include "g112_core.h"
#include "g112_protocol.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G112Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G112Control;
EVT_WDF_DEVICE_FILE_CREATE G112FileCreate;
static volatile LONG G112Attempts,G112Ready,G112Fault,G112Maps;
static volatile LONG64 G112Sequence;
static G112_CAPTURE*G112Frozen;
static int FullWindows(void)
{
 UNICODE_STRING name;OBJECT_ATTRIBUTES attributes;HANDLE key;NTSTATUS status;ULONG bytes=0;
 union {KEY_VALUE_PARTIAL_INFORMATION Info;UCHAR Storage[128];}value;
 static const WCHAR expected[]=L"C:\\Windows";
 if(KeGetCurrentIrql()!=PASSIVE_LEVEL)return 0;
 RtlInitUnicodeString(&name,L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\MiniNT");InitializeObjectAttributes(&attributes,&name,OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,NULL,NULL);
 status=ZwOpenKey(&key,KEY_QUERY_VALUE,&attributes);if(NT_SUCCESS(status)){ZwClose(key);return 0;}if(status!=STATUS_OBJECT_NAME_NOT_FOUND&&status!=STATUS_OBJECT_PATH_NOT_FOUND)return 0;
 RtlInitUnicodeString(&name,L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");InitializeObjectAttributes(&attributes,&name,OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,NULL,NULL);
 status=ZwOpenKey(&key,KEY_QUERY_VALUE,&attributes);if(!NT_SUCCESS(status))return 0;
 RtlInitUnicodeString(&name,L"SystemRoot");status=ZwQueryValueKey(key,&name,KeyValuePartialInformation,&value,sizeof(value),&bytes);ZwClose(key);
 return NT_SUCCESS(status)&&bytes<=sizeof(value)&&value.Info.Type==REG_SZ&&(value.Info.DataLength==sizeof(expected)||value.Info.DataLength==sizeof(expected)-sizeof(WCHAR))&&bytes>=FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION,Data)+value.Info.DataLength&&RtlCompareMemory(value.Info.Data,expected,value.Info.DataLength)==value.Info.DataLength;
}
static void Status(G112_STATUS*s)
{
 UCHAR dsdt[sizeof(G112ExpectedDsdt)];ULONG bytes=0;NTSTATUS status;RTL_OSVERSIONINFOW version;LARGE_INTEGER freq;
 RtlZeroMemory(s,sizeof(*s));s->Size=sizeof(*s);s->Version=G112_ABI;s->Magic=G112_MAGIC;s->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);s->Irql=KeGetCurrentIrql();s->MapCalls=(ULONG)InterlockedCompareExchange(&G112Maps,0,0);s->Attempts=(ULONG)InterlockedCompareExchange(&G112Attempts,0,0);s->Ready=(ULONG)InterlockedCompareExchange(&G112Ready,0,0);s->Fault=(ULONG)InterlockedCompareExchange(&G112Fault,0,0);s->InterruptTime=KeQueryInterruptTime();s->Sequence=(ULONGLONG)InterlockedIncrement64(&G112Sequence);KeQueryPerformanceCounter(&freq);s->Frequency=(ULONGLONG)freq.QuadPart;
 if(s->Irql!=PASSIVE_LEVEL){s->FirmwareStatus=(ULONG)STATUS_INVALID_DEVICE_STATE;return;}
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);if(NT_SUCCESS(RtlGetVersion(&version)))s->KernelBuild=version.dwBuildNumber;
 status=AuxKlibGetSystemFirmwareTable(0x41435049,0x54445344,dsdt,sizeof(dsdt),&bytes);s->FirmwareStatus=(ULONG)status;s->FirmwareBytes=bytes;if(NT_SUCCESS(status)&&bytes==sizeof(dsdt)&&RtlCompareMemory(dsdt,G112ExpectedDsdt,sizeof(dsdt))==sizeof(dsdt))s->FirmwareMatch=1;
}

/* Only fixed read-only pages; serial-engine pages are mapped lazily after
 * independent native clock checks. No bus data/FIFO/clear register is allowed. */
static const ULONG Pages[]={0x152000,0x11e000,0x117000,0x123000,0xf100000,0xf101000,0xf106000,0xf107000,0x880000,0x8c0000,0x994000,0x9c0000};
typedef struct {PVOID Maps[12];WDFREQUEST Request;ULONG Reads,MapCalls,Guard;ULONGLONG Frequency;}G112_CONTEXT;
static int NoManagedRam(void){
 PPHYSICAL_MEMORY_RANGE ranges=MmGetPhysicalMemoryRangesEx2(NULL,0);int valid=0;if(!ranges)return 0;
 for(ULONG i=0;i<512;i++){ULONGLONG a=(ULONGLONG)ranges[i].BaseAddress.QuadPart,n=(ULONGLONG)ranges[i].NumberOfBytes.QuadPart;if(!n){valid=1;break;}if(n>MAXULONGLONG-a)break;for(ULONG j=0;j<12;j++)if(a<(ULONGLONG)Pages[j]+4096&&Pages[j]<a+n)goto done;}
 done:ExFreePool(ranges);return valid;
}
static PULONG Address(G112_CONTEXT*c,ULONG at)
{
 if(!G112ReadAllowed(at))return NULL;
 for(ULONG i=0;i<12;i++)if(at>=Pages[i]&&at-Pages[i]<=0xffc){
  if(!c->Maps[i]){PHYSICAL_ADDRESS a;a.QuadPart=Pages[i];c->MapCalls++;InterlockedIncrement(&G112Maps);c->Maps[i]=MmMapIoSpaceEx(a,0x1000,PAGE_READONLY|PAGE_NOCACHE);}
  return c->Maps[i]?(PULONG)((PUCHAR)c->Maps[i]+at-Pages[i]):NULL;
 }
 return NULL;
}
static int SafeRead(G112_CONTEXT*c,uint32_t at,uint32_t*v)
{
 PULONG p;if(c->Reads>=2048||WdfRequestIsCanceled(c->Request))return 0;
 p=Address(c,at);if(!p)return 0;c->Reads++;*v=READ_REGISTER_ULONG(p);return 1;
}
static int NativeClocks(G112_CONTEXT*c,unsigned i)
{
 uint32_t v[8];const G112_CONTROLLER*k=G112Controllers+i;
 for(unsigned j=0;j<3;j++)if(!SafeRead(c,k->Clocks[j].Vote,v+2*j)||!SafeRead(c,k->Clocks[j].Cbcr,v+2*j+1))return 0;
 return SafeRead(c,k->Root,v+6)&&SafeRead(c,k->Root+4,v+7)&&G112ClockUsable(i,v);
}
static int NativeRead(void*x,uint32_t at,uint32_t*v)
{
 G112_CONTEXT*c=x;int i;if(!G112ReadAllowed(at)){c->Guard=1;return 0;}
 i=G112Peripheral(at);if(i>=0&&!NativeClocks(c,(unsigned)i)){c->Guard=2;return 0;}
 return SafeRead(c,at,v);
}
static int Available(void*x){return !WdfRequestIsCanceled(((G112_CONTEXT*)x)->Request);}
static uint64_t NowUs(void*x){G112_CONTEXT*c=x;LARGE_INTEGER q=KeQueryPerformanceCounter(NULL);ULONGLONG u=(ULONGLONG)q.QuadPart;if(q.QuadPart<0||!c->Frequency)return 0;return u/c->Frequency*1000000+(u%c->Frequency)*1000000/c->Frequency;}
static void Capture(G112_CAPTURE*out,WDFREQUEST request,ULONGLONG nonce)
{
 G112_CONTEXT c;G112_IO io;Status(&out->Status);out->Nonce=nonce;out->Result.Size=sizeof(out->Result);RtlZeroMemory(&c,sizeof(c));c.Request=request;c.Frequency=out->Status.Frequency;
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26300||out->Status.Processors!=8||out->Status.Irql!=PASSIVE_LEVEL||!c.Frequency||c.Frequency>1000000000ULL||!FullWindows()){out->Result.Code=1004;goto done;}
 if(!NoManagedRam()){out->Result.Code=1005;goto done;}
 io.Context=&c;io.Read=NativeRead;io.Available=Available;io.NowUs=NowUs;G112Probe(&io,&out->Result);
 done:for(ULONG i=12;i;i--)if(c.Maps[i-1])MmUnmapIoSpace(c.Maps[i-1],0x1000);
 out->NativeReads=c.Reads;out->MapCalls=c.MapCalls;out->Guard=c.Guard;if(out->Result.Code)InterlockedExchange(&G112Fault,1);
 InterlockedExchange(&G112Ready,1);Status(&out->Status);
}
VOID G112Control(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 G112_REQUEST*input,in;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;UNREFERENCED_PARAMETER(queue);
 if(code!=G112_IOCTL_STATUS&&code!=G112_IOCTL_READ&&code!=G112_IOCTL_RESULT){status=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inputBytes!=sizeof(in)){status=STATUS_INVALID_PARAMETER;goto done;}status=WdfRequestRetrieveInputBuffer(request,sizeof(in),(PVOID*)&input,NULL);if(!NT_SUCCESS(status))goto done;in=*input;
 if(in.Size!=sizeof(in)||in.Version!=G112_ABI||in.Magic!=G112_MAGIC||in.Reserved||in.Count||(code==G112_IOCTL_STATUS?in.Nonce||in.Count:!in.Nonce)){status=STATUS_INVALID_PARAMETER;goto done;}
 needed=code==G112_IOCTL_STATUS?sizeof(G112_STATUS):sizeof(G112_CAPTURE);if(outputBytes!=needed){status=STATUS_BUFFER_TOO_SMALL;goto done;}status=WdfRequestRetrieveOutputBuffer(request,needed,&output,NULL);if(!NT_SUCCESS(status))goto done;
 if(code==G112_IOCTL_STATUS)Status(output);
 else if(code==G112_IOCTL_RESULT){if(!InterlockedCompareExchange(&G112Ready,0,0)||G112Frozen->Nonce!=in.Nonce){status=STATUS_NOT_FOUND;goto done;}RtlCopyMemory(output,G112Frozen,sizeof(*G112Frozen));}
 else{if(InterlockedCompareExchange(&G112Attempts,1,0)){status=STATUS_QUOTA_EXCEEDED;goto done;}RtlZeroMemory(G112Frozen,sizeof(*G112Frozen));Capture(G112Frozen,request,in.Nonce);RtlCopyMemory(output,G112Frozen,sizeof(*G112Frozen));}
 status=STATUS_SUCCESS;information=needed;
 done:WdfRequestCompleteWithInformation(request,status,information);
}
VOID G112FileCreate(WDFDEVICE device,WDFREQUEST request,WDFFILEOBJECT file){PUNICODE_STRING name=WdfFileObjectGetFileName(file);UNREFERENCED_PARAMETER(device);WdfRequestComplete(request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);}
VOID G112Unload(WDFDRIVER driver){UNREFERENCED_PARAMETER(driver);if(G112Frozen){ExFreePoolWithTag(G112Frozen,'01GO');G112Frozen=NULL;}}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING path)
{
 WDF_DRIVER_CONFIG config;WDFDRIVER driver;PWDFDEVICE_INIT init=NULL;WDFDEVICE device;WDF_OBJECT_ATTRIBUTES attr;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG file;NTSTATUS status;
 DECLARE_CONST_UNICODE_STRING(sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");DECLARE_CONST_UNICODE_STRING(name,L"\\Device\\OpenG112");DECLARE_CONST_UNICODE_STRING(link,L"\\DosDevices\\OpenG112");
 WDF_DRIVER_CONFIG_INIT(&config,WDF_NO_EVENT_CALLBACK);config.DriverInitFlags|=WdfDriverInitNonPnpDriver;config.EvtDriverUnload=G112Unload;status=WdfDriverCreate(object,path,WDF_NO_OBJECT_ATTRIBUTES,&config,&driver);if(!NT_SUCCESS(status))return status;status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 G112Frozen=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*G112Frozen),'01GO');if(!G112Frozen)return STATUS_INSUFFICIENT_RESOURCES;
 init=WdfControlDeviceInitAllocate(driver,&sddl);if(!init){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&file,G112FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);WdfDeviceInitSetFileObjectConfig(init,&file,WDF_NO_OBJECT_ATTRIBUTES);status=WdfDeviceInitAssignName(init,&name);if(!NT_SUCCESS(status))goto done;WDF_OBJECT_ATTRIBUTES_INIT(&attr);attr.ExecutionLevel=WdfExecutionLevelPassive;attr.SynchronizationScope=WdfSynchronizationScopeDevice;status=WdfDeviceCreate(&init,&attr,&device);if(!NT_SUCCESS(status))goto done;
 status=WdfDeviceCreateSymbolicLink(device,&link);if(!NT_SUCCESS(status))goto done;WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfFalse;queue.EvtIoDeviceControl=G112Control;status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))goto done;WdfControlFinishInitializing(device);
 done:if(init)WdfDeviceInitFree(init);if(!NT_SUCCESS(status)&&G112Frozen){ExFreePoolWithTag(G112Frozen,'01GO');G112Frozen=NULL;}return status;
}
