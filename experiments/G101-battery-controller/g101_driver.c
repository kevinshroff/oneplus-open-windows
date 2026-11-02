/* SPDX-License-Identifier: MIT
 * Demand-loaded, one-shot, read-only battery-controller resource diagnostic.
 * Driver load and STATUS/RESULT never map hardware. No hardware writes or bus transactions.
 */
#include <ntifs.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g101_binding.h"
#include "g101_core.h"
#include "g101_protocol.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G101Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G101Control;
EVT_WDF_DEVICE_FILE_CREATE G101FileCreate;
static volatile LONG G101Attempts,G101Ready,G101Fault,G101Maps;
static volatile LONG64 G101Sequence;
static G101_CAPTURE*G101Frozen;
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
static void Status(G101_STATUS*s)
{
 UCHAR dsdt[sizeof(G101ExpectedDsdt)];ULONG bytes=0;NTSTATUS status;RTL_OSVERSIONINFOW version;LARGE_INTEGER freq;
 RtlZeroMemory(s,sizeof(*s));s->Size=sizeof(*s);s->Version=G101_ABI;s->Magic=G101_MAGIC;s->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);s->Irql=KeGetCurrentIrql();s->MapCalls=(ULONG)InterlockedCompareExchange(&G101Maps,0,0);s->Attempts=(ULONG)InterlockedCompareExchange(&G101Attempts,0,0);s->Ready=(ULONG)InterlockedCompareExchange(&G101Ready,0,0);s->Fault=(ULONG)InterlockedCompareExchange(&G101Fault,0,0);s->InterruptTime=KeQueryInterruptTime();s->Sequence=(ULONGLONG)InterlockedIncrement64(&G101Sequence);KeQueryPerformanceCounter(&freq);s->Frequency=(ULONGLONG)freq.QuadPart;
 if(s->Irql!=PASSIVE_LEVEL){s->FirmwareStatus=(ULONG)STATUS_INVALID_DEVICE_STATE;return;}
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);if(NT_SUCCESS(RtlGetVersion(&version)))s->KernelBuild=version.dwBuildNumber;
 status=AuxKlibGetSystemFirmwareTable(0x41435049,0x54445344,dsdt,sizeof(dsdt),&bytes);s->FirmwareStatus=(ULONG)status;s->FirmwareBytes=bytes;if(NT_SUCCESS(status)&&bytes==sizeof(dsdt)&&RtlCompareMemory(dsdt,G101ExpectedDsdt,sizeof(dsdt))==sizeof(dsdt))s->FirmwareMatch=1;
}

/* Only fixed read-only pages; serial-engine pages are mapped lazily after
 * independent native clock checks. No bus data/FIFO/clear register is allowed. */
static const ULONG Pages[]={0x152000,0x11e000,0x117000,0x123000,0xf100000,0xf101000,0xf116000,0xf117000,0x880000,0x8c0000,0x98c000,0x9c0000};
typedef struct {PVOID Maps[12];WDFREQUEST Request;ULONG Reads,MapCalls,Guard;ULONGLONG Frequency;}G101_CONTEXT;
static PULONG Address(G101_CONTEXT*c,ULONG at)
{
 if(!G101ReadAllowed(at))return NULL;
 for(ULONG i=0;i<12;i++)if(at>=Pages[i]&&at-Pages[i]<=0xffc){
  if(!c->Maps[i]){PHYSICAL_ADDRESS a;a.QuadPart=Pages[i];c->MapCalls++;InterlockedIncrement(&G101Maps);c->Maps[i]=MmMapIoSpaceEx(a,0x1000,PAGE_READONLY|PAGE_NOCACHE);}
  return c->Maps[i]?(PULONG)((PUCHAR)c->Maps[i]+at-Pages[i]):NULL;
 }
 return NULL;
}
static int SafeRead(G101_CONTEXT*c,uint32_t at,uint32_t*v)
{
 PULONG p;if(c->Reads>=2048||WdfRequestIsCanceled(c->Request))return 0;
 p=Address(c,at);if(!p)return 0;c->Reads++;*v=READ_REGISTER_ULONG(p);return 1;
}
static int NativeClocks(G101_CONTEXT*c,unsigned i)
{
 uint32_t v[8];const G101_CONTROLLER*k=G101Controllers+i;
 for(unsigned j=0;j<3;j++)if(!SafeRead(c,k->Clocks[j].Vote,v+2*j)||!SafeRead(c,k->Clocks[j].Cbcr,v+2*j+1))return 0;
 return SafeRead(c,k->Root,v+6)&&SafeRead(c,k->Root+4,v+7)&&G101ClockUsable(i,v);
}
static int NativeRead(void*x,uint32_t at,uint32_t*v)
{
 G101_CONTEXT*c=x;int i;if(!G101ReadAllowed(at)){c->Guard=1;return 0;}
 i=G101Peripheral(at);if(i>=0&&!NativeClocks(c,(unsigned)i)){c->Guard=2;return 0;}
 return SafeRead(c,at,v);
}
static int Available(void*x){return !WdfRequestIsCanceled(((G101_CONTEXT*)x)->Request);}
static uint64_t NowUs(void*x){G101_CONTEXT*c=x;LARGE_INTEGER q=KeQueryPerformanceCounter(NULL);ULONGLONG u=(ULONGLONG)q.QuadPart;if(q.QuadPart<0||!c->Frequency)return 0;return u/c->Frequency*1000000+(u%c->Frequency)*1000000/c->Frequency;}
static void Capture(G101_CAPTURE*out,WDFREQUEST request,ULONGLONG nonce)
{
 G101_CONTEXT c;G101_IO io;Status(&out->Status);out->Nonce=nonce;out->Result.Size=sizeof(out->Result);RtlZeroMemory(&c,sizeof(c));c.Request=request;c.Frequency=out->Status.Frequency;
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26300||out->Status.Processors!=8||out->Status.Irql!=PASSIVE_LEVEL||!c.Frequency||c.Frequency>1000000000ULL||!FullWindows()){out->Result.Code=1004;goto done;}
 io.Context=&c;io.Read=NativeRead;io.Available=Available;io.NowUs=NowUs;G101Probe(&io,&out->Result);
 done:for(ULONG i=12;i;i--)if(c.Maps[i-1])MmUnmapIoSpace(c.Maps[i-1],0x1000);
 out->NativeReads=c.Reads;out->MapCalls=c.MapCalls;out->Guard=c.Guard;if(out->Result.Code)InterlockedExchange(&G101Fault,1);
 InterlockedExchange(&G101Ready,1);Status(&out->Status);
}
VOID G101Control(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 G101_REQUEST*input,in;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;UNREFERENCED_PARAMETER(queue);
 if(code!=G101_IOCTL_STATUS&&code!=G101_IOCTL_READ&&code!=G101_IOCTL_RESULT){status=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inputBytes!=sizeof(in)){status=STATUS_INVALID_PARAMETER;goto done;}status=WdfRequestRetrieveInputBuffer(request,sizeof(in),(PVOID*)&input,NULL);if(!NT_SUCCESS(status))goto done;in=*input;
 if(in.Size!=sizeof(in)||in.Version!=G101_ABI||in.Magic!=G101_MAGIC||in.Reserved||in.Count||(code==G101_IOCTL_STATUS?in.Nonce||in.Count:!in.Nonce)){status=STATUS_INVALID_PARAMETER;goto done;}
 needed=code==G101_IOCTL_STATUS?sizeof(G101_STATUS):sizeof(G101_CAPTURE);if(outputBytes!=needed){status=STATUS_BUFFER_TOO_SMALL;goto done;}status=WdfRequestRetrieveOutputBuffer(request,needed,&output,NULL);if(!NT_SUCCESS(status))goto done;
 if(code==G101_IOCTL_STATUS)Status(output);
 else if(code==G101_IOCTL_RESULT){if(!InterlockedCompareExchange(&G101Ready,0,0)||G101Frozen->Nonce!=in.Nonce){status=STATUS_NOT_FOUND;goto done;}RtlCopyMemory(output,G101Frozen,sizeof(*G101Frozen));}
 else{if(InterlockedCompareExchange(&G101Attempts,1,0)){status=STATUS_QUOTA_EXCEEDED;goto done;}RtlZeroMemory(G101Frozen,sizeof(*G101Frozen));Capture(G101Frozen,request,in.Nonce);RtlCopyMemory(output,G101Frozen,sizeof(*G101Frozen));}
 status=STATUS_SUCCESS;information=needed;
 done:WdfRequestCompleteWithInformation(request,status,information);
}
VOID G101FileCreate(WDFDEVICE device,WDFREQUEST request,WDFFILEOBJECT file){PUNICODE_STRING name=WdfFileObjectGetFileName(file);UNREFERENCED_PARAMETER(device);WdfRequestComplete(request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);}
VOID G101Unload(WDFDRIVER driver){UNREFERENCED_PARAMETER(driver);if(G101Frozen){ExFreePoolWithTag(G101Frozen,'01GO');G101Frozen=NULL;}}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING path)
{
 WDF_DRIVER_CONFIG config;WDFDRIVER driver;PWDFDEVICE_INIT init=NULL;WDFDEVICE device;WDF_OBJECT_ATTRIBUTES attr;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG file;NTSTATUS status;
 DECLARE_CONST_UNICODE_STRING(sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");DECLARE_CONST_UNICODE_STRING(name,L"\\Device\\OpenG101");DECLARE_CONST_UNICODE_STRING(link,L"\\DosDevices\\OpenG101");
 WDF_DRIVER_CONFIG_INIT(&config,WDF_NO_EVENT_CALLBACK);config.DriverInitFlags|=WdfDriverInitNonPnpDriver;config.EvtDriverUnload=G101Unload;status=WdfDriverCreate(object,path,WDF_NO_OBJECT_ATTRIBUTES,&config,&driver);if(!NT_SUCCESS(status))return status;status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 G101Frozen=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*G101Frozen),'01GO');if(!G101Frozen)return STATUS_INSUFFICIENT_RESOURCES;
 init=WdfControlDeviceInitAllocate(driver,&sddl);if(!init){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&file,G101FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);WdfDeviceInitSetFileObjectConfig(init,&file,WDF_NO_OBJECT_ATTRIBUTES);status=WdfDeviceInitAssignName(init,&name);if(!NT_SUCCESS(status))goto done;WDF_OBJECT_ATTRIBUTES_INIT(&attr);attr.ExecutionLevel=WdfExecutionLevelPassive;attr.SynchronizationScope=WdfSynchronizationScopeDevice;status=WdfDeviceCreate(&init,&attr,&device);if(!NT_SUCCESS(status))goto done;
 status=WdfDeviceCreateSymbolicLink(device,&link);if(!NT_SUCCESS(status))goto done;WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfFalse;queue.EvtIoDeviceControl=G101Control;status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))goto done;WdfControlFinishInitializing(device);
 done:if(init)WdfDeviceInitFree(init);if(!NT_SUCCESS(status)&&G101Frozen){ExFreePoolWithTag(G101Frozen,'01GO');G101Frozen=NULL;}return status;
}
