/* SPDX-License-Identifier: MIT
 * Demand-loaded, one-shot, disjoint PON/GPIO observer READ diagnostic.
 * Driver load and STATUS/RESULT never map hardware. No PMIC writes or policy.
 */
#include <ntifs.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g99_binding.h"
#include "g99_core.h"
#include "g99_protocol.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G99Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G99Control;
EVT_WDF_DEVICE_FILE_CREATE G99FileCreate;
static volatile LONG G99Attempts,G99Ready,G99Fault,G99Maps;
static volatile LONG64 G99Sequence;
static G99_CAPTURE*G99Frozen;
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
static void Status(G99_STATUS*s)
{
 UCHAR dsdt[sizeof(G99ExpectedDsdt)];ULONG bytes=0;NTSTATUS status;RTL_OSVERSIONINFOW version;LARGE_INTEGER freq;
 RtlZeroMemory(s,sizeof(*s));s->Size=sizeof(*s);s->Version=G99_ABI;s->Magic=G99_MAGIC;s->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);s->Irql=KeGetCurrentIrql();s->MapCalls=(ULONG)InterlockedCompareExchange(&G99Maps,0,0);s->Attempts=(ULONG)InterlockedCompareExchange(&G99Attempts,0,0);s->Ready=(ULONG)InterlockedCompareExchange(&G99Ready,0,0);s->Fault=(ULONG)InterlockedCompareExchange(&G99Fault,0,0);s->InterruptTime=KeQueryInterruptTime();s->Sequence=(ULONGLONG)InterlockedIncrement64(&G99Sequence);KeQueryPerformanceCounter(&freq);s->Frequency=(ULONGLONG)freq.QuadPart;
 if(s->Irql!=PASSIVE_LEVEL){s->FirmwareStatus=(ULONG)STATUS_INVALID_DEVICE_STATE;return;}
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);if(NT_SUCCESS(RtlGetVersion(&version)))s->KernelBuild=version.dwBuildNumber;
 status=AuxKlibGetSystemFirmwareTable(0x41435049,0x54445344,dsdt,sizeof(dsdt),&bytes);s->FirmwareStatus=(ULONG)status;s->FirmwareBytes=bytes;if(NT_SUCCESS(status)&&bytes==sizeof(dsdt)&&RtlCompareMemory(dsdt,G99ExpectedDsdt,sizeof(dsdt))==sizeof(dsdt))s->FirmwareMatch=1;
}
static const ULONG Pages[5]={0xc400000,0xc402000,0xc42d000,0xc440000,0xc444000};
typedef struct {PVOID Maps[5];WDFREQUEST Request;ULONG Reads,Writes,Guard;ULONGLONG Frequency;}G99_CONTEXT;
static PULONG Address(G99_CONTEXT*c,ULONG at,int write,ULONG value)
{
 if((at&3)||(write?!G99WriteAllowed(at,value):!G99ReadAllowed(at)))return NULL;
 for(ULONG i=0;i<5;i++)if(c->Maps[i]&&at>=Pages[i]&&at-Pages[i]<=0xffc){if(write&&i<3)return NULL;return(PULONG)((PUCHAR)c->Maps[i]+at-Pages[i]);}return NULL;
}
static int NativeRead(void*x,uint32_t at,uint32_t*v)
{
 G99_CONTEXT*c=x;PULONG p;if(c->Reads>=80000)return 0;p=Address(c,at,0,0);if(!p)return 0;c->Reads++;*v=READ_REGISTER_ULONG(p);return 1;
}
static int NativeWrite(void*x,uint32_t at,uint32_t value)
{
 G99_CONTEXT*c=x;PULONG p;uint32_t map,owner,status,previous;unsigned i;
 if(c->Writes>=G99_MAX_COMMANDS||!G99WriteAllowed(at,value)){c->Guard=1;return 0;}
 if(WdfRequestIsCanceled(c->Request)){c->Guard=4;return 0;}
 for(i=0;i<4;i++)if(at==G99Base(i))break;if(i==4){c->Guard=1;return 0;}
 if(!NativeRead(c,0xc402000+G99Targets[i].Apid*4,&map)||!NativeRead(c,0xc42d000+G99Targets[i].Apid*4,&owner)||map!=G99Targets[i].Map||owner!=G99Targets[i].Owner){c->Guard=2;return 0;}
 if(!NativeRead(c,at+8,&status)||!NativeRead(c,at,&previous)||(!(status&1)&&previous)){c->Guard=3;return 0;}
 p=Address(c,at,1,value);if(!p){c->Guard=1;return 0;}c->Writes++;WRITE_REGISTER_ULONG(p,value);return 1;
}
static void WaitUs(void*x){UNREFERENCED_PARAMETER(x);KeStallExecutionProcessor(1);}
static void WaitInterval(void*x){LARGE_INTEGER wait;UNREFERENCED_PARAMETER(x);wait.QuadPart=-200000;KeDelayExecutionThread(KernelMode,FALSE,&wait);}
static int Available(void*x){return !WdfRequestIsCanceled(((G99_CONTEXT*)x)->Request);}
static uint64_t NowUs(void*x){G99_CONTEXT*c=x;LARGE_INTEGER q=KeQueryPerformanceCounter(NULL);ULONGLONG u=(ULONGLONG)q.QuadPart;if(q.QuadPart<0||!c->Frequency)return 0;return u/c->Frequency*1000000+(u%c->Frequency)*1000000/c->Frequency;}
static void Capture(G99_CAPTURE*out,WDFREQUEST request,ULONGLONG nonce,ULONG count)
{
 G99_CONTEXT c;G99_IO io;Status(&out->Status);out->Nonce=nonce;out->Requested=count;out->Result.Size=sizeof(out->Result);RtlZeroMemory(&c,sizeof(c));c.Request=request;c.Frequency=out->Status.Frequency;
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26300||out->Status.Processors!=8||out->Status.Irql!=PASSIVE_LEVEL||!c.Frequency||c.Frequency>1000000000ULL||!FullWindows()){out->Result.Code=1004;goto done;}
 for(ULONG i=0;i<5;i++){PHYSICAL_ADDRESS a;a.QuadPart=Pages[i];InterlockedIncrement(&G99Maps);c.Maps[i]=MmMapIoSpaceEx(a,0x1000,(i<3?PAGE_READONLY:PAGE_READWRITE)|PAGE_NOCACHE);if(!c.Maps[i]){out->Result.Code=1005;goto done;}}
 io.Context=&c;io.Read=NativeRead;io.Write=NativeWrite;io.WaitUs=WaitUs;io.WaitInterval=WaitInterval;io.Available=Available;io.NowUs=NowUs;G99Sample(&io,count,&out->Result);
 done:for(ULONG i=5;i;i--)if(c.Maps[i-1])MmUnmapIoSpace(c.Maps[i-1],0x1000);
 out->NativeReads=c.Reads;out->NativeWrites=c.Writes;out->NativeGuard=c.Guard;if(out->Result.Code)InterlockedExchange(&G99Fault,1);
 InterlockedExchange(&G99Ready,1);Status(&out->Status);
}
VOID G99Control(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 G99_REQUEST*input,in;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;UNREFERENCED_PARAMETER(queue);
 if(code!=G99_IOCTL_STATUS&&code!=G99_IOCTL_SAMPLE&&code!=G99_IOCTL_RESULT){status=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inputBytes!=sizeof(in)){status=STATUS_INVALID_PARAMETER;goto done;}status=WdfRequestRetrieveInputBuffer(request,sizeof(in),(PVOID*)&input,NULL);if(!NT_SUCCESS(status))goto done;in=*input;
 if(in.Size!=sizeof(in)||in.Version!=G99_ABI||in.Magic!=G99_MAGIC||in.Reserved||(code==G99_IOCTL_STATUS?in.Nonce||in.Count:!in.Nonce)||(code==G99_IOCTL_RESULT&&in.Count)||(code==G99_IOCTL_SAMPLE&&(!in.Count||in.Count>G99_MAX_SAMPLES))){status=STATUS_INVALID_PARAMETER;goto done;}
 needed=code==G99_IOCTL_STATUS?sizeof(G99_STATUS):sizeof(G99_CAPTURE);if(outputBytes!=needed){status=STATUS_BUFFER_TOO_SMALL;goto done;}status=WdfRequestRetrieveOutputBuffer(request,needed,&output,NULL);if(!NT_SUCCESS(status))goto done;
 if(code==G99_IOCTL_STATUS)Status(output);
 else if(code==G99_IOCTL_RESULT){if(!InterlockedCompareExchange(&G99Ready,0,0)||G99Frozen->Nonce!=in.Nonce){status=STATUS_NOT_FOUND;goto done;}RtlCopyMemory(output,G99Frozen,sizeof(*G99Frozen));}
 else{if(InterlockedCompareExchange(&G99Attempts,1,0)){status=STATUS_QUOTA_EXCEEDED;goto done;}RtlZeroMemory(G99Frozen,sizeof(*G99Frozen));Capture(G99Frozen,request,in.Nonce,in.Count);RtlCopyMemory(output,G99Frozen,sizeof(*G99Frozen));}
 status=STATUS_SUCCESS;information=needed;
 done:WdfRequestCompleteWithInformation(request,status,information);
}
VOID G99FileCreate(WDFDEVICE device,WDFREQUEST request,WDFFILEOBJECT file){PUNICODE_STRING name=WdfFileObjectGetFileName(file);UNREFERENCED_PARAMETER(device);WdfRequestComplete(request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);}
VOID G99Unload(WDFDRIVER driver){UNREFERENCED_PARAMETER(driver);if(G99Frozen){ExFreePoolWithTag(G99Frozen,'99GO');G99Frozen=NULL;}}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING path)
{
 WDF_DRIVER_CONFIG config;WDFDRIVER driver;PWDFDEVICE_INIT init=NULL;WDFDEVICE device;WDF_OBJECT_ATTRIBUTES attr;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG file;NTSTATUS status;
 DECLARE_CONST_UNICODE_STRING(sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");DECLARE_CONST_UNICODE_STRING(name,L"\\Device\\OpenG99");DECLARE_CONST_UNICODE_STRING(link,L"\\DosDevices\\OpenG99");
 WDF_DRIVER_CONFIG_INIT(&config,WDF_NO_EVENT_CALLBACK);config.DriverInitFlags|=WdfDriverInitNonPnpDriver;config.EvtDriverUnload=G99Unload;status=WdfDriverCreate(object,path,WDF_NO_OBJECT_ATTRIBUTES,&config,&driver);if(!NT_SUCCESS(status))return status;status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 G99Frozen=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*G99Frozen),'99GO');if(!G99Frozen)return STATUS_INSUFFICIENT_RESOURCES;
 init=WdfControlDeviceInitAllocate(driver,&sddl);if(!init){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&file,G99FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);WdfDeviceInitSetFileObjectConfig(init,&file,WDF_NO_OBJECT_ATTRIBUTES);status=WdfDeviceInitAssignName(init,&name);if(!NT_SUCCESS(status))goto done;WDF_OBJECT_ATTRIBUTES_INIT(&attr);attr.ExecutionLevel=WdfExecutionLevelPassive;attr.SynchronizationScope=WdfSynchronizationScopeDevice;status=WdfDeviceCreate(&init,&attr,&device);if(!NT_SUCCESS(status))goto done;
 status=WdfDeviceCreateSymbolicLink(device,&link);if(!NT_SUCCESS(status))goto done;WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfFalse;queue.EvtIoDeviceControl=G99Control;status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))goto done;WdfControlFinishInitializing(device);
 done:if(init)WdfDeviceInitFree(init);if(!NT_SUCCESS(status)&&G99Frozen){ExFreePoolWithTag(G99Frozen,'99GO');G99Frozen=NULL;}return status;
}
