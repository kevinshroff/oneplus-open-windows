/* SPDX-License-Identifier: MIT
 * Demand-loaded, one-shot fixed gauge identification queries.
 * Load and STATUS/RESULT never map hardware. Only fixed query transport writes
 * are allowed; no clock/pin/rate/packing/reset or gauge-configuration writes.
 */
#include <ntifs.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g104_binding.h"
#include "g104_core.h"
#include "g104_policy.h"
#include "g104_protocol.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G104Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G104Control;
EVT_WDF_DEVICE_FILE_CREATE G104FileCreate;
static volatile LONG G104Attempts,G104Ready,G104Fault,G104Maps;
static volatile LONG64 G104Sequence;
static G104_CAPTURE*G104Frozen;
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
static void Status(G104_STATUS*s)
{
 UCHAR dsdt[sizeof(G104ExpectedDsdt)];ULONG bytes=0;NTSTATUS status;RTL_OSVERSIONINFOW version;LARGE_INTEGER freq;
 RtlZeroMemory(s,sizeof(*s));s->Size=sizeof(*s);s->Version=G104_ABI;s->Magic=G104_MAGIC;s->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);s->Irql=KeGetCurrentIrql();s->MapCalls=(ULONG)InterlockedCompareExchange(&G104Maps,0,0);s->Attempts=(ULONG)InterlockedCompareExchange(&G104Attempts,0,0);s->Ready=(ULONG)InterlockedCompareExchange(&G104Ready,0,0);s->Fault=(ULONG)InterlockedCompareExchange(&G104Fault,0,0);s->InterruptTime=KeQueryInterruptTime();s->Sequence=(ULONGLONG)InterlockedIncrement64(&G104Sequence);KeQueryPerformanceCounter(&freq);s->Frequency=(ULONGLONG)freq.QuadPart;
 if(s->Irql!=PASSIVE_LEVEL){s->FirmwareStatus=(ULONG)STATUS_INVALID_DEVICE_STATE;return;}
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);if(NT_SUCCESS(RtlGetVersion(&version)))s->KernelBuild=version.dwBuildNumber;
 status=AuxKlibGetSystemFirmwareTable(0x41435049,0x54445344,dsdt,sizeof(dsdt),&bytes);s->FirmwareStatus=(ULONG)status;s->FirmwareBytes=bytes;if(NT_SUCCESS(status)&&bytes==sizeof(dsdt)&&RtlCompareMemory(dsdt,G104ExpectedDsdt,sizeof(dsdt))==sizeof(dsdt))s->FirmwareMatch=1;
}

/* Fixed inherited resources. Only the two engine pages are mapped RW; every
 * store and FIFO read requires independent fixed transaction policy. Resource
 * observations do not constitute a production ACPI/SPB power/resource lease. */
static const ULONG Pages[]={0x152000,0x11e000,0x117000,0x123000,0xf100000,0xf101000,0xf116000,0xf117000,0x880000,0x8c0000,0x98c000,0x9c0000};
typedef struct {PVOID Maps[12];WDFREQUEST Request;ULONG Reads,Writes,MapCalls,Guard;ULONGLONG Frequency;G104_POLICY Policy;}G104_CONTEXT;
static int WriteOffset(ULONG o){return o==0x26c||o==0x270||o==0x600||o==0x604||o==0x618||o==0x700||o==0x80c;}
static PULONG Address(G104_CONTEXT*c,ULONG at,int write)
{
 int controller=G104Controller(at);
 if(write?(controller<0||!WriteOffset(at-G102Controllers[controller].Base)):!G104ReadAllowed(at))return NULL;
 for(ULONG i=0;i<12;i++)if(at>=Pages[i]&&at-Pages[i]<=0xffc){
  if(!c->Maps[i]){PHYSICAL_ADDRESS a;a.QuadPart=Pages[i];c->MapCalls++;InterlockedIncrement(&G104Maps);c->Maps[i]=MmMapIoSpaceEx(a,0x1000,((i==8||i==10)?PAGE_READWRITE:PAGE_READONLY)|PAGE_NOCACHE);}
  return c->Maps[i]?(PULONG)((PUCHAR)c->Maps[i]+at-Pages[i]):NULL;
 }
 return NULL;
}
static int SafeRead(G104_CONTEXT*c,uint32_t at,uint32_t*v)
{
 PULONG p;if(c->Reads>=200000)return 0;
 p=Address(c,at,0);if(!p)return 0;c->Reads++;*v=READ_REGISTER_ULONG(p);return 1;
}
static int NativeClocks(G104_CONTEXT*c,unsigned i)
{
 uint32_t v[8],pin;const G102_CONTROLLER*k=G102Controllers+i;
 for(unsigned j=0;j<3;j++)if(!SafeRead(c,k->Clocks[j].Vote,v+2*j)||!SafeRead(c,k->Clocks[j].Cbcr,v+2*j+1))return 0;
 if(!SafeRead(c,k->Root,v+6)||!SafeRead(c,k->Root+4,v+7)||!G102ClockUsable(i,v)||v[7]!=(i?1u:0x100001u))return 0;
 for(unsigned j=0;j<2;j++)if(!SafeRead(c,0xf100000+k->Pins[j]*0x1000,&pin)||pin!=((k->Mux[j]<<2)|3))return 0;
 return 1;
}
static int NativeRead(void*x,uint32_t at,uint32_t*v)
{
 G104_CONTEXT*c=x;int i;if(!G104ReadAllowed(at)){c->Guard=1;return 0;}
 i=G102Peripheral(at);if(i<0)i=G104Controller(at);
 if(i>=0&&!NativeClocks(c,(unsigned)i)){c->Guard=2;return 0;}
 int engine=G104Controller(at);
 if(engine>=0&&at-G102Controllers[engine].Base==0x780&&!G104ReceiveAllowed(&c->Policy,(unsigned)engine)){c->Guard=3;return 0;}
 if(!SafeRead(c,at,v))return 0;
 if(engine>=0)G104Observed(&c->Policy,(unsigned)engine,at-G102Controllers[engine].Base,*v);
 return 1;
}
static int NativeWrite(void*x,uint32_t at,uint32_t v)
{
 G104_CONTEXT*c=x;int i=G104Controller(at);PULONG p;
 if(i<0||!WriteOffset(at-G102Controllers[i].Base)||c->Writes>=512){c->Guard=4;return 0;}
 if(!NativeClocks(c,(unsigned)i)){c->Guard=2;return 0;}
 p=Address(c,at,1);if(!p)return 0;
 if(!G104WriteAllowed(&c->Policy,(unsigned)i,at-G102Controllers[i].Base,v)){c->Guard=4;return 0;}
 c->Writes++;WRITE_REGISTER_ULONG(p,v);return 1;
}
static void DelayUs(void*x,uint32_t us){UNREFERENCED_PARAMETER(x);if(us==20)KeStallExecutionProcessor(20);}
static int Available(void*x){return !WdfRequestIsCanceled(((G104_CONTEXT*)x)->Request);}
static uint64_t NowUs(void*x){G104_CONTEXT*c=x;LARGE_INTEGER q=KeQueryPerformanceCounter(NULL);ULONGLONG u=(ULONGLONG)q.QuadPart;if(q.QuadPart<0||!c->Frequency)return 0;return u/c->Frequency*1000000+(u%c->Frequency)*1000000/c->Frequency;}
static void Capture(G104_CAPTURE*out,WDFREQUEST request,ULONGLONG nonce)
{
 G104_CONTEXT c;G104_IO io;Status(&out->Status);out->Nonce=nonce;out->Result.Size=sizeof(out->Result);RtlZeroMemory(&c,sizeof(c));c.Request=request;c.Frequency=out->Status.Frequency;
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26300||out->Status.Processors!=8||out->Status.Irql!=PASSIVE_LEVEL||!c.Frequency||c.Frequency>1000000000ULL||!FullWindows()){out->Result.Code=1004;goto done;}
 io.Context=&c;io.Read=NativeRead;io.Write=NativeWrite;io.Available=Available;io.NowUs=NowUs;io.DelayUs=DelayUs;G104Identify(&io,&out->Result);
 done:for(ULONG i=12;i;i--)if(c.Maps[i-1])MmUnmapIoSpace(c.Maps[i-1],0x1000);
 out->NativeReads=c.Reads;out->NativeWrites=c.Writes;out->MapCalls=c.MapCalls;out->Guard=c.Guard;out->PolicyCommands=c.Policy.Commands;out->PolicyCompleted=c.Policy.Completed;out->PolicyFault=c.Policy.Faulted;if(out->Result.Code)InterlockedExchange(&G104Fault,1);
 InterlockedExchange(&G104Ready,1);Status(&out->Status);
}
VOID G104Control(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 G104_REQUEST*input,in;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;UNREFERENCED_PARAMETER(queue);
 if(code!=G104_IOCTL_STATUS&&code!=G104_IOCTL_READ&&code!=G104_IOCTL_RESULT){status=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inputBytes!=sizeof(in)){status=STATUS_INVALID_PARAMETER;goto done;}status=WdfRequestRetrieveInputBuffer(request,sizeof(in),(PVOID*)&input,NULL);if(!NT_SUCCESS(status))goto done;in=*input;
 if(in.Size!=sizeof(in)||in.Version!=G104_ABI||in.Magic!=G104_MAGIC||in.Reserved||in.Count||(code==G104_IOCTL_STATUS?in.Nonce||in.Count:!in.Nonce)){status=STATUS_INVALID_PARAMETER;goto done;}
 needed=code==G104_IOCTL_STATUS?sizeof(G104_STATUS):sizeof(G104_CAPTURE);if(outputBytes!=needed){status=STATUS_BUFFER_TOO_SMALL;goto done;}status=WdfRequestRetrieveOutputBuffer(request,needed,&output,NULL);if(!NT_SUCCESS(status))goto done;
 if(code==G104_IOCTL_STATUS)Status(output);
 else if(code==G104_IOCTL_RESULT){if(!InterlockedCompareExchange(&G104Ready,0,0)||G104Frozen->Nonce!=in.Nonce){status=STATUS_NOT_FOUND;goto done;}RtlCopyMemory(output,G104Frozen,sizeof(*G104Frozen));}
 else{if(InterlockedCompareExchange(&G104Attempts,1,0)){status=STATUS_QUOTA_EXCEEDED;goto done;}RtlZeroMemory(G104Frozen,sizeof(*G104Frozen));Capture(G104Frozen,request,in.Nonce);RtlCopyMemory(output,G104Frozen,sizeof(*G104Frozen));}
 status=STATUS_SUCCESS;information=needed;
 done:WdfRequestCompleteWithInformation(request,status,information);
}
VOID G104FileCreate(WDFDEVICE device,WDFREQUEST request,WDFFILEOBJECT file){PUNICODE_STRING name=WdfFileObjectGetFileName(file);UNREFERENCED_PARAMETER(device);WdfRequestComplete(request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);}
VOID G104Unload(WDFDRIVER driver){UNREFERENCED_PARAMETER(driver);if(G104Frozen){ExFreePoolWithTag(G104Frozen,'01GO');G104Frozen=NULL;}}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING path)
{
 WDF_DRIVER_CONFIG config;WDFDRIVER driver;PWDFDEVICE_INIT init=NULL;WDFDEVICE device;WDF_OBJECT_ATTRIBUTES attr;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG file;NTSTATUS status;
 DECLARE_CONST_UNICODE_STRING(sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");DECLARE_CONST_UNICODE_STRING(name,L"\\Device\\OpenG104");DECLARE_CONST_UNICODE_STRING(link,L"\\DosDevices\\OpenG104");
 WDF_DRIVER_CONFIG_INIT(&config,WDF_NO_EVENT_CALLBACK);config.DriverInitFlags|=WdfDriverInitNonPnpDriver;config.EvtDriverUnload=G104Unload;status=WdfDriverCreate(object,path,WDF_NO_OBJECT_ATTRIBUTES,&config,&driver);if(!NT_SUCCESS(status))return status;status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 G104Frozen=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*G104Frozen),'01GO');if(!G104Frozen)return STATUS_INSUFFICIENT_RESOURCES;
 init=WdfControlDeviceInitAllocate(driver,&sddl);if(!init){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&file,G104FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);WdfDeviceInitSetFileObjectConfig(init,&file,WDF_NO_OBJECT_ATTRIBUTES);status=WdfDeviceInitAssignName(init,&name);if(!NT_SUCCESS(status))goto done;WDF_OBJECT_ATTRIBUTES_INIT(&attr);attr.ExecutionLevel=WdfExecutionLevelPassive;attr.SynchronizationScope=WdfSynchronizationScopeDevice;status=WdfDeviceCreate(&init,&attr,&device);if(!NT_SUCCESS(status))goto done;
 status=WdfDeviceCreateSymbolicLink(device,&link);if(!NT_SUCCESS(status))goto done;WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfFalse;queue.EvtIoDeviceControl=G104Control;status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))goto done;WdfControlFinishInitializing(device);
 done:if(init)WdfDeviceInitFree(init);if(!NT_SUCCESS(status)&&G104Frozen){ExFreePoolWithTag(G104Frozen,'01GO');G104Frozen=NULL;}return status;
}
