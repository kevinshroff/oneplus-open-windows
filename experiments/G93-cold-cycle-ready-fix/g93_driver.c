/* SPDX-License-Identifier: MIT
 * Temporary source-built KMDF diagnostic. Fixed qualified register/PMIC reads.
 * This control device is not the eventual PnP bus/regulator owner.
 */
#include <ntddk.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g93_binding.h"
#include "g93_observer.h"
#include "g93_protocol.h"
#include "g93_adapter_policy.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G93Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G93Control;
EVT_WDF_DEVICE_FILE_CREATE G93FileCreate;
static volatile LONG64 G93Sequence;
static volatile LONG G93MapCalls;
static volatile LONG G93ObserverAttempts;
static volatile LONG G93ObserverFault;
static volatile LONG G93RunUsed,G93PmicVerified,G93TotalObservers,G93RunReady;
static G93_RUN*G93Frozen;

static VOID G93Status(G93_STATUS *out)
{
 UCHAR table[sizeof(G93ExpectedDsdt)];ULONG bytes=0;
 RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=G93_ABI;out->Magic=G93_MAGIC;
 out->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
 out->CurrentIrql=KeGetCurrentIrql();out->RegisterCount=G93_REGISTER_COUNT;
 out->RunAttempts=(ULONG)InterlockedCompareExchange(&G93RunUsed,0,0);out->ObserverCaptures=(ULONG)InterlockedCompareExchange(&G93TotalObservers,0,0);out->ObserverFault=(ULONG)InterlockedCompareExchange(&G93ObserverFault,0,0);out->OffPmicVerified=(ULONG)InterlockedCompareExchange(&G93PmicVerified,0,0);
 out->MapCalls=(ULONG)InterlockedCompareExchange(&G93MapCalls,0,0);
 out->Sequence=(ULONGLONG)InterlockedIncrement64(&G93Sequence);out->InterruptTime=KeQueryInterruptTime();
 RtlCopyMemory(out->BuildId,"G93-cold-lease",sizeof("G93-cold-lease"));
 if(out->CurrentIrql!=PASSIVE_LEVEL){out->FirmwareStatus=(ULONG)STATUS_INVALID_DEVICE_STATE;return;}
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);
 if(NT_SUCCESS(RtlGetVersion(&version)))out->KernelBuild=version.dwBuildNumber;
 RtlZeroMemory(table,sizeof(table));
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);
 out->FirmwareStatus=(ULONG)status;out->FirmwareBytes=bytes;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G93ExpectedDsdt,sizeof(table))==sizeof(table))out->FirmwareMatch=1;
}

static NTSTATUS G93Snapshot(G93_SNAPSHOT *out)
{
 PVOID maps[RTL_NUMBER_OF(G93Ranges)];NTSTATUS status=STATUS_SUCCESS;ULONG i;
 RtlZeroMemory(out,sizeof(*out));G93Status(&out->Status);
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26300||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL)return STATUS_NOT_SUPPORTED;
 RtlZeroMemory(maps,sizeof(maps));
 for(i=0;i<RTL_NUMBER_OF(G93Ranges);i++){
  PHYSICAL_ADDRESS address;address.QuadPart=(LONGLONG)G93Ranges[i].Base;
  InterlockedIncrement(&G93MapCalls);
  maps[i]=MmMapIoSpaceEx(address,G93Ranges[i].Bytes,PAGE_READONLY|PAGE_NOCACHE);
  if(maps[i]==NULL){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 }
 for(i=0;i<G93_REGISTER_COUNT;i++){
  const G93_FIELD *field=&G93Fields[i];
  out->Values[i]=READ_REGISTER_ULONG((PULONG)((PUCHAR)maps[field->Range]+field->Offset));
 }
 out->Count=G93_REGISTER_COUNT;
 done:
 for(i=RTL_NUMBER_OF(G93Ranges);i>0;i--)if(maps[i-1])MmUnmapIoSpace(maps[i-1],G93Ranges[i-1].Bytes);
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G93MapCalls,0,0);
 return status;
}

static int G93FixedBaseline(const uint32_t*v)
{
 if(G93_REGISTER_COUNT!=50||G93Fields[12].Range!=0||G93Fields[12].Offset!=0xd44||G93Ranges[0].Base!=0x17a20000)return 0;
 for(ULONG i=0;i<50;i++){if(i==12){if(v[i]!=0&&v[i]!=7)return 0;}else if(v[i]!=G93ExpectedValues[i])return 0;}return 1;
}
typedef struct {PVOID Maps[G93_IO_RANGES];ULONG Reads,Writes,Ready;}G93_IO_CONTEXT;
static void G93Unmap(G93_IO_CONTEXT*c)
{for(ULONG i=G93_IO_RANGES;i;i--)if(c->Maps[i-1]){MmUnmapIoSpace(c->Maps[i-1],G93IoRanges[i-1].Bytes);c->Maps[i-1]=NULL;}c->Ready=0;}
static int G93Map(G93_IO_CONTEXT*c)
{
 RtlZeroMemory(c,sizeof(*c));for(ULONG i=0;i<G93_IO_RANGES;i++){
  PHYSICAL_ADDRESS a;a.QuadPart=G93IoRanges[i].Base;InterlockedIncrement(&G93MapCalls);
  c->Maps[i]=MmMapIoSpaceEx(a,G93IoRanges[i].Bytes,(G93IoRanges[i].Writable?PAGE_READWRITE:PAGE_READONLY)|PAGE_NOCACHE);
  if(!c->Maps[i]){G93Unmap(c);return 0;}
 }c->Ready=1;return 1;
}
static PULONG G93Address(G93_IO_CONTEXT*c,ULONG at,ULONG writing,ULONG value)
{
 if(!c->Ready||(at&3)||(writing?!G93IoWriteAllowed(at,value):!G93IoReadAllowed(at)))return NULL;
 for(ULONG i=0;i<G93_IO_RANGES;i++)if(c->Maps[i]&&at>=G93IoRanges[i].Base&&at-G93IoRanges[i].Base<=G93IoRanges[i].Bytes-4){
  if(writing&&!G93IoRanges[i].Writable)return NULL;return(PULONG)((PUCHAR)c->Maps[i]+at-G93IoRanges[i].Base);
 }
 return NULL;
}
static int G93NativeRead(void*context,uint32_t at,uint32_t*v)
{
 G93_IO_CONTEXT*c=context;PULONG p;if(c->Reads>=3000)return 0;p=G93Address(c,at,0,0);if(!p)return 0;c->Reads++;*v=READ_REGISTER_ULONG(p);return 1;
}
static int G93NativeWrite(void*context,uint32_t at,uint32_t value)
{
 G93_IO_CONTEXT*c=context;PULONG p;if(c->Writes>=183)return 0;p=G93Address(c,at,1,value);if(!p)return 0;
 if(at==0xc440ea0||at==0xc441220||at==0xc4456e0){
  if(InterlockedCompareExchange(&G93ObserverFault,0,0))return 0;
  if(at==0xc440ea0){LONG n=InterlockedCompareExchange(&G93TotalObservers,0,0);if(n>=5||InterlockedCompareExchange(&G93TotalObservers,n+1,n)!=n)return 0;}
 }
 c->Writes++;WRITE_REGISTER_ULONG(p,value);return 1;
}
static void G93WaitMs(void*context){LARGE_INTEGER wait;UNREFERENCED_PARAMETER(context);wait.QuadPart=-10000;KeDelayExecutionThread(KernelMode,FALSE,&wait);}
static void G93Wait10(void*context){LARGE_INTEGER wait;UNREFERENCED_PARAMETER(context);wait.QuadPart=-100000;KeDelayExecutionThread(KernelMode,FALSE,&wait);}
static void G93WaitUs(void*context){UNREFERENCED_PARAMETER(context);KeStallExecutionProcessor(1);}
static int G93OffState(const G93_OBS_RESULT*p)
{const UCHAR off[8]={8,7,0,0,7,7,0,0};return !p->Code&&(p->Status==3||p->Status==0x43)&&RtlCompareMemory(p->Configuration,off,8)==8;}
static void G93CapturePmic(G93_PMIC*out)
{
 G93_IO_CONTEXT c;G93_SNAPSHOT before,after;LARGE_INTEGER start,end,freq;LONG previous;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&c,sizeof(c));G93Status(&out->Status);start=KeQueryPerformanceCounter(&freq);out->CounterFrequency=(uint64_t)freq.QuadPart;
 previous=InterlockedCompareExchange(&G93ObserverAttempts,0,0);out->Attempt=(ULONG)previous;
 if(InterlockedCompareExchange(&G93ObserverFault,0,0)){out->Observer.Code=1001;goto done;}
 if(previous>=2||InterlockedCompareExchange(&G93ObserverAttempts,previous+1,previous)!=previous){out->Observer.Code=1002;goto done;}out->Attempt=(ULONG)previous+1;
 InterlockedExchange(&G93PmicVerified,0);
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26300||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Observer.Code=1004;goto done;}
 if(!NT_SUCCESS(G93Snapshot(&before))||!G93FixedBaseline(before.Values)){out->Observer.Code=1005;goto done;}
 if(!G93Map(&c)){out->Observer.Code=1006;goto done;}
 G93_OBS_IO io={&c,G93NativeRead,G93NativeWrite,G93WaitUs};G93Observe(&io,&out->Observer);G93Unmap(&c);
 if(!out->Observer.Code){if(NT_SUCCESS(G93Snapshot(&after))&&RtlCompareMemory(before.Values,after.Values,sizeof(before.Values))==sizeof(before.Values))out->FixedRegistersUnchanged=1;else out->Observer.Code=1007;}
 if(out->Observer.Code)InterlockedExchange(&G93ObserverFault,1);
 else if(out->FixedRegistersUnchanged&&G93OffState(&out->Observer))InterlockedExchange(&G93PmicVerified,1);
 done:G93Unmap(&c);G93Status(&out->Status);end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(uint64_t)(end.QuadPart-start.QuadPart);
}
static void G93CaptureRun(G93_RUN*out,uint64_t nonce)
{
 G93_IO_CONTEXT c;G93_SNAPSHOT before,after;LARGE_INTEGER start,end,freq;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&c,sizeof(c));out->Nonce=nonce;out->Attempt=1;G93Status(&out->Status);start=KeQueryPerformanceCounter(&freq);out->CounterFrequency=(uint64_t)freq.QuadPart;
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26300||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Power.Code=1004;goto done;}
 if(!InterlockedCompareExchange(&G93PmicVerified,0,0)||InterlockedCompareExchange(&G93ObserverFault,0,0)||InterlockedCompareExchange(&G93ObserverAttempts,0,0)!=1||InterlockedCompareExchange(&G93TotalObservers,0,0)!=1){out->Power.Code=1005;goto done;}
 if(!NT_SUCCESS(G93Snapshot(&before))||!G93FixedBaseline(before.Values)){out->Power.Code=1006;goto done;}
 out->BaselineValid=1;RtlCopyMemory(out->Before,before.Values,sizeof(out->Before));
 if(!G93Map(&c)){out->Power.Code=1007;goto done;}
 InterlockedExchange(&G93PmicVerified,0);
 G93_POWER_IO io={{&c,G93NativeRead,G93NativeWrite,G93WaitMs},{&c,G93NativeRead,G93NativeWrite,G93WaitUs},G93Wait10};G93PowerTrial(&io,&out->Power);G93Unmap(&c);
 if(out->Power.OffVerified&&!out->Power.ObserverUncertain&&(!out->Power.EnableAttempted||(out->Power.LastOffObserveTxn>=out->Power.EnableTxn&&out->Power.LastOffObserveTxn>=out->Power.ReleaseTxn)))InterlockedExchange(&G93PmicVerified,1);
 if(out->Power.ObserverUncertain)InterlockedExchange(&G93ObserverFault,1);
 if(NT_SUCCESS(G93Snapshot(&after))){RtlCopyMemory(out->After,after.Values,sizeof(out->After));if(RtlCompareMemory(out->Before,out->After,sizeof(out->Before))==sizeof(out->Before))out->FixedRegistersUnchanged=1;}
 done:G93Unmap(&c);G93Status(&out->Status);end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(uint64_t)(end.QuadPart-start.QuadPart);
}

VOID G93Control(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 G93_REQUEST*source,in;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR info=0;UNREFERENCED_PARAMETER(queue);
 if(code!=G93_IOCTL_STATUS&&code!=G93_IOCTL_SNAPSHOT&&code!=G93_IOCTL_PMIC&&code!=G93_IOCTL_RUN&&code!=G93_IOCTL_RESULT){status=STATUS_INVALID_DEVICE_REQUEST;goto complete;}
 if(inputBytes!=sizeof(in)){status=STATUS_INVALID_PARAMETER;goto complete;}
 status=WdfRequestRetrieveInputBuffer(request,sizeof(in),(PVOID*)&source,NULL);if(!NT_SUCCESS(status))goto complete;in=*source;
 if(in.Size!=24||in.Version!=G93_ABI||in.Magic!=G93_MAGIC||((code==G93_IOCTL_RUN||code==G93_IOCTL_RESULT)?!in.Nonce:in.Nonce!=0)){status=STATUS_INVALID_PARAMETER;goto complete;}
 needed=code==G93_IOCTL_STATUS?sizeof(G93_STATUS):code==G93_IOCTL_SNAPSHOT?sizeof(G93_SNAPSHOT):code==G93_IOCTL_PMIC?sizeof(G93_PMIC):sizeof(G93_RUN);
 if(outputBytes!=needed){status=STATUS_BUFFER_TOO_SMALL;goto complete;}
 status=WdfRequestRetrieveOutputBuffer(request,needed,&output,NULL);if(!NT_SUCCESS(status))goto complete;
 if(code==G93_IOCTL_STATUS){G93Status(output);status=STATUS_SUCCESS;}
 else if(code==G93_IOCTL_SNAPSHOT)status=G93Snapshot(output);
 else if(code==G93_IOCTL_PMIC){G93CapturePmic(output);status=STATUS_SUCCESS;}
 else if(code==G93_IOCTL_RESULT){
  if(!InterlockedCompareExchange(&G93RunReady,0,0)||!G93Frozen||G93Frozen->Nonce!=in.Nonce){status=STATUS_NOT_FOUND;goto complete;}
  RtlCopyMemory(output,G93Frozen,sizeof(*G93Frozen));status=STATUS_SUCCESS;
 }else{
  if(!G93Frozen||InterlockedCompareExchange(&G93RunUsed,1,0)){status=STATUS_QUOTA_EXCEEDED;goto complete;}
  G93CaptureRun(G93Frozen,in.Nonce);InterlockedExchange(&G93RunReady,1);RtlCopyMemory(output,G93Frozen,sizeof(*G93Frozen));status=STATUS_SUCCESS;
 }
 if(NT_SUCCESS(status))info=needed;
 complete:WdfRequestCompleteWithInformation(request,status,info);
}
VOID G93FileCreate(WDFDEVICE device,WDFREQUEST request,WDFFILEOBJECT file)
{PUNICODE_STRING name=WdfFileObjectGetFileName(file);UNREFERENCED_PARAMETER(device);WdfRequestComplete(request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);}
VOID G93Unload(WDFDRIVER driver)
{UNREFERENCED_PARAMETER(driver);if(G93Frozen){ExFreePoolWithTag(G93Frozen,'57GO');G93Frozen=NULL;}}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING path)
{
 WDF_DRIVER_CONFIG config;WDFDRIVER driver;PWDFDEVICE_INIT init=NULL;WDFDEVICE device;WDF_OBJECT_ATTRIBUTES attr;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG file;NTSTATUS status;
 DECLARE_CONST_UNICODE_STRING(sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");DECLARE_CONST_UNICODE_STRING(name,L"\\Device\\OpenG93");DECLARE_CONST_UNICODE_STRING(link,L"\\DosDevices\\OpenG93");
 WDF_DRIVER_CONFIG_INIT(&config,WDF_NO_EVENT_CALLBACK);config.DriverInitFlags|=WdfDriverInitNonPnpDriver;config.EvtDriverUnload=G93Unload;
 status=WdfDriverCreate(object,path,WDF_NO_OBJECT_ATTRIBUTES,&config,&driver);if(!NT_SUCCESS(status))return status;
 status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 G93Frozen=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*G93Frozen),'57GO');if(!G93Frozen)return STATUS_INSUFFICIENT_RESOURCES;
 init=WdfControlDeviceInitAllocate(driver,&sddl);if(!init){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&file,G93FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);WdfDeviceInitSetFileObjectConfig(init,&file,WDF_NO_OBJECT_ATTRIBUTES);
 status=WdfDeviceInitAssignName(init,&name);if(!NT_SUCCESS(status))goto done;
 WDF_OBJECT_ATTRIBUTES_INIT(&attr);attr.ExecutionLevel=WdfExecutionLevelPassive;attr.SynchronizationScope=WdfSynchronizationScopeDevice;
 status=WdfDeviceCreate(&init,&attr,&device);if(!NT_SUCCESS(status))goto done;
 status=WdfDeviceCreateSymbolicLink(device,&link);if(!NT_SUCCESS(status))goto done;
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfFalse;queue.EvtIoDeviceControl=G93Control;
 status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))goto done;WdfControlFinishInitializing(device);
 done:if(init)WdfDeviceInitFree(init);if(!NT_SUCCESS(status)&&G93Frozen){ExFreePoolWithTag(G93Frozen,'57GO');G93Frozen=NULL;}return status;
}
