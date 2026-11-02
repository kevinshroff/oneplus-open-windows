/* SPDX-License-Identifier: MIT
 * Temporary source-built KMDF diagnostic. Fixed qualified register/PMIC reads.
 * This control device is not the eventual PnP bus/regulator owner.
 */
#include <ntddk.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g73_binding.h"
#include "g73_observer.h"
#include "g73_protocol.h"
#include "g73_adapter_policy.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G73Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G73Control;
EVT_WDF_DEVICE_FILE_CREATE G73FileCreate;
static volatile LONG64 G73Sequence;
static volatile LONG G73MapCalls;
static volatile LONG G73ObserverAttempts;
static volatile LONG G73ObserverFault;
static volatile LONG G73RunUsed,G73PmicVerified,G73TotalObservers,G73RunReady;
static G73_RUN*G73Frozen;

static VOID G73Status(G73_STATUS *out)
{
 UCHAR table[sizeof(G73ExpectedDsdt)];ULONG bytes=0;
 RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=G73_ABI;out->Magic=G73_MAGIC;
 out->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
 out->CurrentIrql=KeGetCurrentIrql();out->RegisterCount=G73_REGISTER_COUNT;
 out->RunAttempts=(ULONG)InterlockedCompareExchange(&G73RunUsed,0,0);out->ObserverCaptures=(ULONG)InterlockedCompareExchange(&G73TotalObservers,0,0);out->ObserverFault=(ULONG)InterlockedCompareExchange(&G73ObserverFault,0,0);out->OffPmicVerified=(ULONG)InterlockedCompareExchange(&G73PmicVerified,0,0);
 out->MapCalls=(ULONG)InterlockedCompareExchange(&G73MapCalls,0,0);
 out->Sequence=(ULONGLONG)InterlockedIncrement64(&G73Sequence);out->InterruptTime=KeQueryInterruptTime();
 RtlCopyMemory(out->BuildId,"G73-off-meta1",sizeof("G73-off-meta1"));
 if(out->CurrentIrql!=PASSIVE_LEVEL){out->FirmwareStatus=(ULONG)STATUS_INVALID_DEVICE_STATE;return;}
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);
 if(NT_SUCCESS(RtlGetVersion(&version)))out->KernelBuild=version.dwBuildNumber;
 RtlZeroMemory(table,sizeof(table));
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);
 out->FirmwareStatus=(ULONG)status;out->FirmwareBytes=bytes;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G73ExpectedDsdt,sizeof(table))==sizeof(table))out->FirmwareMatch=1;
}

static NTSTATUS G73Snapshot(G73_SNAPSHOT *out)
{
 PVOID maps[RTL_NUMBER_OF(G73Ranges)];NTSTATUS status=STATUS_SUCCESS;ULONG i;
 RtlZeroMemory(out,sizeof(*out));G73Status(&out->Status);
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26100||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL)return STATUS_NOT_SUPPORTED;
 RtlZeroMemory(maps,sizeof(maps));
 for(i=0;i<RTL_NUMBER_OF(G73Ranges);i++){
  PHYSICAL_ADDRESS address;address.QuadPart=(LONGLONG)G73Ranges[i].Base;
  InterlockedIncrement(&G73MapCalls);
  maps[i]=MmMapIoSpaceEx(address,G73Ranges[i].Bytes,PAGE_READONLY|PAGE_NOCACHE);
  if(maps[i]==NULL){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 }
 for(i=0;i<G73_REGISTER_COUNT;i++){
  const G73_FIELD *field=&G73Fields[i];
  out->Values[i]=READ_REGISTER_ULONG((PULONG)((PUCHAR)maps[field->Range]+field->Offset));
 }
 out->Count=G73_REGISTER_COUNT;
 done:
 for(i=RTL_NUMBER_OF(G73Ranges);i>0;i--)if(maps[i-1])MmUnmapIoSpace(maps[i-1],G73Ranges[i-1].Bytes);
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G73MapCalls,0,0);
 return status;
}

static int G73FixedBaseline(const uint32_t*v)
{
 if(G73_REGISTER_COUNT!=50||G73Fields[12].Range!=0||G73Fields[12].Offset!=0xd44||G73Ranges[0].Base!=0x17a20000)return 0;
 for(ULONG i=0;i<50;i++){if(i==12){if(v[i]!=0&&v[i]!=7)return 0;}else if(v[i]!=G73ExpectedValues[i])return 0;}return 1;
}
typedef struct {PVOID Maps[G73_IO_RANGES];ULONG Reads,Writes,Ready;}G73_IO_CONTEXT;
static void G73Unmap(G73_IO_CONTEXT*c)
{for(ULONG i=G73_IO_RANGES;i;i--)if(c->Maps[i-1]){MmUnmapIoSpace(c->Maps[i-1],G73IoRanges[i-1].Bytes);c->Maps[i-1]=NULL;}c->Ready=0;}
static int G73Map(G73_IO_CONTEXT*c)
{
 RtlZeroMemory(c,sizeof(*c));for(ULONG i=0;i<G73_IO_RANGES;i++){
  PHYSICAL_ADDRESS a;a.QuadPart=G73IoRanges[i].Base;InterlockedIncrement(&G73MapCalls);
  c->Maps[i]=MmMapIoSpaceEx(a,G73IoRanges[i].Bytes,(G73IoRanges[i].Writable?PAGE_READWRITE:PAGE_READONLY)|PAGE_NOCACHE);
  if(!c->Maps[i]){G73Unmap(c);return 0;}
 }c->Ready=1;return 1;
}
static PULONG G73Address(G73_IO_CONTEXT*c,ULONG at,ULONG writing,ULONG value)
{
 if(!c->Ready||(at&3)||(writing?!G73IoWriteAllowed(at,value):!G73IoReadAllowed(at)))return NULL;
 for(ULONG i=0;i<G73_IO_RANGES;i++)if(c->Maps[i]&&at>=G73IoRanges[i].Base&&at-G73IoRanges[i].Base<=G73IoRanges[i].Bytes-4){
  if(writing&&!G73IoRanges[i].Writable)return NULL;return(PULONG)((PUCHAR)c->Maps[i]+at-G73IoRanges[i].Base);
 }
 return NULL;
}
static int G73NativeRead(void*context,uint32_t at,uint32_t*v)
{
 G73_IO_CONTEXT*c=context;PULONG p;if(c->Reads>=3000)return 0;p=G73Address(c,at,0,0);if(!p)return 0;c->Reads++;*v=READ_REGISTER_ULONG(p);return 1;
}
static int G73NativeWrite(void*context,uint32_t at,uint32_t value)
{
 G73_IO_CONTEXT*c=context;PULONG p;if(c->Writes>=183)return 0;p=G73Address(c,at,1,value);if(!p)return 0;
 if(at==0xc440ea0||at==0xc441220||at==0xc4456e0){
  if(InterlockedCompareExchange(&G73ObserverFault,0,0))return 0;
  if(at==0xc440ea0){LONG n=InterlockedCompareExchange(&G73TotalObservers,0,0);if(n>=5||InterlockedCompareExchange(&G73TotalObservers,n+1,n)!=n)return 0;}
 }
 c->Writes++;WRITE_REGISTER_ULONG(p,value);return 1;
}
static void G73WaitMs(void*context){UNREFERENCED_PARAMETER(context);KeStallExecutionProcessor(1000);}
static void G73WaitUs(void*context){UNREFERENCED_PARAMETER(context);KeStallExecutionProcessor(1);}
static int G73OffState(const G73_OBS_RESULT*p)
{const UCHAR off[8]={8,7,0,0,7,7,0,0};return !p->Code&&p->Status==0x43&&RtlCompareMemory(p->Configuration,off,8)==8;}
static void G73CapturePmic(G73_PMIC*out)
{
 G73_IO_CONTEXT c;G73_SNAPSHOT before,after;LARGE_INTEGER start,end,freq;LONG previous;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&c,sizeof(c));G73Status(&out->Status);start=KeQueryPerformanceCounter(&freq);out->CounterFrequency=(uint64_t)freq.QuadPart;
 previous=InterlockedCompareExchange(&G73ObserverAttempts,0,0);out->Attempt=(ULONG)previous;
 if(InterlockedCompareExchange(&G73ObserverFault,0,0)){out->Observer.Code=1001;goto done;}
 if(previous>=2||InterlockedCompareExchange(&G73ObserverAttempts,previous+1,previous)!=previous){out->Observer.Code=1002;goto done;}out->Attempt=(ULONG)previous+1;
 InterlockedExchange(&G73PmicVerified,0);
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26100||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Observer.Code=1004;goto done;}
 if(!NT_SUCCESS(G73Snapshot(&before))||!G73FixedBaseline(before.Values)){out->Observer.Code=1005;goto done;}
 if(!G73Map(&c)){out->Observer.Code=1006;goto done;}
 G73_OBS_IO io={&c,G73NativeRead,G73NativeWrite,G73WaitUs};G73Observe(&io,&out->Observer);G73Unmap(&c);
 if(!out->Observer.Code){if(NT_SUCCESS(G73Snapshot(&after))&&RtlCompareMemory(before.Values,after.Values,sizeof(before.Values))==sizeof(before.Values))out->FixedRegistersUnchanged=1;else out->Observer.Code=1007;}
 if(out->Observer.Code)InterlockedExchange(&G73ObserverFault,1);
 else if(out->FixedRegistersUnchanged&&G73OffState(&out->Observer))InterlockedExchange(&G73PmicVerified,1);
 done:G73Unmap(&c);G73Status(&out->Status);end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(uint64_t)(end.QuadPart-start.QuadPart);
}
static void G73CaptureRun(G73_RUN*out,uint64_t nonce)
{
 G73_IO_CONTEXT c;G73_SNAPSHOT before,after;LARGE_INTEGER start,end,freq;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&c,sizeof(c));out->Nonce=nonce;out->Attempt=1;G73Status(&out->Status);start=KeQueryPerformanceCounter(&freq);out->CounterFrequency=(uint64_t)freq.QuadPart;
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26100||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Off.Code=1004;goto done;}
 if(!InterlockedCompareExchange(&G73PmicVerified,0,0)||InterlockedCompareExchange(&G73ObserverFault,0,0)||InterlockedCompareExchange(&G73ObserverAttempts,0,0)!=1||InterlockedCompareExchange(&G73TotalObservers,0,0)!=1){out->Off.Code=1005;goto done;}
 if(!NT_SUCCESS(G73Snapshot(&before))||!G73FixedBaseline(before.Values)){out->Off.Code=1006;goto done;}
 out->BaselineValid=1;RtlCopyMemory(out->Before,before.Values,sizeof(out->Before));
 if(!G73Map(&c)){out->Off.Code=1007;goto done;}
 G73_OFF_IO io={{&c,G73NativeRead,G73NativeWrite,G73WaitMs},{&c,G73NativeRead,G73NativeWrite,G73WaitUs}};G73OffTrial(&io,&out->Off);G73Unmap(&c);
 if(out->Off.ObserverUncertain)InterlockedExchange(&G73ObserverFault,1);
 if(NT_SUCCESS(G73Snapshot(&after))){RtlCopyMemory(out->After,after.Values,sizeof(out->After));if(RtlCompareMemory(out->Before,out->After,sizeof(out->Before))==sizeof(out->Before))out->FixedRegistersUnchanged=1;}
 done:G73Unmap(&c);G73Status(&out->Status);end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(uint64_t)(end.QuadPart-start.QuadPart);
}

VOID G73Control(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 G73_REQUEST*source,in;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR info=0;UNREFERENCED_PARAMETER(queue);
 if(code!=G73_IOCTL_STATUS&&code!=G73_IOCTL_SNAPSHOT&&code!=G73_IOCTL_PMIC&&code!=G73_IOCTL_RUN&&code!=G73_IOCTL_RESULT){status=STATUS_INVALID_DEVICE_REQUEST;goto complete;}
 if(inputBytes!=sizeof(in)){status=STATUS_INVALID_PARAMETER;goto complete;}
 status=WdfRequestRetrieveInputBuffer(request,sizeof(in),(PVOID*)&source,NULL);if(!NT_SUCCESS(status))goto complete;in=*source;
 if(in.Size!=24||in.Version!=G73_ABI||in.Magic!=G73_MAGIC||((code==G73_IOCTL_RUN||code==G73_IOCTL_RESULT)?!in.Nonce:in.Nonce!=0)){status=STATUS_INVALID_PARAMETER;goto complete;}
 needed=code==G73_IOCTL_STATUS?sizeof(G73_STATUS):code==G73_IOCTL_SNAPSHOT?sizeof(G73_SNAPSHOT):code==G73_IOCTL_PMIC?sizeof(G73_PMIC):sizeof(G73_RUN);
 if(outputBytes!=needed){status=STATUS_BUFFER_TOO_SMALL;goto complete;}
 status=WdfRequestRetrieveOutputBuffer(request,needed,&output,NULL);if(!NT_SUCCESS(status))goto complete;
 if(code==G73_IOCTL_STATUS){G73Status(output);status=STATUS_SUCCESS;}
 else if(code==G73_IOCTL_SNAPSHOT)status=G73Snapshot(output);
 else if(code==G73_IOCTL_PMIC){G73CapturePmic(output);status=STATUS_SUCCESS;}
 else if(code==G73_IOCTL_RESULT){
  if(!InterlockedCompareExchange(&G73RunReady,0,0)||!G73Frozen||G73Frozen->Nonce!=in.Nonce){status=STATUS_NOT_FOUND;goto complete;}
  RtlCopyMemory(output,G73Frozen,sizeof(*G73Frozen));status=STATUS_SUCCESS;
 }else{
  if(!G73Frozen||InterlockedCompareExchange(&G73RunUsed,1,0)){status=STATUS_QUOTA_EXCEEDED;goto complete;}
  G73CaptureRun(G73Frozen,in.Nonce);InterlockedExchange(&G73RunReady,1);RtlCopyMemory(output,G73Frozen,sizeof(*G73Frozen));status=STATUS_SUCCESS;
 }
 if(NT_SUCCESS(status))info=needed;
 complete:WdfRequestCompleteWithInformation(request,status,info);
}
VOID G73FileCreate(WDFDEVICE device,WDFREQUEST request,WDFFILEOBJECT file)
{PUNICODE_STRING name=WdfFileObjectGetFileName(file);UNREFERENCED_PARAMETER(device);WdfRequestComplete(request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);}
VOID G73Unload(WDFDRIVER driver)
{UNREFERENCED_PARAMETER(driver);if(G73Frozen){ExFreePoolWithTag(G73Frozen,'37GO');G73Frozen=NULL;}}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING path)
{
 WDF_DRIVER_CONFIG config;WDFDRIVER driver;PWDFDEVICE_INIT init=NULL;WDFDEVICE device;WDF_OBJECT_ATTRIBUTES attr;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG file;NTSTATUS status;
 DECLARE_CONST_UNICODE_STRING(sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");DECLARE_CONST_UNICODE_STRING(name,L"\\Device\\OpenG73");DECLARE_CONST_UNICODE_STRING(link,L"\\DosDevices\\OpenG73");
 WDF_DRIVER_CONFIG_INIT(&config,WDF_NO_EVENT_CALLBACK);config.DriverInitFlags|=WdfDriverInitNonPnpDriver;config.EvtDriverUnload=G73Unload;
 status=WdfDriverCreate(object,path,WDF_NO_OBJECT_ATTRIBUTES,&config,&driver);if(!NT_SUCCESS(status))return status;
 status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 G73Frozen=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*G73Frozen),'37GO');if(!G73Frozen)return STATUS_INSUFFICIENT_RESOURCES;
 init=WdfControlDeviceInitAllocate(driver,&sddl);if(!init){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&file,G73FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);WdfDeviceInitSetFileObjectConfig(init,&file,WDF_NO_OBJECT_ATTRIBUTES);
 status=WdfDeviceInitAssignName(init,&name);if(!NT_SUCCESS(status))goto done;
 WDF_OBJECT_ATTRIBUTES_INIT(&attr);attr.ExecutionLevel=WdfExecutionLevelPassive;attr.SynchronizationScope=WdfSynchronizationScopeDevice;
 status=WdfDeviceCreate(&init,&attr,&device);if(!NT_SUCCESS(status))goto done;
 status=WdfDeviceCreateSymbolicLink(device,&link);if(!NT_SUCCESS(status))goto done;
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfFalse;queue.EvtIoDeviceControl=G73Control;
 status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))goto done;WdfControlFinishInitializing(device);
 done:if(init)WdfDeviceInitFree(init);if(!NT_SUCCESS(status)&&G73Frozen){ExFreePoolWithTag(G73Frozen,'37GO');G73Frozen=NULL;}return status;
}

