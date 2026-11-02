/* SPDX-License-Identifier: MIT
 * Temporary source-built KMDF diagnostic. Fixed qualified register/PMIC reads.
 * This control device is not the eventual PnP bus/regulator owner.
 */
#include <ntddk.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g74_binding.h"
#include "g74_observer.h"
#include "g74_protocol.h"
#include "g74_adapter_policy.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G74Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G74Control;
EVT_WDF_DEVICE_FILE_CREATE G74FileCreate;
static volatile LONG64 G74Sequence;
static volatile LONG G74MapCalls;
static volatile LONG G74ObserverAttempts;
static volatile LONG G74ObserverFault;
static volatile LONG G74RunUsed,G74PmicVerified,G74TotalObservers,G74RunReady;
static G74_RUN*G74Frozen;

static VOID G74Status(G74_STATUS *out)
{
 UCHAR table[sizeof(G74ExpectedDsdt)];ULONG bytes=0;
 RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=G74_ABI;out->Magic=G74_MAGIC;
 out->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
 out->CurrentIrql=KeGetCurrentIrql();out->RegisterCount=G74_REGISTER_COUNT;
 out->RunAttempts=(ULONG)InterlockedCompareExchange(&G74RunUsed,0,0);out->ObserverCaptures=(ULONG)InterlockedCompareExchange(&G74TotalObservers,0,0);out->ObserverFault=(ULONG)InterlockedCompareExchange(&G74ObserverFault,0,0);out->OffPmicVerified=(ULONG)InterlockedCompareExchange(&G74PmicVerified,0,0);
 out->MapCalls=(ULONG)InterlockedCompareExchange(&G74MapCalls,0,0);
 out->Sequence=(ULONGLONG)InterlockedIncrement64(&G74Sequence);out->InterruptTime=KeQueryInterruptTime();
 RtlCopyMemory(out->BuildId,"G74-off-meta1",sizeof("G74-off-meta1"));
 if(out->CurrentIrql!=PASSIVE_LEVEL){out->FirmwareStatus=(ULONG)STATUS_INVALID_DEVICE_STATE;return;}
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);
 if(NT_SUCCESS(RtlGetVersion(&version)))out->KernelBuild=version.dwBuildNumber;
 RtlZeroMemory(table,sizeof(table));
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);
 out->FirmwareStatus=(ULONG)status;out->FirmwareBytes=bytes;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G74ExpectedDsdt,sizeof(table))==sizeof(table))out->FirmwareMatch=1;
}

static NTSTATUS G74Snapshot(G74_SNAPSHOT *out)
{
 PVOID maps[RTL_NUMBER_OF(G74Ranges)];NTSTATUS status=STATUS_SUCCESS;ULONG i;
 RtlZeroMemory(out,sizeof(*out));G74Status(&out->Status);
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26100||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL)return STATUS_NOT_SUPPORTED;
 RtlZeroMemory(maps,sizeof(maps));
 for(i=0;i<RTL_NUMBER_OF(G74Ranges);i++){
  PHYSICAL_ADDRESS address;address.QuadPart=(LONGLONG)G74Ranges[i].Base;
  InterlockedIncrement(&G74MapCalls);
  maps[i]=MmMapIoSpaceEx(address,G74Ranges[i].Bytes,PAGE_READONLY|PAGE_NOCACHE);
  if(maps[i]==NULL){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 }
 for(i=0;i<G74_REGISTER_COUNT;i++){
  const G74_FIELD *field=&G74Fields[i];
  out->Values[i]=READ_REGISTER_ULONG((PULONG)((PUCHAR)maps[field->Range]+field->Offset));
 }
 out->Count=G74_REGISTER_COUNT;
 done:
 for(i=RTL_NUMBER_OF(G74Ranges);i>0;i--)if(maps[i-1])MmUnmapIoSpace(maps[i-1],G74Ranges[i-1].Bytes);
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G74MapCalls,0,0);
 return status;
}

static int G74FixedBaseline(const uint32_t*v)
{
 if(G74_REGISTER_COUNT!=50||G74Fields[12].Range!=0||G74Fields[12].Offset!=0xd44||G74Ranges[0].Base!=0x17a20000)return 0;
 for(ULONG i=0;i<50;i++){if(i==12){if(v[i]!=0&&v[i]!=7)return 0;}else if(v[i]!=G74ExpectedValues[i])return 0;}return 1;
}
typedef struct {PVOID Maps[G74_IO_RANGES];ULONG Reads,Writes,Ready;}G74_IO_CONTEXT;
static void G74Unmap(G74_IO_CONTEXT*c)
{for(ULONG i=G74_IO_RANGES;i;i--)if(c->Maps[i-1]){MmUnmapIoSpace(c->Maps[i-1],G74IoRanges[i-1].Bytes);c->Maps[i-1]=NULL;}c->Ready=0;}
static int G74Map(G74_IO_CONTEXT*c)
{
 RtlZeroMemory(c,sizeof(*c));for(ULONG i=0;i<G74_IO_RANGES;i++){
  PHYSICAL_ADDRESS a;a.QuadPart=G74IoRanges[i].Base;InterlockedIncrement(&G74MapCalls);
  c->Maps[i]=MmMapIoSpaceEx(a,G74IoRanges[i].Bytes,(G74IoRanges[i].Writable?PAGE_READWRITE:PAGE_READONLY)|PAGE_NOCACHE);
  if(!c->Maps[i]){G74Unmap(c);return 0;}
 }c->Ready=1;return 1;
}
static PULONG G74Address(G74_IO_CONTEXT*c,ULONG at,ULONG writing,ULONG value)
{
 if(!c->Ready||(at&3)||(writing?!G74IoWriteAllowed(at,value):!G74IoReadAllowed(at)))return NULL;
 for(ULONG i=0;i<G74_IO_RANGES;i++)if(c->Maps[i]&&at>=G74IoRanges[i].Base&&at-G74IoRanges[i].Base<=G74IoRanges[i].Bytes-4){
  if(writing&&!G74IoRanges[i].Writable)return NULL;return(PULONG)((PUCHAR)c->Maps[i]+at-G74IoRanges[i].Base);
 }
 return NULL;
}
static int G74NativeRead(void*context,uint32_t at,uint32_t*v)
{
 G74_IO_CONTEXT*c=context;PULONG p;if(c->Reads>=3000)return 0;p=G74Address(c,at,0,0);if(!p)return 0;c->Reads++;*v=READ_REGISTER_ULONG(p);return 1;
}
static int G74NativeWrite(void*context,uint32_t at,uint32_t value)
{
 G74_IO_CONTEXT*c=context;PULONG p;if(c->Writes>=183)return 0;p=G74Address(c,at,1,value);if(!p)return 0;
 if(at==0xc440ea0||at==0xc441220||at==0xc4456e0){
  if(InterlockedCompareExchange(&G74ObserverFault,0,0))return 0;
  if(at==0xc440ea0){LONG n=InterlockedCompareExchange(&G74TotalObservers,0,0);if(n>=5||InterlockedCompareExchange(&G74TotalObservers,n+1,n)!=n)return 0;}
 }
 c->Writes++;WRITE_REGISTER_ULONG(p,value);return 1;
}
static void G74WaitMs(void*context){UNREFERENCED_PARAMETER(context);KeStallExecutionProcessor(1000);}
static void G74WaitUs(void*context){UNREFERENCED_PARAMETER(context);KeStallExecutionProcessor(1);}
static int G74OffState(const G74_OBS_RESULT*p)
{const UCHAR off[8]={8,7,0,0,7,7,0,0};return !p->Code&&p->Status==0x43&&RtlCompareMemory(p->Configuration,off,8)==8;}
static void G74CapturePmic(G74_PMIC*out)
{
 G74_IO_CONTEXT c;G74_SNAPSHOT before,after;LARGE_INTEGER start,end,freq;LONG previous;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&c,sizeof(c));G74Status(&out->Status);start=KeQueryPerformanceCounter(&freq);out->CounterFrequency=(uint64_t)freq.QuadPart;
 previous=InterlockedCompareExchange(&G74ObserverAttempts,0,0);out->Attempt=(ULONG)previous;
 if(InterlockedCompareExchange(&G74ObserverFault,0,0)){out->Observer.Code=1001;goto done;}
 if(previous>=2||InterlockedCompareExchange(&G74ObserverAttempts,previous+1,previous)!=previous){out->Observer.Code=1002;goto done;}out->Attempt=(ULONG)previous+1;
 InterlockedExchange(&G74PmicVerified,0);
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26100||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Observer.Code=1004;goto done;}
 if(!NT_SUCCESS(G74Snapshot(&before))||!G74FixedBaseline(before.Values)){out->Observer.Code=1005;goto done;}
 if(!G74Map(&c)){out->Observer.Code=1006;goto done;}
 G74_OBS_IO io={&c,G74NativeRead,G74NativeWrite,G74WaitUs};G74Observe(&io,&out->Observer);G74Unmap(&c);
 if(!out->Observer.Code){if(NT_SUCCESS(G74Snapshot(&after))&&RtlCompareMemory(before.Values,after.Values,sizeof(before.Values))==sizeof(before.Values))out->FixedRegistersUnchanged=1;else out->Observer.Code=1007;}
 if(out->Observer.Code)InterlockedExchange(&G74ObserverFault,1);
 else if(out->FixedRegistersUnchanged&&G74OffState(&out->Observer))InterlockedExchange(&G74PmicVerified,1);
 done:G74Unmap(&c);G74Status(&out->Status);end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(uint64_t)(end.QuadPart-start.QuadPart);
}
static void G74CaptureRun(G74_RUN*out,uint64_t nonce)
{
 G74_IO_CONTEXT c;G74_SNAPSHOT before,after;LARGE_INTEGER start,end,freq;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&c,sizeof(c));out->Nonce=nonce;out->Attempt=1;G74Status(&out->Status);start=KeQueryPerformanceCounter(&freq);out->CounterFrequency=(uint64_t)freq.QuadPart;
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26100||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Off.Code=1004;goto done;}
 if(!InterlockedCompareExchange(&G74PmicVerified,0,0)||InterlockedCompareExchange(&G74ObserverFault,0,0)||InterlockedCompareExchange(&G74ObserverAttempts,0,0)!=1||InterlockedCompareExchange(&G74TotalObservers,0,0)!=1){out->Off.Code=1005;goto done;}
 if(!NT_SUCCESS(G74Snapshot(&before))||!G74FixedBaseline(before.Values)){out->Off.Code=1006;goto done;}
 out->BaselineValid=1;RtlCopyMemory(out->Before,before.Values,sizeof(out->Before));
 if(!G74Map(&c)){out->Off.Code=1007;goto done;}
 G74_OFF_IO io={{&c,G74NativeRead,G74NativeWrite,G74WaitMs},{&c,G74NativeRead,G74NativeWrite,G74WaitUs}};G74OffTrial(&io,&out->Off);G74Unmap(&c);
 if(out->Off.ObserverUncertain)InterlockedExchange(&G74ObserverFault,1);
 if(NT_SUCCESS(G74Snapshot(&after))){RtlCopyMemory(out->After,after.Values,sizeof(out->After));if(RtlCompareMemory(out->Before,out->After,sizeof(out->Before))==sizeof(out->Before))out->FixedRegistersUnchanged=1;}
 done:G74Unmap(&c);G74Status(&out->Status);end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(uint64_t)(end.QuadPart-start.QuadPart);
}

VOID G74Control(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 G74_REQUEST*source,in;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR info=0;UNREFERENCED_PARAMETER(queue);
 if(code!=G74_IOCTL_STATUS&&code!=G74_IOCTL_SNAPSHOT&&code!=G74_IOCTL_PMIC&&code!=G74_IOCTL_RUN&&code!=G74_IOCTL_RESULT){status=STATUS_INVALID_DEVICE_REQUEST;goto complete;}
 if(inputBytes!=sizeof(in)){status=STATUS_INVALID_PARAMETER;goto complete;}
 status=WdfRequestRetrieveInputBuffer(request,sizeof(in),(PVOID*)&source,NULL);if(!NT_SUCCESS(status))goto complete;in=*source;
 if(in.Size!=24||in.Version!=G74_ABI||in.Magic!=G74_MAGIC||((code==G74_IOCTL_RUN||code==G74_IOCTL_RESULT)?!in.Nonce:in.Nonce!=0)){status=STATUS_INVALID_PARAMETER;goto complete;}
 needed=code==G74_IOCTL_STATUS?sizeof(G74_STATUS):code==G74_IOCTL_SNAPSHOT?sizeof(G74_SNAPSHOT):code==G74_IOCTL_PMIC?sizeof(G74_PMIC):sizeof(G74_RUN);
 if(outputBytes!=needed){status=STATUS_BUFFER_TOO_SMALL;goto complete;}
 status=WdfRequestRetrieveOutputBuffer(request,needed,&output,NULL);if(!NT_SUCCESS(status))goto complete;
 if(code==G74_IOCTL_STATUS){G74Status(output);status=STATUS_SUCCESS;}
 else if(code==G74_IOCTL_SNAPSHOT)status=G74Snapshot(output);
 else if(code==G74_IOCTL_PMIC){G74CapturePmic(output);status=STATUS_SUCCESS;}
 else if(code==G74_IOCTL_RESULT){
  if(!InterlockedCompareExchange(&G74RunReady,0,0)||!G74Frozen||G74Frozen->Nonce!=in.Nonce){status=STATUS_NOT_FOUND;goto complete;}
  RtlCopyMemory(output,G74Frozen,sizeof(*G74Frozen));status=STATUS_SUCCESS;
 }else{
  if(!G74Frozen||InterlockedCompareExchange(&G74RunUsed,1,0)){status=STATUS_QUOTA_EXCEEDED;goto complete;}
  G74CaptureRun(G74Frozen,in.Nonce);InterlockedExchange(&G74RunReady,1);RtlCopyMemory(output,G74Frozen,sizeof(*G74Frozen));status=STATUS_SUCCESS;
 }
 if(NT_SUCCESS(status))info=needed;
 complete:WdfRequestCompleteWithInformation(request,status,info);
}
VOID G74FileCreate(WDFDEVICE device,WDFREQUEST request,WDFFILEOBJECT file)
{PUNICODE_STRING name=WdfFileObjectGetFileName(file);UNREFERENCED_PARAMETER(device);WdfRequestComplete(request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);}
VOID G74Unload(WDFDRIVER driver)
{UNREFERENCED_PARAMETER(driver);if(G74Frozen){ExFreePoolWithTag(G74Frozen,'47GO');G74Frozen=NULL;}}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING path)
{
 WDF_DRIVER_CONFIG config;WDFDRIVER driver;PWDFDEVICE_INIT init=NULL;WDFDEVICE device;WDF_OBJECT_ATTRIBUTES attr;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG file;NTSTATUS status;
 DECLARE_CONST_UNICODE_STRING(sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");DECLARE_CONST_UNICODE_STRING(name,L"\\Device\\OpenG74");DECLARE_CONST_UNICODE_STRING(link,L"\\DosDevices\\OpenG74");
 WDF_DRIVER_CONFIG_INIT(&config,WDF_NO_EVENT_CALLBACK);config.DriverInitFlags|=WdfDriverInitNonPnpDriver;config.EvtDriverUnload=G74Unload;
 status=WdfDriverCreate(object,path,WDF_NO_OBJECT_ATTRIBUTES,&config,&driver);if(!NT_SUCCESS(status))return status;
 status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 G74Frozen=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*G74Frozen),'47GO');if(!G74Frozen)return STATUS_INSUFFICIENT_RESOURCES;
 init=WdfControlDeviceInitAllocate(driver,&sddl);if(!init){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&file,G74FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);WdfDeviceInitSetFileObjectConfig(init,&file,WDF_NO_OBJECT_ATTRIBUTES);
 status=WdfDeviceInitAssignName(init,&name);if(!NT_SUCCESS(status))goto done;
 WDF_OBJECT_ATTRIBUTES_INIT(&attr);attr.ExecutionLevel=WdfExecutionLevelPassive;attr.SynchronizationScope=WdfSynchronizationScopeDevice;
 status=WdfDeviceCreate(&init,&attr,&device);if(!NT_SUCCESS(status))goto done;
 status=WdfDeviceCreateSymbolicLink(device,&link);if(!NT_SUCCESS(status))goto done;
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfFalse;queue.EvtIoDeviceControl=G74Control;
 status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))goto done;WdfControlFinishInitializing(device);
 done:if(init)WdfDeviceInitFree(init);if(!NT_SUCCESS(status)&&G74Frozen){ExFreePoolWithTag(G74Frozen,'47GO');G74Frozen=NULL;}return status;
}

