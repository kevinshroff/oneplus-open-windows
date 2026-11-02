/* SPDX-License-Identifier: MIT
 * Temporary source-built KMDF diagnostic. Fixed qualified register/PMIC reads.
 * This control device is not the eventual PnP bus/regulator owner.
 */
#include <ntddk.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g90_binding.h"
#include "g90_observer.h"
#include "g90_protocol.h"
#include "g90_adapter_policy.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G90Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G90Control;
EVT_WDF_DEVICE_FILE_CREATE G90FileCreate;
static volatile LONG64 G90Sequence;
static volatile LONG G90MapCalls;
static volatile LONG G90ObserverAttempts;
static volatile LONG G90ObserverFault;
static volatile LONG G90RunUsed,G90PmicVerified,G90TotalObservers;
static G90_RUN*G90Frozen;

static VOID G90Status(G90_STATUS *out)
{
 UCHAR table[sizeof(G90ExpectedDsdt)];ULONG bytes=0;
 RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=G90_ABI;out->Magic=G90_MAGIC;
 out->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
 out->CurrentIrql=KeGetCurrentIrql();out->RegisterCount=G90_REGISTER_COUNT;
 out->RunAttempts=(ULONG)InterlockedCompareExchange(&G90RunUsed,0,0);out->ObserverCaptures=(ULONG)InterlockedCompareExchange(&G90TotalObservers,0,0);out->ObserverFault=(ULONG)InterlockedCompareExchange(&G90ObserverFault,0,0);out->OffPmicVerified=(ULONG)InterlockedCompareExchange(&G90PmicVerified,0,0);
 out->MapCalls=(ULONG)InterlockedCompareExchange(&G90MapCalls,0,0);
 out->Sequence=(ULONGLONG)InterlockedIncrement64(&G90Sequence);out->InterruptTime=KeQueryInterruptTime();
 RtlCopyMemory(out->BuildId,"G90-cold-lease",sizeof("G90-cold-lease"));
 if(out->CurrentIrql!=PASSIVE_LEVEL){out->FirmwareStatus=(ULONG)STATUS_INVALID_DEVICE_STATE;return;}
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);
 if(NT_SUCCESS(RtlGetVersion(&version)))out->KernelBuild=version.dwBuildNumber;
 RtlZeroMemory(table,sizeof(table));
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);
 out->FirmwareStatus=(ULONG)status;out->FirmwareBytes=bytes;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G90ExpectedDsdt,sizeof(table))==sizeof(table))out->FirmwareMatch=1;
}

static NTSTATUS G90Snapshot(G90_SNAPSHOT *out)
{
 PVOID maps[RTL_NUMBER_OF(G90Ranges)];NTSTATUS status=STATUS_SUCCESS;ULONG i;
 RtlZeroMemory(out,sizeof(*out));G90Status(&out->Status);
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26300||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL)return STATUS_NOT_SUPPORTED;
 RtlZeroMemory(maps,sizeof(maps));
 for(i=0;i<RTL_NUMBER_OF(G90Ranges);i++){
  PHYSICAL_ADDRESS address;address.QuadPart=(LONGLONG)G90Ranges[i].Base;
  InterlockedIncrement(&G90MapCalls);
  maps[i]=MmMapIoSpaceEx(address,G90Ranges[i].Bytes,PAGE_READONLY|PAGE_NOCACHE);
  if(maps[i]==NULL){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 }
 for(i=0;i<G90_REGISTER_COUNT;i++){
  const G90_FIELD *field=&G90Fields[i];
  out->Values[i]=READ_REGISTER_ULONG((PULONG)((PUCHAR)maps[field->Range]+field->Offset));
 }
 out->Count=G90_REGISTER_COUNT;
 done:
 for(i=RTL_NUMBER_OF(G90Ranges);i>0;i--)if(maps[i-1])MmUnmapIoSpace(maps[i-1],G90Ranges[i-1].Bytes);
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G90MapCalls,0,0);
 return status;
}

static int G90FixedBaseline(const uint32_t*v)
{
 if(G90_REGISTER_COUNT!=50||G90Fields[12].Range!=0||G90Fields[12].Offset!=0xd44||G90Ranges[0].Base!=0x17a20000)return 0;
 for(ULONG i=0;i<50;i++){if(i==12){if(v[i]!=0&&v[i]!=7)return 0;}else if(v[i]!=G90ExpectedValues[i])return 0;}return 1;
}
typedef struct {PVOID Maps[G90_IO_RANGES];ULONG Reads,Writes,Ready;}G90_IO_CONTEXT;
static void G90Unmap(G90_IO_CONTEXT*c)
{for(ULONG i=G90_IO_RANGES;i;i--)if(c->Maps[i-1]){MmUnmapIoSpace(c->Maps[i-1],G90IoRanges[i-1].Bytes);c->Maps[i-1]=NULL;}c->Ready=0;}
static int G90Map(G90_IO_CONTEXT*c)
{
 RtlZeroMemory(c,sizeof(*c));for(ULONG i=0;i<G90_IO_RANGES;i++){
  PHYSICAL_ADDRESS a;a.QuadPart=G90IoRanges[i].Base;InterlockedIncrement(&G90MapCalls);
  c->Maps[i]=MmMapIoSpaceEx(a,G90IoRanges[i].Bytes,(G90IoRanges[i].Writable?PAGE_READWRITE:PAGE_READONLY)|PAGE_NOCACHE);
  if(!c->Maps[i]){G90Unmap(c);return 0;}
 }c->Ready=1;return 1;
}
static PULONG G90Address(G90_IO_CONTEXT*c,ULONG at,ULONG writing,ULONG value)
{
 if(!c->Ready||(at&3)||(writing?!G90IoWriteAllowed(at,value):!G90IoReadAllowed(at)))return NULL;
 for(ULONG i=0;i<G90_IO_RANGES;i++)if(c->Maps[i]&&at>=G90IoRanges[i].Base&&at-G90IoRanges[i].Base<=G90IoRanges[i].Bytes-4){
  if(writing&&!G90IoRanges[i].Writable)return NULL;return(PULONG)((PUCHAR)c->Maps[i]+at-G90IoRanges[i].Base);
 }
 return NULL;
}
static int G90NativeRead(void*context,uint32_t at,uint32_t*v)
{
 G90_IO_CONTEXT*c=context;PULONG p;if(c->Reads>=3000)return 0;p=G90Address(c,at,0,0);if(!p)return 0;c->Reads++;*v=READ_REGISTER_ULONG(p);return 1;
}
static int G90NativeWrite(void*context,uint32_t at,uint32_t value)
{
 G90_IO_CONTEXT*c=context;PULONG p;if(c->Writes>=183)return 0;p=G90Address(c,at,1,value);if(!p)return 0;
 if(at==0xc440ea0||at==0xc441220||at==0xc4456e0){
  if(InterlockedCompareExchange(&G90ObserverFault,0,0))return 0;
  if(at==0xc440ea0){LONG n=InterlockedCompareExchange(&G90TotalObservers,0,0);if(n>=5||InterlockedCompareExchange(&G90TotalObservers,n+1,n)!=n)return 0;}
 }
 c->Writes++;WRITE_REGISTER_ULONG(p,value);return 1;
}
static void G90WaitMs(void*context){LARGE_INTEGER wait;UNREFERENCED_PARAMETER(context);wait.QuadPart=-10000;KeDelayExecutionThread(KernelMode,FALSE,&wait);}
static void G90Wait10(void*context){LARGE_INTEGER wait;UNREFERENCED_PARAMETER(context);wait.QuadPart=-100000;KeDelayExecutionThread(KernelMode,FALSE,&wait);}
static void G90WaitUs(void*context){UNREFERENCED_PARAMETER(context);KeStallExecutionProcessor(1);}
static int G90OffState(const G90_OBS_RESULT*p)
{const UCHAR off[8]={8,7,0,0,7,7,0,0};return !p->Code&&p->Status==0x43&&RtlCompareMemory(p->Configuration,off,8)==8;}
static void G90CapturePmic(G90_PMIC*out)
{
 G90_IO_CONTEXT c;G90_SNAPSHOT before,after;LARGE_INTEGER start,end,freq;LONG previous;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&c,sizeof(c));G90Status(&out->Status);start=KeQueryPerformanceCounter(&freq);out->CounterFrequency=(uint64_t)freq.QuadPart;
 previous=InterlockedCompareExchange(&G90ObserverAttempts,0,0);out->Attempt=(ULONG)previous;
 if(InterlockedCompareExchange(&G90ObserverFault,0,0)){out->Observer.Code=1001;goto done;}
 if(previous>=2||InterlockedCompareExchange(&G90ObserverAttempts,previous+1,previous)!=previous){out->Observer.Code=1002;goto done;}out->Attempt=(ULONG)previous+1;
 InterlockedExchange(&G90PmicVerified,0);
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26300||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Observer.Code=1004;goto done;}
 if(!NT_SUCCESS(G90Snapshot(&before))||!G90FixedBaseline(before.Values)){out->Observer.Code=1005;goto done;}
 if(!G90Map(&c)){out->Observer.Code=1006;goto done;}
 G90_OBS_IO io={&c,G90NativeRead,G90NativeWrite,G90WaitUs};G90Observe(&io,&out->Observer);G90Unmap(&c);
 if(!out->Observer.Code){if(NT_SUCCESS(G90Snapshot(&after))&&RtlCompareMemory(before.Values,after.Values,sizeof(before.Values))==sizeof(before.Values))out->FixedRegistersUnchanged=1;else out->Observer.Code=1007;}
 if(out->Observer.Code)InterlockedExchange(&G90ObserverFault,1);
 else if(out->FixedRegistersUnchanged&&G90OffState(&out->Observer))InterlockedExchange(&G90PmicVerified,1);
 done:G90Unmap(&c);G90Status(&out->Status);end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(uint64_t)(end.QuadPart-start.QuadPart);
}
__attribute__((unused)) static void G90CaptureRun(G90_RUN*out,uint64_t nonce)
{
 G90_IO_CONTEXT c;G90_SNAPSHOT before,after;LARGE_INTEGER start,end,freq;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&c,sizeof(c));out->Nonce=nonce;out->Attempt=1;G90Status(&out->Status);start=KeQueryPerformanceCounter(&freq);out->CounterFrequency=(uint64_t)freq.QuadPart;
 if(!out->Status.FirmwareMatch||out->Status.KernelBuild!=26300||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Power.Code=1004;goto done;}
 if(!InterlockedCompareExchange(&G90PmicVerified,0,0)||InterlockedCompareExchange(&G90ObserverFault,0,0)||InterlockedCompareExchange(&G90ObserverAttempts,0,0)!=1||InterlockedCompareExchange(&G90TotalObservers,0,0)!=1){out->Power.Code=1005;goto done;}
 if(!NT_SUCCESS(G90Snapshot(&before))||!G90FixedBaseline(before.Values)){out->Power.Code=1006;goto done;}
 out->BaselineValid=1;RtlCopyMemory(out->Before,before.Values,sizeof(out->Before));
 if(!G90Map(&c)){out->Power.Code=1007;goto done;}
 InterlockedExchange(&G90PmicVerified,0);
 G90_POWER_IO io={{&c,G90NativeRead,G90NativeWrite,G90WaitMs},{&c,G90NativeRead,G90NativeWrite,G90WaitUs},G90Wait10};G90PowerTrial(&io,&out->Power);G90Unmap(&c);
 if(out->Power.OffVerified&&!out->Power.ObserverUncertain&&(!out->Power.EnableAttempted||(out->Power.LastOffObserveTxn>=out->Power.EnableTxn&&out->Power.LastOffObserveTxn>=out->Power.ReleaseTxn)))InterlockedExchange(&G90PmicVerified,1);
 if(out->Power.ObserverUncertain)InterlockedExchange(&G90ObserverFault,1);
 if(NT_SUCCESS(G90Snapshot(&after))){RtlCopyMemory(out->After,after.Values,sizeof(out->After));if(RtlCompareMemory(out->Before,out->After,sizeof(out->Before))==sizeof(out->Before))out->FixedRegistersUnchanged=1;}
 done:G90Unmap(&c);G90Status(&out->Status);end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(uint64_t)(end.QuadPart-start.QuadPart);
}

VOID G90Control(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 G90_REQUEST*source,in;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR info=0;UNREFERENCED_PARAMETER(queue);
 if(code!=G90_IOCTL_STATUS&&code!=G90_IOCTL_SNAPSHOT&&code!=G90_IOCTL_PMIC){status=STATUS_INVALID_DEVICE_REQUEST;goto complete;}
 if(inputBytes!=sizeof(in)){status=STATUS_INVALID_PARAMETER;goto complete;}
 status=WdfRequestRetrieveInputBuffer(request,sizeof(in),(PVOID*)&source,NULL);if(!NT_SUCCESS(status))goto complete;in=*source;
 if(in.Size!=24||in.Version!=G90_ABI||in.Magic!=G90_MAGIC||in.Nonce){status=STATUS_INVALID_PARAMETER;goto complete;}
 needed=code==G90_IOCTL_STATUS?sizeof(G90_STATUS):code==G90_IOCTL_SNAPSHOT?sizeof(G90_SNAPSHOT):sizeof(G90_PMIC);
 if(outputBytes!=needed){status=STATUS_BUFFER_TOO_SMALL;goto complete;}
 status=WdfRequestRetrieveOutputBuffer(request,needed,&output,NULL);if(!NT_SUCCESS(status))goto complete;
 if(code==G90_IOCTL_STATUS){G90Status(output);status=STATUS_SUCCESS;}
 else if(code==G90_IOCTL_SNAPSHOT)status=G90Snapshot(output);
 else {G90CapturePmic(output);status=STATUS_SUCCESS;}
 if(NT_SUCCESS(status))info=needed;
 complete:WdfRequestCompleteWithInformation(request,status,info);
}
VOID G90FileCreate(WDFDEVICE device,WDFREQUEST request,WDFFILEOBJECT file)
{PUNICODE_STRING name=WdfFileObjectGetFileName(file);UNREFERENCED_PARAMETER(device);WdfRequestComplete(request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);}
VOID G90Unload(WDFDRIVER driver)
{UNREFERENCED_PARAMETER(driver);if(G90Frozen){ExFreePoolWithTag(G90Frozen,'57GO');G90Frozen=NULL;}}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING path)
{
 WDF_DRIVER_CONFIG config;WDFDRIVER driver;PWDFDEVICE_INIT init=NULL;WDFDEVICE device;WDF_OBJECT_ATTRIBUTES attr;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG file;NTSTATUS status;
 DECLARE_CONST_UNICODE_STRING(sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");DECLARE_CONST_UNICODE_STRING(name,L"\\Device\\OpenG90");DECLARE_CONST_UNICODE_STRING(link,L"\\DosDevices\\OpenG90");
 WDF_DRIVER_CONFIG_INIT(&config,WDF_NO_EVENT_CALLBACK);config.DriverInitFlags|=WdfDriverInitNonPnpDriver;config.EvtDriverUnload=G90Unload;
 status=WdfDriverCreate(object,path,WDF_NO_OBJECT_ATTRIBUTES,&config,&driver);if(!NT_SUCCESS(status))return status;
 status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 G90Frozen=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*G90Frozen),'57GO');if(!G90Frozen)return STATUS_INSUFFICIENT_RESOURCES;
 init=WdfControlDeviceInitAllocate(driver,&sddl);if(!init){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&file,G90FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);WdfDeviceInitSetFileObjectConfig(init,&file,WDF_NO_OBJECT_ATTRIBUTES);
 status=WdfDeviceInitAssignName(init,&name);if(!NT_SUCCESS(status))goto done;
 WDF_OBJECT_ATTRIBUTES_INIT(&attr);attr.ExecutionLevel=WdfExecutionLevelPassive;attr.SynchronizationScope=WdfSynchronizationScopeDevice;
 status=WdfDeviceCreate(&init,&attr,&device);if(!NT_SUCCESS(status))goto done;
 status=WdfDeviceCreateSymbolicLink(device,&link);if(!NT_SUCCESS(status))goto done;
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfFalse;queue.EvtIoDeviceControl=G90Control;
 status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))goto done;WdfControlFinishInitializing(device);
 done:if(init)WdfDeviceInitFree(init);if(!NT_SUCCESS(status)&&G90Frozen){ExFreePoolWithTag(G90Frozen,'57GO');G90Frozen=NULL;}return status;
}
