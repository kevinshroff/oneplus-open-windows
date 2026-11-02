/* SPDX-License-Identifier: MIT
 * Temporary source-built KMDF diagnostic. Fixed qualified register/PMIC reads.
 * This control device is not the eventual PnP bus/regulator owner.
 */
#include <ntddk.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g38_binding.h"
#include "g38_observer.h"
#include "g38_power.h"
#include "g38_protocol.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G38Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G38Control;
EVT_WDF_DEVICE_FILE_CREATE G38FileCreate;
static volatile LONG64 G38Sequence;
static volatile LONG G38MapCalls;
static volatile LONG G38ObserverAttempts;
static volatile LONG G38ObserverFault;
static volatile LONG G38OffPmicVerified;
static volatile LONG G38PowerUsed;

static VOID G38Status(G38_STATUS *out)
{
 UCHAR table[sizeof(G38ExpectedDsdt)];ULONG bytes=0;
 RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=G38_ABI;out->Magic=G38_MAGIC;
 out->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
 out->CurrentIrql=KeGetCurrentIrql();out->RegisterCount=G38_REGISTER_COUNT;
 out->MapCalls=(ULONG)InterlockedCompareExchange(&G38MapCalls,0,0);
 out->Sequence=(ULONGLONG)InterlockedIncrement64(&G38Sequence);out->InterruptTime=KeQueryInterruptTime();
 RtlCopyMemory(out->BuildId,"G38-rsc-pwr-1",13);
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);
 if(NT_SUCCESS(RtlGetVersion(&version)))out->KernelBuild=version.dwBuildNumber;
 RtlZeroMemory(table,sizeof(table));
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);
 out->FirmwareStatus=(ULONG)status;out->FirmwareBytes=bytes;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G38ExpectedDsdt,sizeof(table))==sizeof(table))out->FirmwareMatch=1;
}

static NTSTATUS G38Snapshot(G38_SNAPSHOT *out)
{
 PVOID maps[RTL_NUMBER_OF(G38Ranges)];NTSTATUS status=STATUS_SUCCESS;ULONG i;
 RtlZeroMemory(out,sizeof(*out));G38Status(&out->Status);
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL)return STATUS_NOT_SUPPORTED;
 RtlZeroMemory(maps,sizeof(maps));
 for(i=0;i<RTL_NUMBER_OF(G38Ranges);i++){
  PHYSICAL_ADDRESS address;address.QuadPart=(LONGLONG)G38Ranges[i].Base;
  InterlockedIncrement(&G38MapCalls);
  maps[i]=MmMapIoSpaceEx(address,G38Ranges[i].Bytes,PAGE_READONLY|PAGE_NOCACHE);
  if(maps[i]==NULL){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 }
 for(i=0;i<G38_REGISTER_COUNT;i++){
  const G38_FIELD *field=&G38Fields[i];
  out->Values[i]=READ_REGISTER_ULONG((PULONG)((PUCHAR)maps[field->Range]+field->Offset));
 }
 out->Count=G38_REGISTER_COUNT;
 done:
 for(i=RTL_NUMBER_OF(G38Ranges);i>0;i--)if(maps[i-1])MmUnmapIoSpace(maps[i-1],G38Ranges[i-1].Bytes);
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G38MapCalls,0,0);
 return status;
}

typedef struct {PVOID Maps[7];} G38_OBS_CONTEXT;
static const ULONG G38ObserverPages[6]={0xc400000,0xc402000,0xc42d000,0xc440000,0xc441000,0xc445000};
static PULONG G38ObserverAddress(G38_OBS_CONTEXT *ctx,ULONG at,BOOLEAN write)
{
 ULONG i;
 if((at&3)!=0)return NULL;
 if(write&&at!=0xc440ea0&&at!=0xc441220&&at!=0xc4456e0)return NULL;
 for(i=0;i<6;i++)if(ctx->Maps[i]&&at>=G38ObserverPages[i]&&at-G38ObserverPages[i]<=0xffc){
  if(write&&i<3)return NULL;
  return(PULONG)((PUCHAR)ctx->Maps[i]+at-G38ObserverPages[i]);
 }
 return NULL;
}
static int G38ObserverRead(void *context,uint32_t at,uint32_t *value)
{
 PULONG reg=G38ObserverAddress((G38_OBS_CONTEXT*)context,at,FALSE);
 if(!reg)return 0;*value=READ_REGISTER_ULONG(reg);return 1;
}
static int G38ObserverWrite(void *context,uint32_t at,uint32_t value)
{
 PULONG reg=G38ObserverAddress((G38_OBS_CONTEXT*)context,at,TRUE);
 if(!reg||!((value==0x08000007)||(value==0x08000080)||(value==0x08000407)))return 0;
 WRITE_REGISTER_ULONG(reg,value);return 1;
}
static void G38ObserverWait(void *context){UNREFERENCED_PARAMETER(context);KeStallExecutionProcessor(1);}
static VOID G38CapturePmic(G38_PMIC *out)
{
 G38_OBS_CONTEXT context;G38_OBS_IO io;G38_SNAPSHOT before,after;
 LARGE_INTEGER begin,end,frequency;LONG previous;ULONG i;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&context,sizeof(context));
 G38Status(&out->Status);begin=KeQueryPerformanceCounter(&frequency);
 out->CounterFrequency=(ULONGLONG)frequency.QuadPart;
 previous=InterlockedCompareExchange(&G38ObserverAttempts,0,0);out->Attempt=(ULONG)previous;
 if(InterlockedCompareExchange(&G38ObserverFault,0,0)){out->Observer.Code=1001;goto done;}
 if(previous>=2){out->Observer.Code=1002;goto done;}
 if(InterlockedCompareExchange(&G38ObserverAttempts,previous+1,previous)!=previous){out->Observer.Code=1003;goto done;}
 out->Attempt=(ULONG)previous+1;
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Observer.Code=1004;goto done;}
 status=G38Snapshot(&before);
 if(!NT_SUCCESS(status)||RtlCompareMemory(before.Values,G38ExpectedValues,sizeof(before.Values))!=sizeof(before.Values)){
  out->Observer.Code=1005;goto done;
 }
 for(i=0;i<6;i++){
  PHYSICAL_ADDRESS at;at.QuadPart=G38ObserverPages[i];InterlockedIncrement(&G38MapCalls);
  context.Maps[i]=MmMapIoSpaceEx(at,0x1000,(i<3?PAGE_READONLY:PAGE_READWRITE)|PAGE_NOCACHE);
  if(!context.Maps[i]){out->Observer.Code=1006;goto done;}
 }
 io.Context=&context;io.Read=G38ObserverRead;io.Write=G38ObserverWrite;io.WaitMicrosecond=G38ObserverWait;
 G38Observe(&io,&out->Observer);
 done:
 for(i=6;i>0;i--)if(context.Maps[i-1])MmUnmapIoSpace(context.Maps[i-1],0x1000);
 if(out->Attempt==(ULONG)previous+1){
  if(out->Observer.Code==0){
   status=G38Snapshot(&after);
   if(NT_SUCCESS(status)&&RtlCompareMemory(before.Values,after.Values,sizeof(before.Values))==sizeof(before.Values))out->FixedRegistersUnchanged=1;
   else out->Observer.Code=1007;
  }
  if(out->Observer.Code!=0)InterlockedExchange(&G38ObserverFault,1);
 }
 if(out->Observer.Code==0&&out->FixedRegistersUnchanged){
  static const UCHAR off[8]={8,7,0,0,7,7,0,0};
  InterlockedExchange(&G38OffPmicVerified,out->Observer.Status==0x43&&RtlCompareMemory(out->Observer.Configuration,off,8)==8);
 }
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G38MapCalls,0,0);
 end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(ULONGLONG)(end.QuadPart-begin.QuadPart);
}

typedef struct {PVOID Maps[10];G38_POWER_RESULT*Result;} G38_PWR_CONTEXT;
static const G38_RANGE G38PowerRanges[10]={{0x17a20000,0x2000},{0x17100000,0x1000},{0xf10a000,0x1000},{0xf118000,0x2000},{0xc400000,0x1000},{0xc402000,0x1000},{0xc42d000,0x1000},{0xc440000,0x1000},{0xc441000,0x1000},{0xc445000,0x1000}};
static PULONG G38PowerAddress(G38_PWR_CONTEXT*ctx,ULONG at,BOOLEAN write)
{
 ULONG i;if(at&3)return NULL;
 if(write&&at!=0xc440ea0&&at!=0xc441220&&at!=0xc4456e0&&
 at!=0x17a20d34&&at!=0x17a20d38&&at!=0x17a20d3c&&at!=0x17a20d24&&at!=0x17a20d2c&&at!=0x17a20d08)return NULL;
 for(i=0;i<10;i++)if(ctx->Maps[i]&&at>=G38PowerRanges[i].Base&&at-G38PowerRanges[i].Base+4<=G38PowerRanges[i].Bytes){
  if(write&&i!=0&&i<7)return NULL;
  return(PULONG)((PUCHAR)ctx->Maps[i]+at-G38PowerRanges[i].Base);
 }
 return NULL;
}
static int G38PowerRead(void*context,uint32_t at,uint32_t*value)
{
 PULONG reg=G38PowerAddress((G38_PWR_CONTEXT*)context,at,FALSE);if(!reg)return 0;*value=READ_REGISTER_ULONG(reg);return 1;
}
static int G38PowerWrite(void*context,uint32_t at,uint32_t value)
{
 PULONG reg=G38PowerAddress((G38_PWR_CONTEXT*)context,at,TRUE);if(!reg)return 0;
 if(at==0xc440ea0||at==0xc441220||at==0xc4456e0){if(value!=0x08000007&&value!=0x08000080&&value!=0x08000407)return 0;}
 else if(!G38RscWriteAllowed(at,value))return 0;
 WRITE_REGISTER_ULONG(reg,value);return 1;
}
static void G38PowerWait1(void*context)
{
 G38_PWR_CONTEXT*ctx=context;LARGE_INTEGER wait;ctx->Result->Waits1ms++;wait.QuadPart=-10000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}
static void G38PowerWait10(void*context)
{
 LARGE_INTEGER wait;UNREFERENCED_PARAMETER(context);wait.QuadPart=-100000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}
static VOID G38CapturePower(G38_POWER*out)
{
 G38_PWR_CONTEXT context;G38_POWER_IO io;G38_SNAPSHOT before,after;
 LARGE_INTEGER begin,end,frequency;ULONG i;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&context,sizeof(context));G38Status(&out->Status);context.Result=&out->Power;
 begin=KeQueryPerformanceCounter(&frequency);out->CounterFrequency=(ULONGLONG)frequency.QuadPart;
 if(InterlockedCompareExchange(&G38PowerUsed,1,0)!=0){out->Power.Code=1002;goto done;}
 out->Attempt=1;
 if(InterlockedCompareExchange(&G38ObserverAttempts,0,0)!=1||!InterlockedCompareExchange(&G38OffPmicVerified,0,0)||InterlockedCompareExchange(&G38ObserverFault,0,0)){out->Power.Code=1003;goto done;}
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Power.Code=1004;goto done;}
 status=G38Snapshot(&before);
 if(!NT_SUCCESS(status)||RtlCompareMemory(before.Values,G38ExpectedValues,sizeof(before.Values))!=sizeof(before.Values)){out->Power.Code=1005;goto done;}
 for(i=0;i<10;i++){
  PHYSICAL_ADDRESS at;at.QuadPart=(LONGLONG)G38PowerRanges[i].Base;InterlockedIncrement(&G38MapCalls);
  context.Maps[i]=MmMapIoSpaceEx(at,G38PowerRanges[i].Bytes,(i==0||i>=7?PAGE_READWRITE:PAGE_READONLY)|PAGE_NOCACHE);
  if(!context.Maps[i]){out->Power.Code=1006;goto done;}
 }
 io.Rsc.Context=&context;io.Rsc.Read=G38PowerRead;io.Rsc.Write=G38PowerWrite;io.Rsc.WaitMillisecond=G38PowerWait1;
 io.Observer.Context=&context;io.Observer.Read=G38PowerRead;io.Observer.Write=G38PowerWrite;io.Observer.WaitMicrosecond=G38ObserverWait;io.WaitTenMilliseconds=G38PowerWait10;
 G38PowerTrial(&io,&out->Power);
 done:
 for(i=10;i>0;i--)if(context.Maps[i-1])MmUnmapIoSpace(context.Maps[i-1],G38PowerRanges[i-1].Bytes);
 if(out->Power.Code<1000){
  status=G38Snapshot(&after);
  if(NT_SUCCESS(status)&&RtlCompareMemory(before.Values,after.Values,sizeof(before.Values))==sizeof(before.Values))out->FixedRegistersUnchanged=1;
  else if(!out->Power.Code)out->Power.Code=1007;
 }
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G38MapCalls,0,0);
 end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(ULONGLONG)(end.QuadPart-begin.QuadPart);
}

VOID G38Control(WDFQUEUE Queue,WDFREQUEST Request,size_t OutputLength,size_t InputLength,ULONG Code)
{
 G38_REQUEST *input;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;
 UNREFERENCED_PARAMETER(Queue);
 if(Code!=G38_IOCTL_STATUS&&Code!=G38_IOCTL_SNAPSHOT&&Code!=G38_IOCTL_PMIC&&Code!=G38_IOCTL_POWER){status=STATUS_INVALID_DEVICE_REQUEST;goto complete;}
 if(InputLength!=sizeof(G38_REQUEST)){status=STATUS_INVALID_PARAMETER;goto complete;}
 status=WdfRequestRetrieveInputBuffer(Request,sizeof(G38_REQUEST),(PVOID*)&input,NULL);
 if(!NT_SUCCESS(status))goto complete;
 if(input->Size!=sizeof(*input)||input->Version!=G38_ABI||input->Magic!=G38_MAGIC){status=STATUS_INVALID_PARAMETER;goto complete;}
 needed=Code==G38_IOCTL_STATUS?sizeof(G38_STATUS):Code==G38_IOCTL_SNAPSHOT?sizeof(G38_SNAPSHOT):Code==G38_IOCTL_PMIC?sizeof(G38_PMIC):sizeof(G38_POWER);
 if(OutputLength<needed){status=STATUS_BUFFER_TOO_SMALL;goto complete;}
 status=WdfRequestRetrieveOutputBuffer(Request,needed,&output,NULL);if(!NT_SUCCESS(status))goto complete;
 if(Code==G38_IOCTL_STATUS){G38Status((G38_STATUS*)output);status=STATUS_SUCCESS;}
 else if(Code==G38_IOCTL_PMIC){G38CapturePmic((G38_PMIC*)output);status=STATUS_SUCCESS;}
 else if(Code==G38_IOCTL_POWER){G38CapturePower((G38_POWER*)output);status=STATUS_SUCCESS;}
 else status=G38Snapshot((G38_SNAPSHOT*)output);
 if(NT_SUCCESS(status))information=needed;
 complete:WdfRequestCompleteWithInformation(Request,status,information);
}
VOID G38FileCreate(WDFDEVICE Device,WDFREQUEST Request,WDFFILEOBJECT FileObject)
{
 PUNICODE_STRING name=WdfFileObjectGetFileName(FileObject);UNREFERENCED_PARAMETER(Device);
 WdfRequestComplete(Request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);
}
VOID G38Unload(WDFDRIVER Driver){UNREFERENCED_PARAMETER(Driver);}
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath)
{
 WDF_DRIVER_CONFIG config;WDFDRIVER driver;PWDFDEVICE_INIT init=NULL;WDFDEVICE device;
 WDF_OBJECT_ATTRIBUTES attributes;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG files;NTSTATUS status;
 DECLARE_CONST_UNICODE_STRING(sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
 DECLARE_CONST_UNICODE_STRING(name,L"\\Device\\OpenG38");
 DECLARE_CONST_UNICODE_STRING(link,L"\\DosDevices\\OpenG38");
 WDF_DRIVER_CONFIG_INIT(&config,WDF_NO_EVENT_CALLBACK);config.DriverInitFlags|=WdfDriverInitNonPnpDriver;config.EvtDriverUnload=G38Unload;
 status=WdfDriverCreate(DriverObject,RegistryPath,WDF_NO_OBJECT_ATTRIBUTES,&config,&driver);if(!NT_SUCCESS(status))return status;
 status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 init=WdfControlDeviceInitAllocate(driver,&sddl);if(!init)return STATUS_INSUFFICIENT_RESOURCES;
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);
 WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&files,G38FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);
 WdfDeviceInitSetFileObjectConfig(init,&files,WDF_NO_OBJECT_ATTRIBUTES);
 status=WdfDeviceInitAssignName(init,&name);if(!NT_SUCCESS(status))goto done;
 WDF_OBJECT_ATTRIBUTES_INIT(&attributes);attributes.ExecutionLevel=WdfExecutionLevelPassive;attributes.SynchronizationScope=WdfSynchronizationScopeDevice;
 status=WdfDeviceCreate(&init,&attributes,&device);if(!NT_SUCCESS(status))goto done;
 status=WdfDeviceCreateSymbolicLink(device,&link);if(!NT_SUCCESS(status))goto done;
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfFalse;queue.EvtIoDeviceControl=G38Control;
 status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))goto done;
 WdfControlFinishInitializing(device);
 done:if(init)WdfDeviceInitFree(init);return status;
}
