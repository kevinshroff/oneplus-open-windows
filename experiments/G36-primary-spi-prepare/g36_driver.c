/* SPDX-License-Identifier: MIT
 * Temporary source-built KMDF diagnostic. Fixed qualified register/PMIC reads.
 * This control device is not the eventual PnP bus/regulator owner.
 */
#include <ntddk.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g36_binding.h"
#include "g36_observer.h"
#include "g36_spi.h"
#include "g36_protocol.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G36Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G36Control;
EVT_WDF_DEVICE_FILE_CREATE G36FileCreate;
static volatile LONG64 G36Sequence;
static volatile LONG G36MapCalls;
static volatile LONG G36ObserverAttempts;
static volatile LONG G36ObserverFault;
static volatile LONG G36OffPmicVerified;
static volatile LONG G36SpiUsed;

static VOID G36Status(G36_STATUS *out)
{
 UCHAR table[sizeof(G36ExpectedDsdt)];ULONG bytes=0;
 RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=G36_ABI;out->Magic=G36_MAGIC;
 out->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
 out->CurrentIrql=KeGetCurrentIrql();out->RegisterCount=G36_REGISTER_COUNT;
 out->MapCalls=(ULONG)InterlockedCompareExchange(&G36MapCalls,0,0);
 out->Sequence=(ULONGLONG)InterlockedIncrement64(&G36Sequence);out->InterruptTime=KeQueryInterruptTime();
 RtlCopyMemory(out->BuildId,"G36-spi-pad-1",13);
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);
 if(NT_SUCCESS(RtlGetVersion(&version)))out->KernelBuild=version.dwBuildNumber;
 RtlZeroMemory(table,sizeof(table));
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);
 out->FirmwareStatus=(ULONG)status;out->FirmwareBytes=bytes;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G36ExpectedDsdt,sizeof(table))==sizeof(table))out->FirmwareMatch=1;
}

static NTSTATUS G36Snapshot(G36_SNAPSHOT *out)
{
 PVOID maps[RTL_NUMBER_OF(G36Ranges)];NTSTATUS status=STATUS_SUCCESS;ULONG i;
 RtlZeroMemory(out,sizeof(*out));G36Status(&out->Status);
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL)return STATUS_NOT_SUPPORTED;
 RtlZeroMemory(maps,sizeof(maps));
 for(i=0;i<RTL_NUMBER_OF(G36Ranges);i++){
  PHYSICAL_ADDRESS address;address.QuadPart=(LONGLONG)G36Ranges[i].Base;
  InterlockedIncrement(&G36MapCalls);
  maps[i]=MmMapIoSpaceEx(address,G36Ranges[i].Bytes,PAGE_READONLY|PAGE_NOCACHE);
  if(maps[i]==NULL){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 }
 for(i=0;i<G36_REGISTER_COUNT;i++){
  const G36_FIELD *field=&G36Fields[i];
  out->Values[i]=READ_REGISTER_ULONG((PULONG)((PUCHAR)maps[field->Range]+field->Offset));
 }
 out->Count=G36_REGISTER_COUNT;
 done:
 for(i=RTL_NUMBER_OF(G36Ranges);i>0;i--)if(maps[i-1])MmUnmapIoSpace(maps[i-1],G36Ranges[i-1].Bytes);
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G36MapCalls,0,0);
 return status;
}

typedef struct {PVOID Maps[6];} G36_OBS_CONTEXT;
static const ULONG G36ObserverPages[6]={0xc400000,0xc402000,0xc42d000,0xc440000,0xc441000,0xc445000};
static PULONG G36ObserverAddress(G36_OBS_CONTEXT *ctx,ULONG at,BOOLEAN write)
{
 ULONG i;
 if((at&3)!=0)return NULL;
 if(write&&at!=0xc440ea0&&at!=0xc441220&&at!=0xc4456e0)return NULL;
 for(i=0;i<6;i++)if(ctx->Maps[i]&&at>=G36ObserverPages[i]&&at-G36ObserverPages[i]<=0xffc){
  if(write&&i<3)return NULL;
  return(PULONG)((PUCHAR)ctx->Maps[i]+at-G36ObserverPages[i]);
 }
 return NULL;
}
static int G36ObserverRead(void *context,uint32_t at,uint32_t *value)
{
 PULONG reg=G36ObserverAddress((G36_OBS_CONTEXT*)context,at,FALSE);
 if(!reg)return 0;*value=READ_REGISTER_ULONG(reg);return 1;
}
static int G36ObserverWrite(void *context,uint32_t at,uint32_t value)
{
 PULONG reg=G36ObserverAddress((G36_OBS_CONTEXT*)context,at,TRUE);
 if(!reg||!((value==0x08000007)||(value==0x08000080)||(value==0x08000407)))return 0;
 WRITE_REGISTER_ULONG(reg,value);return 1;
}
static void G36ObserverWait(void *context){UNREFERENCED_PARAMETER(context);KeStallExecutionProcessor(1);}
static VOID G36CapturePmic(G36_PMIC *out)
{
 G36_OBS_CONTEXT context;G36_OBS_IO io;G36_SNAPSHOT before,after;
 LARGE_INTEGER begin,end,frequency;LONG previous;ULONG i;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&context,sizeof(context));
 G36Status(&out->Status);begin=KeQueryPerformanceCounter(&frequency);
 out->CounterFrequency=(ULONGLONG)frequency.QuadPart;
 previous=InterlockedCompareExchange(&G36ObserverAttempts,0,0);out->Attempt=(ULONG)previous;
 if(InterlockedCompareExchange(&G36ObserverFault,0,0)){out->Observer.Code=1001;goto done;}
 if(previous>=2){out->Observer.Code=1002;goto done;}
 if(InterlockedCompareExchange(&G36ObserverAttempts,previous+1,previous)!=previous){out->Observer.Code=1003;goto done;}
 out->Attempt=(ULONG)previous+1;
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Observer.Code=1004;goto done;}
 status=G36Snapshot(&before);
 if(!NT_SUCCESS(status)||RtlCompareMemory(before.Values,G36ExpectedValues,sizeof(before.Values))!=sizeof(before.Values)){
  out->Observer.Code=1005;goto done;
 }
 for(i=0;i<6;i++){
  PHYSICAL_ADDRESS at;at.QuadPart=G36ObserverPages[i];InterlockedIncrement(&G36MapCalls);
  context.Maps[i]=MmMapIoSpaceEx(at,0x1000,(i<3?PAGE_READONLY:PAGE_READWRITE)|PAGE_NOCACHE);
  if(!context.Maps[i]){out->Observer.Code=1006;goto done;}
 }
 io.Context=&context;io.Read=G36ObserverRead;io.Write=G36ObserverWrite;io.WaitMicrosecond=G36ObserverWait;
 G36Observe(&io,&out->Observer);
 done:
 for(i=6;i>0;i--)if(context.Maps[i-1])MmUnmapIoSpace(context.Maps[i-1],0x1000);
 if(out->Attempt==(ULONG)previous+1){
  if(out->Observer.Code==0){
   status=G36Snapshot(&after);
   if(NT_SUCCESS(status)&&RtlCompareMemory(before.Values,after.Values,sizeof(before.Values))==sizeof(before.Values))out->FixedRegistersUnchanged=1;
   else out->Observer.Code=1007;
  }
  if(out->Observer.Code!=0)InterlockedExchange(&G36ObserverFault,1);
 }
 if(out->Observer.Code==0&&out->FixedRegistersUnchanged){
  static const UCHAR off[8]={8,7,0,0,7,7,0,0};
  InterlockedExchange(&G36OffPmicVerified,out->Observer.Status==0x43&&RtlCompareMemory(out->Observer.Configuration,off,8)==8);
 }
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G36MapCalls,0,0);
 end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(ULONGLONG)(end.QuadPart-begin.QuadPart);
}

static const G36_RANGE G36SpiRanges[6]={{0x152000,0x1000},{0x118000,0x1000},{0x123000,0x1000},{0xf12c000,0x4000},{0xa90000,0x1000},{0xac0000,0x1000}};
static PULONG G36SpiAddress(G36_OBS_CONTEXT *ctx,ULONG at,BOOLEAN write)
{
 ULONG i;
 if((at&3)!=0)return NULL;
 if(write&&at!=0x152008&&at!=0xf12c000&&at!=0xf12d000&&at!=0xf12e000&&at!=0xf12f000)return NULL;
 for(i=0;i<6;i++)if(ctx->Maps[i]&&at>=G36SpiRanges[i].Base&&at-G36SpiRanges[i].Base+4<=G36SpiRanges[i].Bytes){
  if(write&&i!=0&&i!=3)return NULL;
  return(PULONG)((PUCHAR)ctx->Maps[i]+at-G36SpiRanges[i].Base);
 }
 return NULL;
}
static int G36SpiRead(void *context,uint32_t at,uint32_t *value)
{
 PULONG reg=G36SpiAddress((G36_OBS_CONTEXT*)context,at,FALSE);
 if(!reg)return 0;*value=READ_REGISTER_ULONG(reg);return 1;
}
static int G36SpiWrite(void *context,uint32_t at,uint32_t value)
{
 PULONG reg=G36SpiAddress((G36_OBS_CONTEXT*)context,at,TRUE);
 if(!reg)return 0;
 if(at==0x152008){if(value!=0x40002380&&value!=0x40102380&&value!=0x40302380&&value!=0x44302380)return 0;}
 else if(value!=1&&value!=0x85)return 0;
 WRITE_REGISTER_ULONG(reg,value);return 1;
}
static VOID G36CaptureSpi(G36_SPI *out)
{
 G36_OBS_CONTEXT context;G36_SPI_IO io;G36_SNAPSHOT before,after;
 LARGE_INTEGER begin,end,frequency;ULONG i;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&context,sizeof(context));G36Status(&out->Status);
 begin=KeQueryPerformanceCounter(&frequency);out->CounterFrequency=(ULONGLONG)frequency.QuadPart;
 if(InterlockedCompareExchange(&G36SpiUsed,1,0)!=0){out->Spi.Code=1002;goto done;}
 out->Attempt=1;
 if(InterlockedCompareExchange(&G36ObserverAttempts,0,0)!=1||!InterlockedCompareExchange(&G36OffPmicVerified,0,0)||InterlockedCompareExchange(&G36ObserverFault,0,0)){
  out->Spi.Code=1003;goto done;
 }
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Spi.Code=1004;goto done;}
 status=G36Snapshot(&before);
 if(!NT_SUCCESS(status)||RtlCompareMemory(before.Values,G36ExpectedValues,sizeof(before.Values))!=sizeof(before.Values)){out->Spi.Code=1005;goto done;}
 for(i=0;i<6;i++){
  PHYSICAL_ADDRESS at;at.QuadPart=(LONGLONG)G36SpiRanges[i].Base;InterlockedIncrement(&G36MapCalls);
  context.Maps[i]=MmMapIoSpaceEx(at,G36SpiRanges[i].Bytes,((i==0||i==3)?PAGE_READWRITE:PAGE_READONLY)|PAGE_NOCACHE);
  if(!context.Maps[i]){out->Spi.Code=1006;goto done;}
 }
 io.Context=&context;io.Read=G36SpiRead;io.Write=G36SpiWrite;io.WaitMicrosecond=G36ObserverWait;
 G36PrepareSpi(&io,&out->Spi);
 done:
 for(i=6;i>0;i--)if(context.Maps[i-1])MmUnmapIoSpace(context.Maps[i-1],G36SpiRanges[i-1].Bytes);
 if(out->Spi.Code<1000){
  status=G36Snapshot(&after);
  if(NT_SUCCESS(status)&&RtlCompareMemory(before.Values,after.Values,sizeof(before.Values))==sizeof(before.Values))out->FixedRegistersUnchanged=1;
  else out->Spi.Code=1007;
 }
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G36MapCalls,0,0);
 end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(ULONGLONG)(end.QuadPart-begin.QuadPart);
}

VOID G36Control(WDFQUEUE Queue,WDFREQUEST Request,size_t OutputLength,size_t InputLength,ULONG Code)
{
 G36_REQUEST *input;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;
 UNREFERENCED_PARAMETER(Queue);
 if(Code!=G36_IOCTL_STATUS&&Code!=G36_IOCTL_SNAPSHOT&&Code!=G36_IOCTL_PMIC&&Code!=G36_IOCTL_SPI){status=STATUS_INVALID_DEVICE_REQUEST;goto complete;}
 if(InputLength!=sizeof(G36_REQUEST)){status=STATUS_INVALID_PARAMETER;goto complete;}
 status=WdfRequestRetrieveInputBuffer(Request,sizeof(G36_REQUEST),(PVOID*)&input,NULL);
 if(!NT_SUCCESS(status))goto complete;
 if(input->Size!=sizeof(*input)||input->Version!=G36_ABI||input->Magic!=G36_MAGIC){status=STATUS_INVALID_PARAMETER;goto complete;}
 needed=Code==G36_IOCTL_STATUS?sizeof(G36_STATUS):Code==G36_IOCTL_SNAPSHOT?sizeof(G36_SNAPSHOT):Code==G36_IOCTL_PMIC?sizeof(G36_PMIC):sizeof(G36_SPI);
 if(OutputLength<needed){status=STATUS_BUFFER_TOO_SMALL;goto complete;}
 status=WdfRequestRetrieveOutputBuffer(Request,needed,&output,NULL);if(!NT_SUCCESS(status))goto complete;
 if(Code==G36_IOCTL_STATUS){G36Status((G36_STATUS*)output);status=STATUS_SUCCESS;}
 else if(Code==G36_IOCTL_PMIC){G36CapturePmic((G36_PMIC*)output);status=STATUS_SUCCESS;}
 else if(Code==G36_IOCTL_SPI){G36CaptureSpi((G36_SPI*)output);status=STATUS_SUCCESS;}
 else status=G36Snapshot((G36_SNAPSHOT*)output);
 if(NT_SUCCESS(status))information=needed;
 complete:WdfRequestCompleteWithInformation(Request,status,information);
}
VOID G36FileCreate(WDFDEVICE Device,WDFREQUEST Request,WDFFILEOBJECT FileObject)
{
 PUNICODE_STRING name=WdfFileObjectGetFileName(FileObject);UNREFERENCED_PARAMETER(Device);
 WdfRequestComplete(Request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);
}
VOID G36Unload(WDFDRIVER Driver){UNREFERENCED_PARAMETER(Driver);}
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath)
{
 WDF_DRIVER_CONFIG config;WDFDRIVER driver;PWDFDEVICE_INIT init=NULL;WDFDEVICE device;
 WDF_OBJECT_ATTRIBUTES attributes;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG files;NTSTATUS status;
 DECLARE_CONST_UNICODE_STRING(sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
 DECLARE_CONST_UNICODE_STRING(name,L"\\Device\\OpenG36");
 DECLARE_CONST_UNICODE_STRING(link,L"\\DosDevices\\OpenG36");
 WDF_DRIVER_CONFIG_INIT(&config,WDF_NO_EVENT_CALLBACK);config.DriverInitFlags|=WdfDriverInitNonPnpDriver;config.EvtDriverUnload=G36Unload;
 status=WdfDriverCreate(DriverObject,RegistryPath,WDF_NO_OBJECT_ATTRIBUTES,&config,&driver);if(!NT_SUCCESS(status))return status;
 status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 init=WdfControlDeviceInitAllocate(driver,&sddl);if(!init)return STATUS_INSUFFICIENT_RESOURCES;
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);
 WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&files,G36FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);
 WdfDeviceInitSetFileObjectConfig(init,&files,WDF_NO_OBJECT_ATTRIBUTES);
 status=WdfDeviceInitAssignName(init,&name);if(!NT_SUCCESS(status))goto done;
 WDF_OBJECT_ATTRIBUTES_INIT(&attributes);attributes.ExecutionLevel=WdfExecutionLevelPassive;attributes.SynchronizationScope=WdfSynchronizationScopeDevice;
 status=WdfDeviceCreate(&init,&attributes,&device);if(!NT_SUCCESS(status))goto done;
 status=WdfDeviceCreateSymbolicLink(device,&link);if(!NT_SUCCESS(status))goto done;
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfFalse;queue.EvtIoDeviceControl=G36Control;
 status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))goto done;
 WdfControlFinishInitializing(device);
 done:if(init)WdfDeviceInitFree(init);return status;
}
