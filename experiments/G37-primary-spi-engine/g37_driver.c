/* SPDX-License-Identifier: MIT
 * Temporary source-built KMDF diagnostic. Fixed qualified register/PMIC reads.
 * This control device is not the eventual PnP bus/regulator owner.
 */
#include <ntddk.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g37_binding.h"
#include "g37_observer.h"
#include "g37_spi.h"
#include "g37_protocol.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G37Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G37Control;
EVT_WDF_DEVICE_FILE_CREATE G37FileCreate;
static volatile LONG64 G37Sequence;
static volatile LONG G37MapCalls;
static volatile LONG G37ObserverAttempts;
static volatile LONG G37ObserverFault;
static volatile LONG G37OffPmicVerified;
static volatile LONG G37SpiUsed;

static VOID G37Status(G37_STATUS *out)
{
 UCHAR table[sizeof(G37ExpectedDsdt)];ULONG bytes=0;
 RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=G37_ABI;out->Magic=G37_MAGIC;
 out->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
 out->CurrentIrql=KeGetCurrentIrql();out->RegisterCount=G37_REGISTER_COUNT;
 out->MapCalls=(ULONG)InterlockedCompareExchange(&G37MapCalls,0,0);
 out->Sequence=(ULONGLONG)InterlockedIncrement64(&G37Sequence);out->InterruptTime=KeQueryInterruptTime();
 RtlCopyMemory(out->BuildId,"G37-spi-eng-1",13);
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);
 if(NT_SUCCESS(RtlGetVersion(&version)))out->KernelBuild=version.dwBuildNumber;
 RtlZeroMemory(table,sizeof(table));
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);
 out->FirmwareStatus=(ULONG)status;out->FirmwareBytes=bytes;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G37ExpectedDsdt,sizeof(table))==sizeof(table))out->FirmwareMatch=1;
}

static NTSTATUS G37Snapshot(G37_SNAPSHOT *out)
{
 PVOID maps[RTL_NUMBER_OF(G37Ranges)];NTSTATUS status=STATUS_SUCCESS;ULONG i;
 RtlZeroMemory(out,sizeof(*out));G37Status(&out->Status);
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL)return STATUS_NOT_SUPPORTED;
 RtlZeroMemory(maps,sizeof(maps));
 for(i=0;i<RTL_NUMBER_OF(G37Ranges);i++){
  PHYSICAL_ADDRESS address;address.QuadPart=(LONGLONG)G37Ranges[i].Base;
  InterlockedIncrement(&G37MapCalls);
  maps[i]=MmMapIoSpaceEx(address,G37Ranges[i].Bytes,PAGE_READONLY|PAGE_NOCACHE);
  if(maps[i]==NULL){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 }
 for(i=0;i<G37_REGISTER_COUNT;i++){
  const G37_FIELD *field=&G37Fields[i];
  out->Values[i]=READ_REGISTER_ULONG((PULONG)((PUCHAR)maps[field->Range]+field->Offset));
 }
 out->Count=G37_REGISTER_COUNT;
 done:
 for(i=RTL_NUMBER_OF(G37Ranges);i>0;i--)if(maps[i-1])MmUnmapIoSpace(maps[i-1],G37Ranges[i-1].Bytes);
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G37MapCalls,0,0);
 return status;
}

typedef struct {PVOID Maps[7];} G37_OBS_CONTEXT;
static const ULONG G37ObserverPages[6]={0xc400000,0xc402000,0xc42d000,0xc440000,0xc441000,0xc445000};
static PULONG G37ObserverAddress(G37_OBS_CONTEXT *ctx,ULONG at,BOOLEAN write)
{
 ULONG i;
 if((at&3)!=0)return NULL;
 if(write&&at!=0xc440ea0&&at!=0xc441220&&at!=0xc4456e0)return NULL;
 for(i=0;i<6;i++)if(ctx->Maps[i]&&at>=G37ObserverPages[i]&&at-G37ObserverPages[i]<=0xffc){
  if(write&&i<3)return NULL;
  return(PULONG)((PUCHAR)ctx->Maps[i]+at-G37ObserverPages[i]);
 }
 return NULL;
}
static int G37ObserverRead(void *context,uint32_t at,uint32_t *value)
{
 PULONG reg=G37ObserverAddress((G37_OBS_CONTEXT*)context,at,FALSE);
 if(!reg)return 0;*value=READ_REGISTER_ULONG(reg);return 1;
}
static int G37ObserverWrite(void *context,uint32_t at,uint32_t value)
{
 PULONG reg=G37ObserverAddress((G37_OBS_CONTEXT*)context,at,TRUE);
 if(!reg||!((value==0x08000007)||(value==0x08000080)||(value==0x08000407)))return 0;
 WRITE_REGISTER_ULONG(reg,value);return 1;
}
static void G37ObserverWait(void *context){UNREFERENCED_PARAMETER(context);KeStallExecutionProcessor(1);}
static VOID G37CapturePmic(G37_PMIC *out)
{
 G37_OBS_CONTEXT context;G37_OBS_IO io;G37_SNAPSHOT before,after;
 LARGE_INTEGER begin,end,frequency;LONG previous;ULONG i;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&context,sizeof(context));
 G37Status(&out->Status);begin=KeQueryPerformanceCounter(&frequency);
 out->CounterFrequency=(ULONGLONG)frequency.QuadPart;
 previous=InterlockedCompareExchange(&G37ObserverAttempts,0,0);out->Attempt=(ULONG)previous;
 if(InterlockedCompareExchange(&G37ObserverFault,0,0)){out->Observer.Code=1001;goto done;}
 if(previous>=2){out->Observer.Code=1002;goto done;}
 if(InterlockedCompareExchange(&G37ObserverAttempts,previous+1,previous)!=previous){out->Observer.Code=1003;goto done;}
 out->Attempt=(ULONG)previous+1;
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Observer.Code=1004;goto done;}
 status=G37Snapshot(&before);
 if(!NT_SUCCESS(status)||RtlCompareMemory(before.Values,G37ExpectedValues,sizeof(before.Values))!=sizeof(before.Values)){
  out->Observer.Code=1005;goto done;
 }
 for(i=0;i<6;i++){
  PHYSICAL_ADDRESS at;at.QuadPart=G37ObserverPages[i];InterlockedIncrement(&G37MapCalls);
  context.Maps[i]=MmMapIoSpaceEx(at,0x1000,(i<3?PAGE_READONLY:PAGE_READWRITE)|PAGE_NOCACHE);
  if(!context.Maps[i]){out->Observer.Code=1006;goto done;}
 }
 io.Context=&context;io.Read=G37ObserverRead;io.Write=G37ObserverWrite;io.WaitMicrosecond=G37ObserverWait;
 G37Observe(&io,&out->Observer);
 done:
 for(i=6;i>0;i--)if(context.Maps[i-1])MmUnmapIoSpace(context.Maps[i-1],0x1000);
 if(out->Attempt==(ULONG)previous+1){
  if(out->Observer.Code==0){
   status=G37Snapshot(&after);
   if(NT_SUCCESS(status)&&RtlCompareMemory(before.Values,after.Values,sizeof(before.Values))==sizeof(before.Values))out->FixedRegistersUnchanged=1;
   else out->Observer.Code=1007;
  }
  if(out->Observer.Code!=0)InterlockedExchange(&G37ObserverFault,1);
 }
 if(out->Observer.Code==0&&out->FixedRegistersUnchanged){
  static const UCHAR off[8]={8,7,0,0,7,7,0,0};
  InterlockedExchange(&G37OffPmicVerified,out->Observer.Status==0x43&&RtlCompareMemory(out->Observer.Configuration,off,8)==8);
 }
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G37MapCalls,0,0);
 end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(ULONGLONG)(end.QuadPart-begin.QuadPart);
}

static const G37_RANGE G37SpiRanges[7]={{0x152000,0x1000},{0x118000,0x1000},{0x123000,0x1000},{0xf12c000,0x4000},{0xa90000,0x1000},{0xac0000,0x1000},{0x17100000,0x1000}};
static PULONG G37SpiAddress(G37_OBS_CONTEXT *ctx,ULONG at,BOOLEAN write)
{
 ULONG i;
 if((at&3)!=0)return NULL;
 if(write&&at!=0x152008&&at!=0xf12c000&&at!=0xf12d000&&at!=0xf12e000&&at!=0xf12f000&&!G37EngineWriteAddress(at))return NULL;
 for(i=0;i<7;i++)if(ctx->Maps[i]&&at>=G37SpiRanges[i].Base&&at-G37SpiRanges[i].Base+4<=G37SpiRanges[i].Bytes){
  if(write&&i!=0&&i!=3&&i!=4)return NULL;
  return(PULONG)((PUCHAR)ctx->Maps[i]+at-G37SpiRanges[i].Base);
 }
 return NULL;
}
static int G37SpiRead(void *context,uint32_t at,uint32_t *value)
{
 PULONG reg=G37SpiAddress((G37_OBS_CONTEXT*)context,at,FALSE);
 if(!reg)return 0;*value=READ_REGISTER_ULONG(reg);return 1;
}
static int G37SpiWrite(void *context,uint32_t at,uint32_t value)
{
 PULONG reg=G37SpiAddress((G37_OBS_CONTEXT*)context,at,TRUE);
 if(!reg)return 0;
 if(at==0x152008){if(value!=0x40002380&&value!=0x40102380&&value!=0x40302380&&value!=0x44302380)return 0;}
 else if(at>=0xa90000&&at<0xa91000){if(!G37EngineWriteAddress(at))return 0;}
 else if(value!=1&&value!=0x85)return 0;
 WRITE_REGISTER_ULONG(reg,value);return 1;
}
static VOID G37CaptureSpi(G37_SPI *out)
{
 G37_OBS_CONTEXT context;G37_SPI_IO io;G37_SNAPSHOT before,after;
 LARGE_INTEGER begin,end,frequency;ULONG i;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&context,sizeof(context));G37Status(&out->Status);
 begin=KeQueryPerformanceCounter(&frequency);out->CounterFrequency=(ULONGLONG)frequency.QuadPart;
 if(InterlockedCompareExchange(&G37SpiUsed,1,0)!=0){out->Spi.Code=1002;goto done;}
 out->Attempt=1;
 if(InterlockedCompareExchange(&G37ObserverAttempts,0,0)!=1||!InterlockedCompareExchange(&G37OffPmicVerified,0,0)||InterlockedCompareExchange(&G37ObserverFault,0,0)){
  out->Spi.Code=1003;goto done;
 }
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Spi.Code=1004;goto done;}
 status=G37Snapshot(&before);
 if(!NT_SUCCESS(status)||RtlCompareMemory(before.Values,G37ExpectedValues,sizeof(before.Values))!=sizeof(before.Values)){out->Spi.Code=1005;goto done;}
 for(i=0;i<7;i++){
  PHYSICAL_ADDRESS at;at.QuadPart=(LONGLONG)G37SpiRanges[i].Base;InterlockedIncrement(&G37MapCalls);
  context.Maps[i]=MmMapIoSpaceEx(at,G37SpiRanges[i].Bytes,((i==0||i==3||i==4)?PAGE_READWRITE:PAGE_READONLY)|PAGE_NOCACHE);
  if(!context.Maps[i]){out->Spi.Code=1006;goto done;}
 }
 io.Context=&context;io.Read=G37SpiRead;io.Write=G37SpiWrite;io.WaitMicrosecond=G37ObserverWait;
 G37PrepareSpi(&io,&out->Spi);
 done:
 for(i=7;i>0;i--)if(context.Maps[i-1])MmUnmapIoSpace(context.Maps[i-1],G37SpiRanges[i-1].Bytes);
 if(out->Spi.Code<1000){
  status=G37Snapshot(&after);
  if(NT_SUCCESS(status)&&RtlCompareMemory(before.Values,after.Values,sizeof(before.Values))==sizeof(before.Values))out->FixedRegistersUnchanged=1;
  else out->Spi.Code=1007;
 }
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G37MapCalls,0,0);
 end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(ULONGLONG)(end.QuadPart-begin.QuadPart);
}

VOID G37Control(WDFQUEUE Queue,WDFREQUEST Request,size_t OutputLength,size_t InputLength,ULONG Code)
{
 G37_REQUEST *input;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;
 UNREFERENCED_PARAMETER(Queue);
 if(Code!=G37_IOCTL_STATUS&&Code!=G37_IOCTL_SNAPSHOT&&Code!=G37_IOCTL_PMIC&&Code!=G37_IOCTL_SPI){status=STATUS_INVALID_DEVICE_REQUEST;goto complete;}
 if(InputLength!=sizeof(G37_REQUEST)){status=STATUS_INVALID_PARAMETER;goto complete;}
 status=WdfRequestRetrieveInputBuffer(Request,sizeof(G37_REQUEST),(PVOID*)&input,NULL);
 if(!NT_SUCCESS(status))goto complete;
 if(input->Size!=sizeof(*input)||input->Version!=G37_ABI||input->Magic!=G37_MAGIC){status=STATUS_INVALID_PARAMETER;goto complete;}
 needed=Code==G37_IOCTL_STATUS?sizeof(G37_STATUS):Code==G37_IOCTL_SNAPSHOT?sizeof(G37_SNAPSHOT):Code==G37_IOCTL_PMIC?sizeof(G37_PMIC):sizeof(G37_SPI);
 if(OutputLength<needed){status=STATUS_BUFFER_TOO_SMALL;goto complete;}
 status=WdfRequestRetrieveOutputBuffer(Request,needed,&output,NULL);if(!NT_SUCCESS(status))goto complete;
 if(Code==G37_IOCTL_STATUS){G37Status((G37_STATUS*)output);status=STATUS_SUCCESS;}
 else if(Code==G37_IOCTL_PMIC){G37CapturePmic((G37_PMIC*)output);status=STATUS_SUCCESS;}
 else if(Code==G37_IOCTL_SPI){G37CaptureSpi((G37_SPI*)output);status=STATUS_SUCCESS;}
 else status=G37Snapshot((G37_SNAPSHOT*)output);
 if(NT_SUCCESS(status))information=needed;
 complete:WdfRequestCompleteWithInformation(Request,status,information);
}
VOID G37FileCreate(WDFDEVICE Device,WDFREQUEST Request,WDFFILEOBJECT FileObject)
{
 PUNICODE_STRING name=WdfFileObjectGetFileName(FileObject);UNREFERENCED_PARAMETER(Device);
 WdfRequestComplete(Request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);
}
VOID G37Unload(WDFDRIVER Driver){UNREFERENCED_PARAMETER(Driver);}
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath)
{
 WDF_DRIVER_CONFIG config;WDFDRIVER driver;PWDFDEVICE_INIT init=NULL;WDFDEVICE device;
 WDF_OBJECT_ATTRIBUTES attributes;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG files;NTSTATUS status;
 DECLARE_CONST_UNICODE_STRING(sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
 DECLARE_CONST_UNICODE_STRING(name,L"\\Device\\OpenG37");
 DECLARE_CONST_UNICODE_STRING(link,L"\\DosDevices\\OpenG37");
 WDF_DRIVER_CONFIG_INIT(&config,WDF_NO_EVENT_CALLBACK);config.DriverInitFlags|=WdfDriverInitNonPnpDriver;config.EvtDriverUnload=G37Unload;
 status=WdfDriverCreate(DriverObject,RegistryPath,WDF_NO_OBJECT_ATTRIBUTES,&config,&driver);if(!NT_SUCCESS(status))return status;
 status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 init=WdfControlDeviceInitAllocate(driver,&sddl);if(!init)return STATUS_INSUFFICIENT_RESOURCES;
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);
 WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&files,G37FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);
 WdfDeviceInitSetFileObjectConfig(init,&files,WDF_NO_OBJECT_ATTRIBUTES);
 status=WdfDeviceInitAssignName(init,&name);if(!NT_SUCCESS(status))goto done;
 WDF_OBJECT_ATTRIBUTES_INIT(&attributes);attributes.ExecutionLevel=WdfExecutionLevelPassive;attributes.SynchronizationScope=WdfSynchronizationScopeDevice;
 status=WdfDeviceCreate(&init,&attributes,&device);if(!NT_SUCCESS(status))goto done;
 status=WdfDeviceCreateSymbolicLink(device,&link);if(!NT_SUCCESS(status))goto done;
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfFalse;queue.EvtIoDeviceControl=G37Control;
 status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))goto done;
 WdfControlFinishInitializing(device);
 done:if(init)WdfDeviceInitFree(init);return status;
}
