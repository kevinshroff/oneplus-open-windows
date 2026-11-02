/* SPDX-License-Identifier: MIT
 * Temporary source-built KMDF diagnostic. Fixed qualified register/PMIC reads.
 * This control device is not the eventual PnP bus/regulator owner.
 */
#include <ntddk.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g35_binding.h"
#include "g35_observer.h"
#include "g35_protocol.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G35Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G35Control;
EVT_WDF_DEVICE_FILE_CREATE G35FileCreate;
static volatile LONG64 G35Sequence;
static volatile LONG G35MapCalls;
static volatile LONG G35ObserverAttempts;
static volatile LONG G35ObserverFault;

static VOID G35Status(G35_STATUS *out)
{
 UCHAR table[sizeof(G35ExpectedDsdt)];ULONG bytes=0;
 RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=G35_ABI;out->Magic=G35_MAGIC;
 out->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
 out->CurrentIrql=KeGetCurrentIrql();out->RegisterCount=G35_REGISTER_COUNT;
 out->MapCalls=(ULONG)InterlockedCompareExchange(&G35MapCalls,0,0);
 out->Sequence=(ULONGLONG)InterlockedIncrement64(&G35Sequence);out->InterruptTime=KeQueryInterruptTime();
 RtlCopyMemory(out->BuildId,"G35-kmdf-obs1",13);
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);
 if(NT_SUCCESS(RtlGetVersion(&version)))out->KernelBuild=version.dwBuildNumber;
 RtlZeroMemory(table,sizeof(table));
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);
 out->FirmwareStatus=(ULONG)status;out->FirmwareBytes=bytes;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G35ExpectedDsdt,sizeof(table))==sizeof(table))out->FirmwareMatch=1;
}

static NTSTATUS G35Snapshot(G35_SNAPSHOT *out)
{
 PVOID maps[RTL_NUMBER_OF(G35Ranges)];NTSTATUS status=STATUS_SUCCESS;ULONG i;
 RtlZeroMemory(out,sizeof(*out));G35Status(&out->Status);
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL)return STATUS_NOT_SUPPORTED;
 RtlZeroMemory(maps,sizeof(maps));
 for(i=0;i<RTL_NUMBER_OF(G35Ranges);i++){
  PHYSICAL_ADDRESS address;address.QuadPart=(LONGLONG)G35Ranges[i].Base;
  InterlockedIncrement(&G35MapCalls);
  maps[i]=MmMapIoSpaceEx(address,G35Ranges[i].Bytes,PAGE_READONLY|PAGE_NOCACHE);
  if(maps[i]==NULL){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 }
 for(i=0;i<G35_REGISTER_COUNT;i++){
  const G35_FIELD *field=&G35Fields[i];
  out->Values[i]=READ_REGISTER_ULONG((PULONG)((PUCHAR)maps[field->Range]+field->Offset));
 }
 out->Count=G35_REGISTER_COUNT;
 done:
 for(i=RTL_NUMBER_OF(G35Ranges);i>0;i--)if(maps[i-1])MmUnmapIoSpace(maps[i-1],G35Ranges[i-1].Bytes);
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G35MapCalls,0,0);
 return status;
}

typedef struct {PVOID Maps[6];} G35_OBS_CONTEXT;
static const ULONG G35ObserverPages[6]={0xc400000,0xc402000,0xc42d000,0xc440000,0xc441000,0xc445000};
static PULONG G35ObserverAddress(G35_OBS_CONTEXT *ctx,ULONG at,BOOLEAN write)
{
 ULONG i;
 if((at&3)!=0)return NULL;
 if(write&&at!=0xc440ea0&&at!=0xc441220&&at!=0xc4456e0)return NULL;
 for(i=0;i<6;i++)if(ctx->Maps[i]&&at>=G35ObserverPages[i]&&at-G35ObserverPages[i]<=0xffc){
  if(write&&i<3)return NULL;
  return(PULONG)((PUCHAR)ctx->Maps[i]+at-G35ObserverPages[i]);
 }
 return NULL;
}
static int G35ObserverRead(void *context,uint32_t at,uint32_t *value)
{
 PULONG reg=G35ObserverAddress((G35_OBS_CONTEXT*)context,at,FALSE);
 if(!reg)return 0;*value=READ_REGISTER_ULONG(reg);return 1;
}
static int G35ObserverWrite(void *context,uint32_t at,uint32_t value)
{
 PULONG reg=G35ObserverAddress((G35_OBS_CONTEXT*)context,at,TRUE);
 if(!reg||!((value==0x08000007)||(value==0x08000080)||(value==0x08000407)))return 0;
 WRITE_REGISTER_ULONG(reg,value);return 1;
}
static void G35ObserverWait(void *context){UNREFERENCED_PARAMETER(context);KeStallExecutionProcessor(1);}
static VOID G35CapturePmic(G35_PMIC *out)
{
 G35_OBS_CONTEXT context;G35_OBS_IO io;G35_SNAPSHOT before,after;
 LARGE_INTEGER begin,end,frequency;LONG previous;ULONG i;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&context,sizeof(context));
 G35Status(&out->Status);begin=KeQueryPerformanceCounter(&frequency);
 out->CounterFrequency=(ULONGLONG)frequency.QuadPart;
 previous=InterlockedCompareExchange(&G35ObserverAttempts,0,0);out->Attempt=(ULONG)previous;
 if(InterlockedCompareExchange(&G35ObserverFault,0,0)){out->Observer.Code=1001;goto done;}
 if(previous>=2){out->Observer.Code=1002;goto done;}
 if(InterlockedCompareExchange(&G35ObserverAttempts,previous+1,previous)!=previous){out->Observer.Code=1003;goto done;}
 out->Attempt=(ULONG)previous+1;
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Observer.Code=1004;goto done;}
 status=G35Snapshot(&before);
 if(!NT_SUCCESS(status)||RtlCompareMemory(before.Values,G35ExpectedValues,sizeof(before.Values))!=sizeof(before.Values)){
  out->Observer.Code=1005;goto done;
 }
 for(i=0;i<6;i++){
  PHYSICAL_ADDRESS at;at.QuadPart=G35ObserverPages[i];InterlockedIncrement(&G35MapCalls);
  context.Maps[i]=MmMapIoSpaceEx(at,0x1000,(i<3?PAGE_READONLY:PAGE_READWRITE)|PAGE_NOCACHE);
  if(!context.Maps[i]){out->Observer.Code=1006;goto done;}
 }
 io.Context=&context;io.Read=G35ObserverRead;io.Write=G35ObserverWrite;io.WaitMicrosecond=G35ObserverWait;
 G35Observe(&io,&out->Observer);
 done:
 for(i=6;i>0;i--)if(context.Maps[i-1])MmUnmapIoSpace(context.Maps[i-1],0x1000);
 if(out->Attempt==(ULONG)previous+1){
  if(out->Observer.Code==0){
   status=G35Snapshot(&after);
   if(NT_SUCCESS(status)&&RtlCompareMemory(before.Values,after.Values,sizeof(before.Values))==sizeof(before.Values))out->FixedRegistersUnchanged=1;
   else out->Observer.Code=1007;
  }
  if(out->Observer.Code!=0)InterlockedExchange(&G35ObserverFault,1);
 }
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G35MapCalls,0,0);
 end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(ULONGLONG)(end.QuadPart-begin.QuadPart);
}

VOID G35Control(WDFQUEUE Queue,WDFREQUEST Request,size_t OutputLength,size_t InputLength,ULONG Code)
{
 G35_REQUEST *input;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;
 UNREFERENCED_PARAMETER(Queue);
 if(Code!=G35_IOCTL_STATUS&&Code!=G35_IOCTL_SNAPSHOT&&Code!=G35_IOCTL_PMIC){status=STATUS_INVALID_DEVICE_REQUEST;goto complete;}
 if(InputLength!=sizeof(G35_REQUEST)){status=STATUS_INVALID_PARAMETER;goto complete;}
 status=WdfRequestRetrieveInputBuffer(Request,sizeof(G35_REQUEST),(PVOID*)&input,NULL);
 if(!NT_SUCCESS(status))goto complete;
 if(input->Size!=sizeof(*input)||input->Version!=G35_ABI||input->Magic!=G35_MAGIC){status=STATUS_INVALID_PARAMETER;goto complete;}
 needed=Code==G35_IOCTL_STATUS?sizeof(G35_STATUS):Code==G35_IOCTL_SNAPSHOT?sizeof(G35_SNAPSHOT):sizeof(G35_PMIC);
 if(OutputLength<needed){status=STATUS_BUFFER_TOO_SMALL;goto complete;}
 status=WdfRequestRetrieveOutputBuffer(Request,needed,&output,NULL);if(!NT_SUCCESS(status))goto complete;
 if(Code==G35_IOCTL_STATUS){G35Status((G35_STATUS*)output);status=STATUS_SUCCESS;}
 else if(Code==G35_IOCTL_PMIC){G35CapturePmic((G35_PMIC*)output);status=STATUS_SUCCESS;}
 else status=G35Snapshot((G35_SNAPSHOT*)output);
 if(NT_SUCCESS(status))information=needed;
 complete:WdfRequestCompleteWithInformation(Request,status,information);
}
VOID G35FileCreate(WDFDEVICE Device,WDFREQUEST Request,WDFFILEOBJECT FileObject)
{
 PUNICODE_STRING name=WdfFileObjectGetFileName(FileObject);UNREFERENCED_PARAMETER(Device);
 WdfRequestComplete(Request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);
}
VOID G35Unload(WDFDRIVER Driver){UNREFERENCED_PARAMETER(Driver);}
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath)
{
 WDF_DRIVER_CONFIG config;WDFDRIVER driver;PWDFDEVICE_INIT init=NULL;WDFDEVICE device;
 WDF_OBJECT_ATTRIBUTES attributes;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG files;NTSTATUS status;
 DECLARE_CONST_UNICODE_STRING(sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
 DECLARE_CONST_UNICODE_STRING(name,L"\\Device\\OpenG35");
 DECLARE_CONST_UNICODE_STRING(link,L"\\DosDevices\\OpenG35");
 WDF_DRIVER_CONFIG_INIT(&config,WDF_NO_EVENT_CALLBACK);config.DriverInitFlags|=WdfDriverInitNonPnpDriver;config.EvtDriverUnload=G35Unload;
 status=WdfDriverCreate(DriverObject,RegistryPath,WDF_NO_OBJECT_ATTRIBUTES,&config,&driver);if(!NT_SUCCESS(status))return status;
 status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 init=WdfControlDeviceInitAllocate(driver,&sddl);if(!init)return STATUS_INSUFFICIENT_RESOURCES;
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);
 WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&files,G35FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);
 WdfDeviceInitSetFileObjectConfig(init,&files,WDF_NO_OBJECT_ATTRIBUTES);
 status=WdfDeviceInitAssignName(init,&name);if(!NT_SUCCESS(status))goto done;
 WDF_OBJECT_ATTRIBUTES_INIT(&attributes);attributes.ExecutionLevel=WdfExecutionLevelPassive;attributes.SynchronizationScope=WdfSynchronizationScopeDevice;
 status=WdfDeviceCreate(&init,&attributes,&device);if(!NT_SUCCESS(status))goto done;
 status=WdfDeviceCreateSymbolicLink(device,&link);if(!NT_SUCCESS(status))goto done;
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfFalse;queue.EvtIoDeviceControl=G35Control;
 status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))goto done;
 WdfControlFinishInitializing(device);
 done:if(init)WdfDeviceInitFree(init);return status;
}
