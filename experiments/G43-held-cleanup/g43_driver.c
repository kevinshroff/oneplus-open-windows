/* SPDX-License-Identifier: MIT
 * Temporary source-built KMDF diagnostic. Fixed qualified register/PMIC reads.
 * This control device is not the eventual PnP bus/regulator owner.
 */
#include <ntddk.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g43_binding.h"
#include "g43_observer.h"
#include "g43_trial.h"
#include "g43_protocol.h"
#include "g43_recovery.h"
#include "g43_recovery_binding.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G43Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G43Control;
EVT_WDF_DEVICE_FILE_CREATE G43FileCreate;
static volatile LONG64 G43Sequence;
static volatile LONG G43MapCalls;
static volatile LONG G43TrialUsed;

static VOID G43Status(G43_STATUS *out)
{
 UCHAR table[sizeof(G43ExpectedDsdt)];ULONG bytes=0;
 RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=G43_ABI;out->Magic=G43_MAGIC;
 out->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
 out->CurrentIrql=KeGetCurrentIrql();out->RegisterCount=G43_REGISTER_COUNT;
 out->MapCalls=(ULONG)InterlockedCompareExchange(&G43MapCalls,0,0);
 out->Sequence=(ULONGLONG)InterlockedIncrement64(&G43Sequence);out->InterruptTime=KeQueryInterruptTime();
 RtlCopyMemory(out->BuildId,"G43-recover1",13);
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);
 if(NT_SUCCESS(RtlGetVersion(&version)))out->KernelBuild=version.dwBuildNumber;
 RtlZeroMemory(table,sizeof(table));
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);
 out->FirmwareStatus=(ULONG)status;out->FirmwareBytes=bytes;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G43ExpectedDsdt,sizeof(table))==sizeof(table))out->FirmwareMatch=1;
}

static NTSTATUS G43Snapshot(G43_SNAPSHOT *out)
{
 PVOID maps[RTL_NUMBER_OF(G43Ranges)];NTSTATUS status=STATUS_SUCCESS;ULONG i;
 RtlZeroMemory(out,sizeof(*out));G43Status(&out->Status);
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL)return STATUS_NOT_SUPPORTED;
 RtlZeroMemory(maps,sizeof(maps));
 for(i=0;i<RTL_NUMBER_OF(G43Ranges);i++){
  PHYSICAL_ADDRESS address;address.QuadPart=(LONGLONG)G43Ranges[i].Base;
  InterlockedIncrement(&G43MapCalls);
  maps[i]=MmMapIoSpaceEx(address,G43Ranges[i].Bytes,PAGE_READONLY|PAGE_NOCACHE);
  if(maps[i]==NULL){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 }
 for(i=0;i<G43_REGISTER_COUNT;i++){
  const G43_FIELD *field=&G43Fields[i];
  out->Values[i]=READ_REGISTER_ULONG((PULONG)((PUCHAR)maps[field->Range]+field->Offset));
 }
 out->Count=G43_REGISTER_COUNT;
 done:
 for(i=RTL_NUMBER_OF(G43Ranges);i>0;i--)if(maps[i-1])MmUnmapIoSpace(maps[i-1],G43Ranges[i-1].Bytes);
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G43MapCalls,0,0);
 return status;
}

static void G43ObserverWait(void *context){UNREFERENCED_PARAMETER(context);KeStallExecutionProcessor(1);}
static VOID G43CapturePmic(G43_PMIC*out)
{
 RtlZeroMemory(out,sizeof(*out));G43Status(&out->Status);out->Observer.Code=1002;
}

typedef struct {PVOID Maps[16];G43_POWER_RESULT*Result;G43_TRIAL_RESULT*Trial;ULONG OwnedPrior,LastM,LastS,HaveM,HaveS,SAcks,MAcks;} G43_PWR_CONTEXT;
static const G43_RANGE G43PowerRanges[16]={{0x17a20000,0x2000},{0x17100000,0x1000},{0xf10a000,0x1000},{0xf118000,0x2000},{0xc400000,0x1000},{0xc402000,0x1000},{0xc42d000,0x1000},{0xc440000,0x1000},{0xc441000,0x1000},{0xc445000,0x1000},{0x152000,0x1000},{0x118000,0x1000},{0x123000,0x1000},{0xf12c000,0x4000},{0xa90000,0x1000},{0xac0000,0x1000}};
static PULONG G43PowerAddress(G43_PWR_CONTEXT*ctx,ULONG at,BOOLEAN write)
{
 ULONG i;if(at&3)return NULL;
 if(write&&at!=0xc440ea0&&at!=0xc441220&&at!=0xc4456e0&&at!=0x17a20d34&&at!=0x17a20d38&&at!=0x17a20d3c&&at!=0x17a20d24&&at!=0x17a20d2c&&at!=0x17a20d08&&
 at!=0xf10a000&&at!=0xf10a004&&at!=0xf118000&&at!=0xf118004&&at!=0xf119000&&at!=0xf11900c&&at!=0x152008&&at!=0xf12c000&&at!=0xf12d000&&at!=0xf12e000&&at!=0xf12f000&&
 !G43EngineWriteAddress(at)&&at!=0xa9026c&&at!=0xa90270&&at!=0xa90618&&at!=0xa90648)return NULL;
 for(i=0;i<16;i++)if(ctx->Maps[i]&&at>=G43PowerRanges[i].Base&&at-G43PowerRanges[i].Base+4<=G43PowerRanges[i].Bytes){
  if(write&&i!=0&&i!=2&&i!=3&&i!=7&&i!=8&&i!=9&&i!=10&&i!=13&&i!=14)return NULL;
  return(PULONG)((PUCHAR)ctx->Maps[i]+at-G43PowerRanges[i].Base);
 }
 return NULL;
}
static int G43PowerRead(void*context,uint32_t at,uint32_t*value)
{
 G43_PWR_CONTEXT*ctx=context;PULONG reg=G43PowerAddress(ctx,at,FALSE);if(!reg)return 0;*value=READ_REGISTER_ULONG(reg);
 if(at==0xa90610){ctx->LastM=*value;ctx->HaveM=1;}if(at==0xa90640){ctx->LastS=*value;ctx->HaveS=1;}return 1;
}
static int G43PowerWrite(void*context,uint32_t at,uint32_t value)
{
 G43_PWR_CONTEXT*ctx=context;PULONG reg=G43PowerAddress(ctx,at,TRUE);unsigned i;if(!reg)return 0;
 if(at==0xc440ea0||at==0xc441220||at==0xc4456e0){if(value!=0x08000007&&value!=0x08000080&&value!=0x08000407)return 0;}
 else if(at>=0x17a20000&&at<0x17a22000){if(!G43RscWriteAllowed(at,value)||(at==0x17a20d3c&&value==1))return 0;}
 else if(at==0x152008){if(value!=0x40002380&&value!=0x40102380&&value!=0x40302380)return 0;}
 else if(at>=0xf12c000&&at<=0xf12f000){if(value!=1)return 0;}
 else if(at==0xf10a000||at==0xf119000){if(value!=1)return 0;}
 else if(at==0xf118000){if(value!=0x201)return 0;}
 else if(at==0xf10a004||at==0xf118004){if(value>1)return 0;}
 else if(at==0xf11900c){if(value)return 0;}
 else if(at==0xa90618){if(!ctx->OwnedPrior||!ctx->HaveM||value!=ctx->LastM||ctx->MAcks)return 0;ctx->HaveM=0;ctx->MAcks++;}
 else if(at==0xa90648){if(!ctx->OwnedPrior||!ctx->HaveS||value!=ctx->LastS||ctx->SAcks)return 0;ctx->HaveS=0;ctx->SAcks++;}
 else if(at==0xa9026c||at==0xa90270){if(value!=G43OriginalLengths[(at-0xa9026c)/4])return 0;}
 else{
  for(i=0;i<24;i++)if(at==0xa90000+G43RecoveryEngineOffsets[i])break;
  if(i==24||value!=G43OriginalEngine[i])return 0;
 }
 WRITE_REGISTER_ULONG(reg,value);return 1;
}
static void G43PowerWait1(void*context)
{
 G43_PWR_CONTEXT*ctx=context;LARGE_INTEGER wait;ctx->Result->Waits1ms++;wait.QuadPart=-10000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}
static void G43PowerWait10(void*context)
{
 LARGE_INTEGER wait;UNREFERENCED_PARAMETER(context);wait.QuadPart=-100000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}

static void G43WaitMs(void*context,uint32_t ms)
{
 LARGE_INTEGER wait;UNREFERENCED_PARAMETER(context);wait.QuadPart=-(LONGLONG)ms*10000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}






static VOID G43CaptureTrial(G43_TRIAL*out)
{
 G43_PWR_CONTEXT context;G43_POWER_IO io;G43_TOUCH_IO touch;G43_SNAPSHOT before,after;
 LARGE_INTEGER begin,end,frequency;ULONG i;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&context,sizeof(context));RtlZeroMemory(&io,sizeof(io));RtlZeroMemory(&touch,sizeof(touch));
 G43Status(&out->Status);context.Trial=&out->Trial;context.Result=&out->Trial.Power;context.OwnedPrior=1;
 begin=KeQueryPerformanceCounter(&frequency);out->CounterFrequency=(ULONGLONG)frequency.QuadPart;
 if(InterlockedCompareExchange(&G43TrialUsed,1,0)!=0){out->Trial.Power.Code=1002;goto done;}
 out->Attempt=1;
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Trial.Power.Code=1004;goto done;}
 status=G43Snapshot(&before);
 if(!NT_SUCCESS(status)||RtlCompareMemory(before.Values,G43HeldValues,sizeof(before.Values))!=sizeof(before.Values)){out->Trial.Power.Code=1005;goto done;}
 for(i=0;i<16;i++){
  PHYSICAL_ADDRESS at;at.QuadPart=(LONGLONG)G43PowerRanges[i].Base;InterlockedIncrement(&G43MapCalls);
  context.Maps[i]=MmMapIoSpaceEx(at,G43PowerRanges[i].Bytes,(i==0||i==2||i==3||i==7||i==8||i==9||i==10||i==13||i==14?PAGE_READWRITE:PAGE_READONLY)|PAGE_NOCACHE);
  if(!context.Maps[i]){out->Trial.Power.Code=1006;goto done;}
 }
 io.Rsc.Context=&context;io.Rsc.Read=G43PowerRead;io.Rsc.Write=G43PowerWrite;io.Rsc.WaitMillisecond=G43PowerWait1;
 io.Observer.Context=&context;io.Observer.Read=G43PowerRead;io.Observer.Write=G43PowerWrite;io.Observer.WaitMicrosecond=G43ObserverWait;io.WaitTenMilliseconds=G43PowerWait10;
 touch.Context=&context;touch.Read=G43PowerRead;touch.Write=G43PowerWrite;touch.WaitMs=G43WaitMs;
 G43RecoverHeld(&io,&touch,&out->Trial);
 done:
 for(i=16;i>0;i--)if(context.Maps[i-1])MmUnmapIoSpace(context.Maps[i-1],G43PowerRanges[i-1].Bytes);
 if(out->Trial.Power.Code<1000){
  status=G43Snapshot(&after);
  if(NT_SUCCESS(status)&&RtlCompareMemory(after.Values,G43ExpectedValues,sizeof(after.Values))==sizeof(after.Values))out->FixedRegistersUnchanged=1;
  else if(!out->Trial.Power.Code)out->Trial.Power.Code=1007;
 }
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G43MapCalls,0,0);
 end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(ULONGLONG)(end.QuadPart-begin.QuadPart);
}

VOID G43Control(WDFQUEUE Queue,WDFREQUEST Request,size_t OutputLength,size_t InputLength,ULONG Code)
{
 G43_REQUEST *input;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;
 UNREFERENCED_PARAMETER(Queue);
 if(Code!=G43_IOCTL_STATUS&&Code!=G43_IOCTL_SNAPSHOT&&Code!=G43_IOCTL_PMIC&&Code!=G43_IOCTL_POWER){status=STATUS_INVALID_DEVICE_REQUEST;goto complete;}
 if(InputLength!=sizeof(G43_REQUEST)){status=STATUS_INVALID_PARAMETER;goto complete;}
 status=WdfRequestRetrieveInputBuffer(Request,sizeof(G43_REQUEST),(PVOID*)&input,NULL);
 if(!NT_SUCCESS(status))goto complete;
 if(input->Size!=sizeof(*input)||input->Version!=G43_ABI||input->Magic!=G43_MAGIC){status=STATUS_INVALID_PARAMETER;goto complete;}
 needed=Code==G43_IOCTL_STATUS?sizeof(G43_STATUS):Code==G43_IOCTL_SNAPSHOT?sizeof(G43_SNAPSHOT):Code==G43_IOCTL_PMIC?sizeof(G43_PMIC):sizeof(G43_TRIAL);
 if(OutputLength<needed){status=STATUS_BUFFER_TOO_SMALL;goto complete;}
 status=WdfRequestRetrieveOutputBuffer(Request,needed,&output,NULL);if(!NT_SUCCESS(status))goto complete;
 if(Code==G43_IOCTL_STATUS){G43Status((G43_STATUS*)output);status=STATUS_SUCCESS;}
 else if(Code==G43_IOCTL_PMIC){G43CapturePmic((G43_PMIC*)output);status=STATUS_SUCCESS;}
 else if(Code==G43_IOCTL_POWER){G43CaptureTrial((G43_TRIAL*)output);status=STATUS_SUCCESS;}
 else status=G43Snapshot((G43_SNAPSHOT*)output);
 if(NT_SUCCESS(status))information=needed;
 complete:WdfRequestCompleteWithInformation(Request,status,information);
}
VOID G43FileCreate(WDFDEVICE Device,WDFREQUEST Request,WDFFILEOBJECT FileObject)
{
 PUNICODE_STRING name=WdfFileObjectGetFileName(FileObject);UNREFERENCED_PARAMETER(Device);
 WdfRequestComplete(Request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);
}
VOID G43Unload(WDFDRIVER Driver){UNREFERENCED_PARAMETER(Driver);}
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath)
{
 WDF_DRIVER_CONFIG config;WDFDRIVER driver;PWDFDEVICE_INIT init=NULL;WDFDEVICE device;
 WDF_OBJECT_ATTRIBUTES attributes;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG files;NTSTATUS status;
 DECLARE_CONST_UNICODE_STRING(sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
 DECLARE_CONST_UNICODE_STRING(name,L"\\Device\\OpenG43");
 DECLARE_CONST_UNICODE_STRING(link,L"\\DosDevices\\OpenG43");
 WDF_DRIVER_CONFIG_INIT(&config,WDF_NO_EVENT_CALLBACK);config.DriverInitFlags|=WdfDriverInitNonPnpDriver;config.EvtDriverUnload=G43Unload;
 status=WdfDriverCreate(DriverObject,RegistryPath,WDF_NO_OBJECT_ATTRIBUTES,&config,&driver);if(!NT_SUCCESS(status))return status;
 status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 init=WdfControlDeviceInitAllocate(driver,&sddl);if(!init)return STATUS_INSUFFICIENT_RESOURCES;
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);
 WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&files,G43FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);
 WdfDeviceInitSetFileObjectConfig(init,&files,WDF_NO_OBJECT_ATTRIBUTES);
 status=WdfDeviceInitAssignName(init,&name);if(!NT_SUCCESS(status))goto done;
 WDF_OBJECT_ATTRIBUTES_INIT(&attributes);attributes.ExecutionLevel=WdfExecutionLevelPassive;attributes.SynchronizationScope=WdfSynchronizationScopeDevice;
 status=WdfDeviceCreate(&init,&attributes,&device);if(!NT_SUCCESS(status))goto done;
 status=WdfDeviceCreateSymbolicLink(device,&link);if(!NT_SUCCESS(status))goto done;
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfFalse;queue.EvtIoDeviceControl=G43Control;
 status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))goto done;
 WdfControlFinishInitializing(device);
 done:if(init)WdfDeviceInitFree(init);return status;
}
