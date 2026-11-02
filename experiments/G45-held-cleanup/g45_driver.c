/* SPDX-License-Identifier: MIT
 * Temporary source-built KMDF diagnostic. Fixed qualified register/PMIC reads.
 * This control device is not the eventual PnP bus/regulator owner.
 */
#include <ntddk.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g45_binding.h"
#include "g45_observer.h"
#include "g45_trial.h"
#include "g45_protocol.h"
#include "g45_recovery.h"
#include "g45_recovery_binding.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G45Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G45Control;
EVT_WDF_DEVICE_FILE_CREATE G45FileCreate;
static volatile LONG64 G45Sequence;
static volatile LONG G45MapCalls;
static volatile LONG G45TrialUsed;

static VOID G45Status(G45_STATUS *out)
{
 UCHAR table[sizeof(G45ExpectedDsdt)];ULONG bytes=0;
 RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=G45_ABI;out->Magic=G45_MAGIC;
 out->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
 out->CurrentIrql=KeGetCurrentIrql();out->RegisterCount=G45_REGISTER_COUNT;
 out->MapCalls=(ULONG)InterlockedCompareExchange(&G45MapCalls,0,0);
 out->Sequence=(ULONGLONG)InterlockedIncrement64(&G45Sequence);out->InterruptTime=KeQueryInterruptTime();
 RtlCopyMemory(out->BuildId,"G45-recover1",13);
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);
 if(NT_SUCCESS(RtlGetVersion(&version)))out->KernelBuild=version.dwBuildNumber;
 RtlZeroMemory(table,sizeof(table));
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);
 out->FirmwareStatus=(ULONG)status;out->FirmwareBytes=bytes;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G45ExpectedDsdt,sizeof(table))==sizeof(table))out->FirmwareMatch=1;
}

static NTSTATUS G45Snapshot(G45_SNAPSHOT *out)
{
 PVOID maps[RTL_NUMBER_OF(G45Ranges)];NTSTATUS status=STATUS_SUCCESS;ULONG i;
 RtlZeroMemory(out,sizeof(*out));G45Status(&out->Status);
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL)return STATUS_NOT_SUPPORTED;
 RtlZeroMemory(maps,sizeof(maps));
 for(i=0;i<RTL_NUMBER_OF(G45Ranges);i++){
  PHYSICAL_ADDRESS address;address.QuadPart=(LONGLONG)G45Ranges[i].Base;
  InterlockedIncrement(&G45MapCalls);
  maps[i]=MmMapIoSpaceEx(address,G45Ranges[i].Bytes,PAGE_READONLY|PAGE_NOCACHE);
  if(maps[i]==NULL){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 }
 for(i=0;i<G45_REGISTER_COUNT;i++){
  const G45_FIELD *field=&G45Fields[i];
  out->Values[i]=READ_REGISTER_ULONG((PULONG)((PUCHAR)maps[field->Range]+field->Offset));
 }
 out->Count=G45_REGISTER_COUNT;
 done:
 for(i=RTL_NUMBER_OF(G45Ranges);i>0;i--)if(maps[i-1])MmUnmapIoSpace(maps[i-1],G45Ranges[i-1].Bytes);
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G45MapCalls,0,0);
 return status;
}

static void G45ObserverWait(void *context){UNREFERENCED_PARAMETER(context);KeStallExecutionProcessor(1);}
static VOID G45CapturePmic(G45_PMIC*out)
{
 RtlZeroMemory(out,sizeof(*out));G45Status(&out->Status);out->Observer.Code=1002;
}

typedef struct {PVOID Maps[16];G45_POWER_RESULT*Result;G45_TRIAL_RESULT*Trial;ULONG OwnedPrior,LastM,LastS,HaveM,HaveS,SAcks,MAcks;} G45_PWR_CONTEXT;
static const G45_RANGE G45PowerRanges[16]={{0x17a20000,0x2000},{0x17100000,0x1000},{0xf10a000,0x1000},{0xf118000,0x2000},{0xc400000,0x1000},{0xc402000,0x1000},{0xc42d000,0x1000},{0xc440000,0x1000},{0xc441000,0x1000},{0xc445000,0x1000},{0x152000,0x1000},{0x118000,0x1000},{0x123000,0x1000},{0xf12c000,0x4000},{0xa90000,0x1000},{0xac0000,0x1000}};
static PULONG G45PowerAddress(G45_PWR_CONTEXT*ctx,ULONG at,BOOLEAN write)
{
 ULONG i;if(at&3)return NULL;
 if(write&&at!=0xc440ea0&&at!=0xc441220&&at!=0xc4456e0&&at!=0x17a20d34&&at!=0x17a20d38&&at!=0x17a20d3c&&at!=0x17a20d24&&at!=0x17a20d2c&&at!=0x17a20d08&&
 at!=0xf10a000&&at!=0xf10a004&&at!=0xf118000&&at!=0xf118004&&at!=0xf119000&&at!=0xf11900c&&at!=0x152008&&at!=0xf12c000&&at!=0xf12d000&&at!=0xf12e000&&at!=0xf12f000&&
 !G45EngineWriteAddress(at)&&at!=0xa9026c&&at!=0xa90270)return NULL;
 for(i=0;i<16;i++)if(ctx->Maps[i]&&at>=G45PowerRanges[i].Base&&at-G45PowerRanges[i].Base+4<=G45PowerRanges[i].Bytes){
  if(write&&i!=0&&i!=2&&i!=3&&i!=7&&i!=8&&i!=9&&i!=10&&i!=13&&i!=14)return NULL;
  return(PULONG)((PUCHAR)ctx->Maps[i]+at-G45PowerRanges[i].Base);
 }
 return NULL;
}
static int G45PowerRead(void*context,uint32_t at,uint32_t*value)
{
 G45_PWR_CONTEXT*ctx=context;PULONG reg=G45PowerAddress(ctx,at,FALSE);if(!reg)return 0;*value=READ_REGISTER_ULONG(reg);
 if(at==0xa90610){ctx->LastM=*value;ctx->HaveM=1;}if(at==0xa90640){ctx->LastS=*value;ctx->HaveS=1;}return 1;
}
static int G45PowerWrite(void*context,uint32_t at,uint32_t value)
{
 G45_PWR_CONTEXT*ctx=context;PULONG reg=G45PowerAddress(ctx,at,TRUE);unsigned i;if(!reg)return 0;
 if(at==0xc440ea0||at==0xc441220||at==0xc4456e0){if(value!=0x08000007&&value!=0x08000080&&value!=0x08000407)return 0;}
 else if(at>=0x17a20000&&at<0x17a22000){if(!G45RscWriteAllowed(at,value)||(at==0x17a20d3c&&value==1))return 0;}
 else if(at==0x152008){if(value!=0x40002380&&value!=0x40102380&&value!=0x40302380)return 0;}
 else if(at>=0xf12c000&&at<=0xf12f000){if(value!=1)return 0;}
 else if(at==0xf10a000||at==0xf119000){if(value!=1)return 0;}
 else if(at==0xf118000){if(value!=0x201)return 0;}
 else if(at==0xf10a004||at==0xf118004){if(value>1)return 0;}
 else if(at==0xf11900c){if(value)return 0;}
 else if(at==0xa90618){if(!ctx->OwnedPrior||!ctx->HaveM||value!=ctx->LastM||ctx->MAcks)return 0;ctx->HaveM=0;ctx->MAcks++;}
 else if(at==0xa90648){if(!ctx->OwnedPrior||!ctx->HaveS||value!=ctx->LastS||ctx->SAcks)return 0;ctx->HaveS=0;ctx->SAcks++;}
 else if(at==0xa9026c||at==0xa90270){if(value!=G45OriginalLengths[(at-0xa9026c)/4])return 0;}
 else{
  for(i=0;i<24;i++)if(at==0xa90000+G45RecoveryEngineOffsets[i])break;
  if(i==24||value!=G45OriginalEngine[i])return 0;
 }
 WRITE_REGISTER_ULONG(reg,value);return 1;
}
static void G45PowerWait1(void*context)
{
 G45_PWR_CONTEXT*ctx=context;LARGE_INTEGER wait;ctx->Result->Waits1ms++;wait.QuadPart=-10000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}
static void G45PowerWait10(void*context)
{
 LARGE_INTEGER wait;UNREFERENCED_PARAMETER(context);wait.QuadPart=-100000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}

static void G45WaitMs(void*context,uint32_t ms)
{
 LARGE_INTEGER wait;UNREFERENCED_PARAMETER(context);wait.QuadPart=-(LONGLONG)ms*10000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}






/* IRQ25 input and its owned pending bit are live read-only observations.
 * Ownership controls/configuration and every other fixed word stay exact. */
static int G45HeldMatches(const ULONG*v)
{
 ULONG i;
 if(G45Fields[47].Range!=3||G45Fields[47].Offset!=0x1004||G45Fields[49].Range!=3||G45Fields[49].Offset!=0x100c||G45Ranges[3].Base!=0xf118000)return 0;
 for(i=0;i<50;i++){
  ULONG mask=(i==47||i==49)?~1u:0xffffffffu;
  if((v[i]&mask)!=(G45HeldValues[i]&mask))return 0;
 }return 1;
}
static VOID G45CaptureTrial(G45_TRIAL*out)
{
 G45_PWR_CONTEXT context;G45_POWER_IO io;G45_TOUCH_IO touch;G45_SNAPSHOT before,after;
 LARGE_INTEGER begin,end,frequency;ULONG i;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&context,sizeof(context));RtlZeroMemory(&io,sizeof(io));RtlZeroMemory(&touch,sizeof(touch));
 G45Status(&out->Status);context.Trial=&out->Trial;context.Result=&out->Trial.Power;context.OwnedPrior=1;
 begin=KeQueryPerformanceCounter(&frequency);out->CounterFrequency=(ULONGLONG)frequency.QuadPart;
 if(InterlockedCompareExchange(&G45TrialUsed,1,0)!=0){out->Trial.Power.Code=1002;goto done;}
 out->Attempt=1;
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Trial.Power.Code=1004;goto done;}
 status=G45Snapshot(&before);
 if(!NT_SUCCESS(status)||!G45HeldMatches(before.Values)){out->Trial.Power.Code=1005;goto done;}
 for(i=0;i<16;i++){
  PHYSICAL_ADDRESS at;at.QuadPart=(LONGLONG)G45PowerRanges[i].Base;InterlockedIncrement(&G45MapCalls);
  context.Maps[i]=MmMapIoSpaceEx(at,G45PowerRanges[i].Bytes,(i==0||i==2||i==3||i==7||i==8||i==9||i==10||i==13||i==14?PAGE_READWRITE:PAGE_READONLY)|PAGE_NOCACHE);
  if(!context.Maps[i]){out->Trial.Power.Code=1006;goto done;}
 }
 io.Rsc.Context=&context;io.Rsc.Read=G45PowerRead;io.Rsc.Write=G45PowerWrite;io.Rsc.WaitMillisecond=G45PowerWait1;
 io.Observer.Context=&context;io.Observer.Read=G45PowerRead;io.Observer.Write=G45PowerWrite;io.Observer.WaitMicrosecond=G45ObserverWait;io.WaitTenMilliseconds=G45PowerWait10;
 touch.Context=&context;touch.Read=G45PowerRead;touch.Write=G45PowerWrite;touch.WaitMs=G45WaitMs;
 G45RecoverHeld(&io,&touch,&out->Trial);
 done:
 for(i=16;i>0;i--)if(context.Maps[i-1])MmUnmapIoSpace(context.Maps[i-1],G45PowerRanges[i-1].Bytes);
 if(out->Trial.Power.Code<1000){
  status=G45Snapshot(&after);
  if(NT_SUCCESS(status)&&RtlCompareMemory(after.Values,G45ExpectedValues,sizeof(after.Values))==sizeof(after.Values))out->FixedRegistersUnchanged=1;
  else if(!out->Trial.Power.Code)out->Trial.Power.Code=1007;
 }
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G45MapCalls,0,0);
 end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(ULONGLONG)(end.QuadPart-begin.QuadPart);
}

VOID G45Control(WDFQUEUE Queue,WDFREQUEST Request,size_t OutputLength,size_t InputLength,ULONG Code)
{
 G45_REQUEST *input;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;
 UNREFERENCED_PARAMETER(Queue);
 if(Code!=G45_IOCTL_STATUS&&Code!=G45_IOCTL_SNAPSHOT&&Code!=G45_IOCTL_PMIC&&Code!=G45_IOCTL_POWER){status=STATUS_INVALID_DEVICE_REQUEST;goto complete;}
 if(InputLength!=sizeof(G45_REQUEST)){status=STATUS_INVALID_PARAMETER;goto complete;}
 status=WdfRequestRetrieveInputBuffer(Request,sizeof(G45_REQUEST),(PVOID*)&input,NULL);
 if(!NT_SUCCESS(status))goto complete;
 if(input->Size!=sizeof(*input)||input->Version!=G45_ABI||input->Magic!=G45_MAGIC){status=STATUS_INVALID_PARAMETER;goto complete;}
 needed=Code==G45_IOCTL_STATUS?sizeof(G45_STATUS):Code==G45_IOCTL_SNAPSHOT?sizeof(G45_SNAPSHOT):Code==G45_IOCTL_PMIC?sizeof(G45_PMIC):sizeof(G45_TRIAL);
 if(OutputLength<needed){status=STATUS_BUFFER_TOO_SMALL;goto complete;}
 status=WdfRequestRetrieveOutputBuffer(Request,needed,&output,NULL);if(!NT_SUCCESS(status))goto complete;
 if(Code==G45_IOCTL_STATUS){G45Status((G45_STATUS*)output);status=STATUS_SUCCESS;}
 else if(Code==G45_IOCTL_PMIC){G45CapturePmic((G45_PMIC*)output);status=STATUS_SUCCESS;}
 else if(Code==G45_IOCTL_POWER){G45CaptureTrial((G45_TRIAL*)output);status=STATUS_SUCCESS;}
 else status=G45Snapshot((G45_SNAPSHOT*)output);
 if(NT_SUCCESS(status))information=needed;
 complete:WdfRequestCompleteWithInformation(Request,status,information);
}
VOID G45FileCreate(WDFDEVICE Device,WDFREQUEST Request,WDFFILEOBJECT FileObject)
{
 PUNICODE_STRING name=WdfFileObjectGetFileName(FileObject);UNREFERENCED_PARAMETER(Device);
 WdfRequestComplete(Request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);
}
VOID G45Unload(WDFDRIVER Driver){UNREFERENCED_PARAMETER(Driver);}
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath)
{
 WDF_DRIVER_CONFIG config;WDFDRIVER driver;PWDFDEVICE_INIT init=NULL;WDFDEVICE device;
 WDF_OBJECT_ATTRIBUTES attributes;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG files;NTSTATUS status;
 DECLARE_CONST_UNICODE_STRING(sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
 DECLARE_CONST_UNICODE_STRING(name,L"\\Device\\OpenG45");
 DECLARE_CONST_UNICODE_STRING(link,L"\\DosDevices\\OpenG45");
 WDF_DRIVER_CONFIG_INIT(&config,WDF_NO_EVENT_CALLBACK);config.DriverInitFlags|=WdfDriverInitNonPnpDriver;config.EvtDriverUnload=G45Unload;
 status=WdfDriverCreate(DriverObject,RegistryPath,WDF_NO_OBJECT_ATTRIBUTES,&config,&driver);if(!NT_SUCCESS(status))return status;
 status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 init=WdfControlDeviceInitAllocate(driver,&sddl);if(!init)return STATUS_INSUFFICIENT_RESOURCES;
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);
 WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&files,G45FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);
 WdfDeviceInitSetFileObjectConfig(init,&files,WDF_NO_OBJECT_ATTRIBUTES);
 status=WdfDeviceInitAssignName(init,&name);if(!NT_SUCCESS(status))goto done;
 WDF_OBJECT_ATTRIBUTES_INIT(&attributes);attributes.ExecutionLevel=WdfExecutionLevelPassive;attributes.SynchronizationScope=WdfSynchronizationScopeDevice;
 status=WdfDeviceCreate(&init,&attributes,&device);if(!NT_SUCCESS(status))goto done;
 status=WdfDeviceCreateSymbolicLink(device,&link);if(!NT_SUCCESS(status))goto done;
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfFalse;queue.EvtIoDeviceControl=G45Control;
 status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))goto done;
 WdfControlFinishInitializing(device);
 done:if(init)WdfDeviceInitFree(init);return status;
}
