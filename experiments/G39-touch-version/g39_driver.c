/* SPDX-License-Identifier: MIT
 * Temporary source-built KMDF diagnostic. Fixed qualified register/PMIC reads.
 * This control device is not the eventual PnP bus/regulator owner.
 */
#include <ntddk.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g39_binding.h"
#include "g39_observer.h"
#include "g39_trial.h"
#include "g39_protocol.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G39Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G39Control;
EVT_WDF_DEVICE_FILE_CREATE G39FileCreate;
static volatile LONG64 G39Sequence;
static volatile LONG G39MapCalls;
static volatile LONG G39ObserverAttempts;
static volatile LONG G39ObserverFault;
static volatile LONG G39OffPmicVerified;
static volatile LONG G39TrialUsed;

static VOID G39Status(G39_STATUS *out)
{
 UCHAR table[sizeof(G39ExpectedDsdt)];ULONG bytes=0;
 RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=G39_ABI;out->Magic=G39_MAGIC;
 out->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
 out->CurrentIrql=KeGetCurrentIrql();out->RegisterCount=G39_REGISTER_COUNT;
 out->MapCalls=(ULONG)InterlockedCompareExchange(&G39MapCalls,0,0);
 out->Sequence=(ULONGLONG)InterlockedIncrement64(&G39Sequence);out->InterruptTime=KeQueryInterruptTime();
 RtlCopyMemory(out->BuildId,"G39-touch-id1",13);
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);
 if(NT_SUCCESS(RtlGetVersion(&version)))out->KernelBuild=version.dwBuildNumber;
 RtlZeroMemory(table,sizeof(table));
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);
 out->FirmwareStatus=(ULONG)status;out->FirmwareBytes=bytes;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G39ExpectedDsdt,sizeof(table))==sizeof(table))out->FirmwareMatch=1;
}

static NTSTATUS G39Snapshot(G39_SNAPSHOT *out)
{
 PVOID maps[RTL_NUMBER_OF(G39Ranges)];NTSTATUS status=STATUS_SUCCESS;ULONG i;
 RtlZeroMemory(out,sizeof(*out));G39Status(&out->Status);
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL)return STATUS_NOT_SUPPORTED;
 RtlZeroMemory(maps,sizeof(maps));
 for(i=0;i<RTL_NUMBER_OF(G39Ranges);i++){
  PHYSICAL_ADDRESS address;address.QuadPart=(LONGLONG)G39Ranges[i].Base;
  InterlockedIncrement(&G39MapCalls);
  maps[i]=MmMapIoSpaceEx(address,G39Ranges[i].Bytes,PAGE_READONLY|PAGE_NOCACHE);
  if(maps[i]==NULL){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 }
 for(i=0;i<G39_REGISTER_COUNT;i++){
  const G39_FIELD *field=&G39Fields[i];
  out->Values[i]=READ_REGISTER_ULONG((PULONG)((PUCHAR)maps[field->Range]+field->Offset));
 }
 out->Count=G39_REGISTER_COUNT;
 done:
 for(i=RTL_NUMBER_OF(G39Ranges);i>0;i--)if(maps[i-1])MmUnmapIoSpace(maps[i-1],G39Ranges[i-1].Bytes);
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G39MapCalls,0,0);
 return status;
}

typedef struct {PVOID Maps[7];} G39_OBS_CONTEXT;
static const ULONG G39ObserverPages[6]={0xc400000,0xc402000,0xc42d000,0xc440000,0xc441000,0xc445000};
static PULONG G39ObserverAddress(G39_OBS_CONTEXT *ctx,ULONG at,BOOLEAN write)
{
 ULONG i;
 if((at&3)!=0)return NULL;
 if(write&&at!=0xc440ea0&&at!=0xc441220&&at!=0xc4456e0)return NULL;
 for(i=0;i<6;i++)if(ctx->Maps[i]&&at>=G39ObserverPages[i]&&at-G39ObserverPages[i]<=0xffc){
  if(write&&i<3)return NULL;
  return(PULONG)((PUCHAR)ctx->Maps[i]+at-G39ObserverPages[i]);
 }
 return NULL;
}
static int G39ObserverRead(void *context,uint32_t at,uint32_t *value)
{
 PULONG reg=G39ObserverAddress((G39_OBS_CONTEXT*)context,at,FALSE);
 if(!reg)return 0;*value=READ_REGISTER_ULONG(reg);return 1;
}
static int G39ObserverWrite(void *context,uint32_t at,uint32_t value)
{
 PULONG reg=G39ObserverAddress((G39_OBS_CONTEXT*)context,at,TRUE);
 if(!reg||!((value==0x08000007)||(value==0x08000080)||(value==0x08000407)))return 0;
 WRITE_REGISTER_ULONG(reg,value);return 1;
}
static void G39ObserverWait(void *context){UNREFERENCED_PARAMETER(context);KeStallExecutionProcessor(1);}
static VOID G39CapturePmic(G39_PMIC *out)
{
 G39_OBS_CONTEXT context;G39_OBS_IO io;G39_SNAPSHOT before,after;
 LARGE_INTEGER begin,end,frequency;LONG previous;ULONG i;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&context,sizeof(context));
 G39Status(&out->Status);begin=KeQueryPerformanceCounter(&frequency);
 out->CounterFrequency=(ULONGLONG)frequency.QuadPart;
 previous=InterlockedCompareExchange(&G39ObserverAttempts,0,0);out->Attempt=(ULONG)previous;
 if(InterlockedCompareExchange(&G39ObserverFault,0,0)){out->Observer.Code=1001;goto done;}
 if(previous>=2){out->Observer.Code=1002;goto done;}
 if(InterlockedCompareExchange(&G39ObserverAttempts,previous+1,previous)!=previous){out->Observer.Code=1003;goto done;}
 out->Attempt=(ULONG)previous+1;
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Observer.Code=1004;goto done;}
 status=G39Snapshot(&before);
 if(!NT_SUCCESS(status)||RtlCompareMemory(before.Values,G39ExpectedValues,sizeof(before.Values))!=sizeof(before.Values)){
  out->Observer.Code=1005;goto done;
 }
 for(i=0;i<6;i++){
  PHYSICAL_ADDRESS at;at.QuadPart=G39ObserverPages[i];InterlockedIncrement(&G39MapCalls);
  context.Maps[i]=MmMapIoSpaceEx(at,0x1000,(i<3?PAGE_READONLY:PAGE_READWRITE)|PAGE_NOCACHE);
  if(!context.Maps[i]){out->Observer.Code=1006;goto done;}
 }
 io.Context=&context;io.Read=G39ObserverRead;io.Write=G39ObserverWrite;io.WaitMicrosecond=G39ObserverWait;
 G39Observe(&io,&out->Observer);
 done:
 for(i=6;i>0;i--)if(context.Maps[i-1])MmUnmapIoSpace(context.Maps[i-1],0x1000);
 if(out->Attempt==(ULONG)previous+1){
  if(out->Observer.Code==0){
   status=G39Snapshot(&after);
   if(NT_SUCCESS(status)&&RtlCompareMemory(before.Values,after.Values,sizeof(before.Values))==sizeof(before.Values))out->FixedRegistersUnchanged=1;
   else out->Observer.Code=1007;
  }
  if(out->Observer.Code!=0)InterlockedExchange(&G39ObserverFault,1);
 }
 if(out->Observer.Code==0&&out->FixedRegistersUnchanged){
  static const UCHAR off[8]={8,7,0,0,7,7,0,0};
  InterlockedExchange(&G39OffPmicVerified,out->Observer.Status==0x43&&RtlCompareMemory(out->Observer.Configuration,off,8)==8);
 }
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G39MapCalls,0,0);
 end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(ULONGLONG)(end.QuadPart-begin.QuadPart);
}

typedef struct {PVOID Maps[16];G39_POWER_RESULT*Result;G39_TRIAL_RESULT*Trial;ULONG CommandUsed,CancelUsed,AbortUsed,FifoWords;} G39_PWR_CONTEXT;
static const G39_RANGE G39PowerRanges[16]={{0x17a20000,0x2000},{0x17100000,0x1000},{0xf10a000,0x1000},{0xf118000,0x2000},{0xc400000,0x1000},{0xc402000,0x1000},{0xc42d000,0x1000},{0xc440000,0x1000},{0xc441000,0x1000},{0xc445000,0x1000},{0x152000,0x1000},{0x118000,0x1000},{0x123000,0x1000},{0xf12c000,0x4000},{0xa90000,0x1000},{0xac0000,0x1000}};
static PULONG G39PowerAddress(G39_PWR_CONTEXT*ctx,ULONG at,BOOLEAN write)
{
 ULONG i;if(at&3)return NULL;
 if(write&&at!=0xc440ea0&&at!=0xc441220&&at!=0xc4456e0&&at!=0x17a20d34&&at!=0x17a20d38&&at!=0x17a20d3c&&at!=0x17a20d24&&at!=0x17a20d2c&&at!=0x17a20d08&&
 at!=0xf10a000&&at!=0xf10a004&&at!=0xf118000&&at!=0xf118004&&at!=0xf119000&&at!=0xf11900c&&at!=0x152008&&at!=0xf12c000&&at!=0xf12d000&&at!=0xf12e000&&at!=0xf12f000&&
 !G39EngineWriteAddress(at)&&at!=0xa9026c&&at!=0xa90270&&at!=0xa90600&&at!=0xa90604&&at!=0xa90618&&at!=0xa90700)return NULL;
 for(i=0;i<16;i++)if(ctx->Maps[i]&&at>=G39PowerRanges[i].Base&&at-G39PowerRanges[i].Base+4<=G39PowerRanges[i].Bytes){
  if(write&&i!=0&&i!=2&&i!=3&&i!=7&&i!=8&&i!=9&&i!=10&&i!=13&&i!=14)return NULL;
  return(PULONG)((PUCHAR)ctx->Maps[i]+at-G39PowerRanges[i].Base);
 }
 return NULL;
}
static int G39PowerRead(void*context,uint32_t at,uint32_t*value)
{
 PULONG reg=G39PowerAddress((G39_PWR_CONTEXT*)context,at,FALSE);if(!reg)return 0;*value=READ_REGISTER_ULONG(reg);return 1;
}
static int G39PowerWrite(void*context,uint32_t at,uint32_t value)
{
 G39_PWR_CONTEXT*ctx=context;PULONG reg=G39PowerAddress(ctx,at,TRUE);if(!reg)return 0;
 if(at==0xc440ea0||at==0xc441220||at==0xc4456e0){if(value!=0x08000007&&value!=0x08000080&&value!=0x08000407)return 0;}
 else if(at>=0x17a20000&&at<0x17a22000){if(!G39RscWriteAllowed(at,value))return 0;}
 else if(at==0x152008){if(value!=0x40002380&&value!=0x40102380&&value!=0x40302380&&value!=0x44302380)return 0;}
 else if(at>=0xf12c000&&at<=0xf12f000){if(value!=1&&value!=0x85)return 0;}
 else if(at==0xf10a000){if(value!=1&&value!=0x81&&value!=0x281)return 0;}
 else if(at==0xf118000){if(value!=0x201&&value!=0x2c0)return 0;}
 else if(at==0xf119000){if(value!=1&&value!=0xc0)return 0;}
 else if(at==0xf10a004||at==0xf118004){if(value>3)return 0;}
 else if(at==0xf11900c){if(value)return 0;}
 else if(at==0xa90600){if(value!=0x18000000||ctx->CommandUsed)return 0;ctx->CommandUsed=1;}
 else if(at==0xa90604){
  if(value==4){if(ctx->CancelUsed||ctx->AbortUsed)return 0;ctx->CancelUsed=1;}
  else if(value==2){if(!ctx->CancelUsed||ctx->AbortUsed)return 0;ctx->AbortUsed=1;}else return 0;
 }
 else if(at==0xa90618){if(value&~0x7fc07fffu)return 0;}
 else if(at==0xa9026c||at==0xa90270){if(value!=36&&value!=ctx->Trial->Touch.LengthsBefore[(at-0xa9026c)/4])return 0;}
 else if(at==0xa90700){
  ULONG i=ctx->FifoWords,expected;const UCHAR*tx=ctx->Trial->Touch.Tx;
  if(i>=9)return 0;expected=(ULONG)tx[i*4]|((ULONG)tx[i*4+1]<<8)|((ULONG)tx[i*4+2]<<16)|((ULONG)tx[i*4+3]<<24);
  if(value!=expected)return 0;ctx->FifoWords++;
 }
 else if(!G39EngineWriteAddress(at))return 0;
 WRITE_REGISTER_ULONG(reg,value);return 1;
}
static void G39PowerWait1(void*context)
{
 G39_PWR_CONTEXT*ctx=context;LARGE_INTEGER wait;ctx->Result->Waits1ms++;wait.QuadPart=-10000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}
static void G39PowerWait10(void*context)
{
 LARGE_INTEGER wait;UNREFERENCED_PARAMETER(context);wait.QuadPart=-100000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}
static int G39Barrier(void*context){UNREFERENCED_PARAMETER(context);KeMemoryBarrier();return 0;}
static void G39WaitMs(void*context,uint32_t ms)
{
 LARGE_INTEGER wait;UNREFERENCED_PARAMETER(context);wait.QuadPart=-(LONGLONG)ms*10000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}
static void G39WaitPoll(void*context){UNREFERENCED_PARAMETER(context);KeStallExecutionProcessor(10);}
static uint64_t G39NowUs(void*context)
{
 LARGE_INTEGER frequency,ticks;ULONGLONG f,t;UNREFERENCED_PARAMETER(context);ticks=KeQueryPerformanceCounter(&frequency);f=(ULONGLONG)frequency.QuadPart;t=(ULONGLONG)ticks.QuadPart;return t/f*1000000+(t%f)*1000000/f;
}
static int G39Ready(void*context)
{
 G39_PWR_CONTEXT*ctx=context;G39_OBS_RESULT*p=&ctx->Trial->Touch.PoweredPmic;
 G39_OBS_IO io={context,G39PowerRead,G39PowerWrite,G39ObserverWait};unsigned i;static const UCHAR cfg[8]={8,7,8,7,7,7,128,0};
 G39Observe(&io,p);if(p->Code){ctx->Trial->Power.ObserverUncertain=1;return 0;}
 if(p->Status!=0xc7)return 0;for(i=0;i<8;i++)if(p->Configuration[i]!=cfg[i])return 0;return 1;
}
static int G39NativeTouch(void*context)
{
 G39_PWR_CONTEXT*ctx=context;G39_TOUCH_IO io={context,G39PowerRead,G39PowerWrite,G39Barrier,G39Ready,G39WaitMs,G39WaitPoll,G39NowUs};
 return G39TouchRead(&io,&ctx->Trial->Touch);
}
static int G39Powered(void*context)
{
 G39_PWR_CONTEXT*ctx=context;G39_TRIAL_RESULT*t=ctx->Trial;
 G39_SPI_IO io={context,G39PowerRead,G39PowerWrite,G39ObserverWait,G39NativeTouch};
 t->PoweredHookCalled++;t->Touch.BusQuiescent=1;G39PrepareSpi(&io,&t->Spi);
 t->SafeRelease=(!t->Spi.VoteDirty||t->Spi.Restored)&&(!t->Spi.Engine.Dirty||t->Spi.Engine.Restored)&&!t->Spi.RestoreError&&!t->Spi.Engine.RestoreError&&(!t->Touch.AnalogDirty||t->Touch.Restored)&&t->Touch.BusQuiescent;
 return !t->Spi.Code&&t->Spi.Restored&&t->Touch.TransportOk&&t->Touch.IdentityOk&&t->Touch.Restored;
}
static int G39SafeRelease(void*context){return((G39_PWR_CONTEXT*)context)->Trial->SafeRelease!=0;}
static VOID G39CaptureTrial(G39_TRIAL*out)
{
 G39_PWR_CONTEXT context;G39_POWER_IO io;G39_SNAPSHOT before,after;
 LARGE_INTEGER begin,end,frequency;ULONG i;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&context,sizeof(context));G39Status(&out->Status);context.Trial=&out->Trial;context.Result=&out->Trial.Power;out->Trial.SafeRelease=1;
 begin=KeQueryPerformanceCounter(&frequency);out->CounterFrequency=(ULONGLONG)frequency.QuadPart;
 if(InterlockedCompareExchange(&G39TrialUsed,1,0)!=0){out->Trial.Power.Code=1002;goto done;}
 out->Attempt=1;
 if(InterlockedCompareExchange(&G39ObserverAttempts,0,0)!=1||!InterlockedCompareExchange(&G39OffPmicVerified,0,0)||InterlockedCompareExchange(&G39ObserverFault,0,0)){out->Trial.Power.Code=1003;goto done;}
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Trial.Power.Code=1004;goto done;}
 status=G39Snapshot(&before);
 if(!NT_SUCCESS(status)||RtlCompareMemory(before.Values,G39ExpectedValues,sizeof(before.Values))!=sizeof(before.Values)){out->Trial.Power.Code=1005;goto done;}
 for(i=0;i<16;i++){
  PHYSICAL_ADDRESS at;at.QuadPart=(LONGLONG)G39PowerRanges[i].Base;InterlockedIncrement(&G39MapCalls);
  context.Maps[i]=MmMapIoSpaceEx(at,G39PowerRanges[i].Bytes,(i==0||i==2||i==3||i==7||i==8||i==9||i==10||i==13||i==14?PAGE_READWRITE:PAGE_READONLY)|PAGE_NOCACHE);
  if(!context.Maps[i]){out->Trial.Power.Code=1006;goto done;}
 }
 io.Rsc.Context=&context;io.Rsc.Read=G39PowerRead;io.Rsc.Write=G39PowerWrite;io.Rsc.WaitMillisecond=G39PowerWait1;
 io.Observer.Context=&context;io.Observer.Read=G39PowerRead;io.Observer.Write=G39PowerWrite;io.Observer.WaitMicrosecond=G39ObserverWait;io.WaitTenMilliseconds=G39PowerWait10;io.Powered=G39Powered;io.SafeToRelease=G39SafeRelease;
 G39PowerTrial(&io,&out->Trial.Power);
 done:
 for(i=16;i>0;i--)if(context.Maps[i-1])MmUnmapIoSpace(context.Maps[i-1],G39PowerRanges[i-1].Bytes);
 if(out->Trial.Power.Code<1000){
  status=G39Snapshot(&after);
  if(NT_SUCCESS(status)&&RtlCompareMemory(before.Values,after.Values,sizeof(before.Values))==sizeof(before.Values))out->FixedRegistersUnchanged=1;
  else if(!out->Trial.Power.Code)out->Trial.Power.Code=1007;
 }
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G39MapCalls,0,0);
 end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(ULONGLONG)(end.QuadPart-begin.QuadPart);
}

VOID G39Control(WDFQUEUE Queue,WDFREQUEST Request,size_t OutputLength,size_t InputLength,ULONG Code)
{
 G39_REQUEST *input;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;
 UNREFERENCED_PARAMETER(Queue);
 if(Code!=G39_IOCTL_STATUS&&Code!=G39_IOCTL_SNAPSHOT&&Code!=G39_IOCTL_PMIC&&Code!=G39_IOCTL_POWER){status=STATUS_INVALID_DEVICE_REQUEST;goto complete;}
 if(InputLength!=sizeof(G39_REQUEST)){status=STATUS_INVALID_PARAMETER;goto complete;}
 status=WdfRequestRetrieveInputBuffer(Request,sizeof(G39_REQUEST),(PVOID*)&input,NULL);
 if(!NT_SUCCESS(status))goto complete;
 if(input->Size!=sizeof(*input)||input->Version!=G39_ABI||input->Magic!=G39_MAGIC){status=STATUS_INVALID_PARAMETER;goto complete;}
 needed=Code==G39_IOCTL_STATUS?sizeof(G39_STATUS):Code==G39_IOCTL_SNAPSHOT?sizeof(G39_SNAPSHOT):Code==G39_IOCTL_PMIC?sizeof(G39_PMIC):sizeof(G39_TRIAL);
 if(OutputLength<needed){status=STATUS_BUFFER_TOO_SMALL;goto complete;}
 status=WdfRequestRetrieveOutputBuffer(Request,needed,&output,NULL);if(!NT_SUCCESS(status))goto complete;
 if(Code==G39_IOCTL_STATUS){G39Status((G39_STATUS*)output);status=STATUS_SUCCESS;}
 else if(Code==G39_IOCTL_PMIC){G39CapturePmic((G39_PMIC*)output);status=STATUS_SUCCESS;}
 else if(Code==G39_IOCTL_POWER){G39CaptureTrial((G39_TRIAL*)output);status=STATUS_SUCCESS;}
 else status=G39Snapshot((G39_SNAPSHOT*)output);
 if(NT_SUCCESS(status))information=needed;
 complete:WdfRequestCompleteWithInformation(Request,status,information);
}
VOID G39FileCreate(WDFDEVICE Device,WDFREQUEST Request,WDFFILEOBJECT FileObject)
{
 PUNICODE_STRING name=WdfFileObjectGetFileName(FileObject);UNREFERENCED_PARAMETER(Device);
 WdfRequestComplete(Request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);
}
VOID G39Unload(WDFDRIVER Driver){UNREFERENCED_PARAMETER(Driver);}
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath)
{
 WDF_DRIVER_CONFIG config;WDFDRIVER driver;PWDFDEVICE_INIT init=NULL;WDFDEVICE device;
 WDF_OBJECT_ATTRIBUTES attributes;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG files;NTSTATUS status;
 DECLARE_CONST_UNICODE_STRING(sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
 DECLARE_CONST_UNICODE_STRING(name,L"\\Device\\OpenG39");
 DECLARE_CONST_UNICODE_STRING(link,L"\\DosDevices\\OpenG39");
 WDF_DRIVER_CONFIG_INIT(&config,WDF_NO_EVENT_CALLBACK);config.DriverInitFlags|=WdfDriverInitNonPnpDriver;config.EvtDriverUnload=G39Unload;
 status=WdfDriverCreate(DriverObject,RegistryPath,WDF_NO_OBJECT_ATTRIBUTES,&config,&driver);if(!NT_SUCCESS(status))return status;
 status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 init=WdfControlDeviceInitAllocate(driver,&sddl);if(!init)return STATUS_INSUFFICIENT_RESOURCES;
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);
 WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&files,G39FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);
 WdfDeviceInitSetFileObjectConfig(init,&files,WDF_NO_OBJECT_ATTRIBUTES);
 status=WdfDeviceInitAssignName(init,&name);if(!NT_SUCCESS(status))goto done;
 WDF_OBJECT_ATTRIBUTES_INIT(&attributes);attributes.ExecutionLevel=WdfExecutionLevelPassive;attributes.SynchronizationScope=WdfSynchronizationScopeDevice;
 status=WdfDeviceCreate(&init,&attributes,&device);if(!NT_SUCCESS(status))goto done;
 status=WdfDeviceCreateSymbolicLink(device,&link);if(!NT_SUCCESS(status))goto done;
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfFalse;queue.EvtIoDeviceControl=G39Control;
 status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))goto done;
 WdfControlFinishInitializing(device);
 done:if(init)WdfDeviceInitFree(init);return status;
}
