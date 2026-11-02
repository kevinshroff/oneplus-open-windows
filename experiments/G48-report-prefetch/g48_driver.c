/* SPDX-License-Identifier: MIT
 * Temporary source-built KMDF diagnostic. Fixed qualified register/PMIC reads.
 * This control device is not the eventual PnP bus/regulator owner.
 */
#include <ntddk.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g48_binding.h"
#include "g48_observer.h"
#include "g48_trial.h"
#include "g48_protocol.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G48Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G48Control;
EVT_WDF_DEVICE_FILE_CREATE G48FileCreate;
static volatile LONG64 G48Sequence;
static volatile LONG G48MapCalls;
static volatile LONG G48ObserverAttempts;
static volatile LONG G48ObserverFault;
static volatile LONG G48OffPmicVerified;
static volatile LONG G48TrialUsed;

static VOID G48Status(G48_STATUS *out)
{
 UCHAR table[sizeof(G48ExpectedDsdt)];ULONG bytes=0;
 RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=G48_ABI;out->Magic=G48_MAGIC;
 out->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
 out->CurrentIrql=KeGetCurrentIrql();out->RegisterCount=G48_REGISTER_COUNT;
 out->MapCalls=(ULONG)InterlockedCompareExchange(&G48MapCalls,0,0);
 out->Sequence=(ULONGLONG)InterlockedIncrement64(&G48Sequence);out->InterruptTime=KeQueryInterruptTime();
 RtlCopyMemory(out->BuildId,"G48-report1",sizeof("G48-report1"));
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);
 if(NT_SUCCESS(RtlGetVersion(&version)))out->KernelBuild=version.dwBuildNumber;
 RtlZeroMemory(table,sizeof(table));
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);
 out->FirmwareStatus=(ULONG)status;out->FirmwareBytes=bytes;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G48ExpectedDsdt,sizeof(table))==sizeof(table))out->FirmwareMatch=1;
}

static NTSTATUS G48Snapshot(G48_SNAPSHOT *out)
{
 PVOID maps[RTL_NUMBER_OF(G48Ranges)];NTSTATUS status=STATUS_SUCCESS;ULONG i;
 RtlZeroMemory(out,sizeof(*out));G48Status(&out->Status);
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL)return STATUS_NOT_SUPPORTED;
 RtlZeroMemory(maps,sizeof(maps));
 for(i=0;i<RTL_NUMBER_OF(G48Ranges);i++){
  PHYSICAL_ADDRESS address;address.QuadPart=(LONGLONG)G48Ranges[i].Base;
  InterlockedIncrement(&G48MapCalls);
  maps[i]=MmMapIoSpaceEx(address,G48Ranges[i].Bytes,PAGE_READONLY|PAGE_NOCACHE);
  if(maps[i]==NULL){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 }
 for(i=0;i<G48_REGISTER_COUNT;i++){
  const G48_FIELD *field=&G48Fields[i];
  out->Values[i]=READ_REGISTER_ULONG((PULONG)((PUCHAR)maps[field->Range]+field->Offset));
 }
 out->Count=G48_REGISTER_COUNT;
 done:
 for(i=RTL_NUMBER_OF(G48Ranges);i>0;i--)if(maps[i-1])MmUnmapIoSpace(maps[i-1],G48Ranges[i-1].Bytes);
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G48MapCalls,0,0);
 return status;
}

/* RESP_DATA is read-only transaction history: reset observed0, final MODE
 * query observed7. It is never writable or part of exact register undo.
 * Keep it reported and allow only these two separately observed boundaries;
 * every other one of the fixed50 words must still match exactly. */
static int G48FixedBaseline(const ULONG*values)
{
 if(G48_REGISTER_COUNT!=50||G48Fields[12].Range!=0||G48Fields[12].Offset!=0xd44||G48Ranges[0].Base!=0x17a20000)return 0;
 ULONG i;for(i=0;i<G48_REGISTER_COUNT;i++){
  if(i==12){if(values[i]!=0&&values[i]!=7)return 0;}
  else if(values[i]!=G48ExpectedValues[i])return 0;
 }return 1;
}
static int G48FixedSameRestorable(const ULONG*before,const ULONG*after)
{
 ULONG i;if(!G48FixedBaseline(before)||!G48FixedBaseline(after))return 0;
 for(i=0;i<G48_REGISTER_COUNT;i++)if(i!=12&&before[i]!=after[i])return 0;
 return 1;
}

typedef struct {PVOID Maps[7];} G48_OBS_CONTEXT;
static const ULONG G48ObserverPages[6]={0xc400000,0xc402000,0xc42d000,0xc440000,0xc441000,0xc445000};
static PULONG G48ObserverAddress(G48_OBS_CONTEXT *ctx,ULONG at,BOOLEAN write)
{
 ULONG i;
 if((at&3)!=0)return NULL;
 if(write&&at!=0xc440ea0&&at!=0xc441220&&at!=0xc4456e0)return NULL;
 for(i=0;i<6;i++)if(ctx->Maps[i]&&at>=G48ObserverPages[i]&&at-G48ObserverPages[i]<=0xffc){
  if(write&&i<3)return NULL;
  return(PULONG)((PUCHAR)ctx->Maps[i]+at-G48ObserverPages[i]);
 }
 return NULL;
}
static int G48ObserverRead(void *context,uint32_t at,uint32_t *value)
{
 PULONG reg=G48ObserverAddress((G48_OBS_CONTEXT*)context,at,FALSE);
 if(!reg)return 0;*value=READ_REGISTER_ULONG(reg);return 1;
}
static int G48ObserverWrite(void *context,uint32_t at,uint32_t value)
{
 PULONG reg=G48ObserverAddress((G48_OBS_CONTEXT*)context,at,TRUE);
 if(!reg||!((value==0x08000007)||(value==0x08000080)||(value==0x08000407)))return 0;
 WRITE_REGISTER_ULONG(reg,value);return 1;
}
static void G48ObserverWait(void *context){UNREFERENCED_PARAMETER(context);KeStallExecutionProcessor(1);}
static VOID G48CapturePmic(G48_PMIC *out)
{
 G48_OBS_CONTEXT context;G48_OBS_IO io;G48_SNAPSHOT before,after;
 LARGE_INTEGER begin,end,frequency;LONG previous;ULONG i;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&context,sizeof(context));
 G48Status(&out->Status);begin=KeQueryPerformanceCounter(&frequency);
 out->CounterFrequency=(ULONGLONG)frequency.QuadPart;
 previous=InterlockedCompareExchange(&G48ObserverAttempts,0,0);out->Attempt=(ULONG)previous;
 if(InterlockedCompareExchange(&G48ObserverFault,0,0)){out->Observer.Code=1001;goto done;}
 if(previous>=2){out->Observer.Code=1002;goto done;}
 if(InterlockedCompareExchange(&G48ObserverAttempts,previous+1,previous)!=previous){out->Observer.Code=1003;goto done;}
 out->Attempt=(ULONG)previous+1;
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Observer.Code=1004;goto done;}
 status=G48Snapshot(&before);
 if(!NT_SUCCESS(status)||!G48FixedBaseline(before.Values)){
  out->Observer.Code=1005;goto done;
 }
 for(i=0;i<6;i++){
  PHYSICAL_ADDRESS at;at.QuadPart=G48ObserverPages[i];InterlockedIncrement(&G48MapCalls);
  context.Maps[i]=MmMapIoSpaceEx(at,0x1000,(i<3?PAGE_READONLY:PAGE_READWRITE)|PAGE_NOCACHE);
  if(!context.Maps[i]){out->Observer.Code=1006;goto done;}
 }
 io.Context=&context;io.Read=G48ObserverRead;io.Write=G48ObserverWrite;io.WaitMicrosecond=G48ObserverWait;
 G48Observe(&io,&out->Observer);
 done:
 for(i=6;i>0;i--)if(context.Maps[i-1])MmUnmapIoSpace(context.Maps[i-1],0x1000);
 if(out->Attempt==(ULONG)previous+1){
  if(out->Observer.Code==0){
   status=G48Snapshot(&after);
   if(NT_SUCCESS(status)&&RtlCompareMemory(before.Values,after.Values,sizeof(before.Values))==sizeof(before.Values))out->FixedRegistersUnchanged=1;
   else out->Observer.Code=1007;
  }
  if(out->Observer.Code!=0)InterlockedExchange(&G48ObserverFault,1);
 }
 if(out->Observer.Code==0&&out->FixedRegistersUnchanged){
  static const UCHAR off[8]={8,7,0,0,7,7,0,0};
  InterlockedExchange(&G48OffPmicVerified,out->Observer.Status==0x43&&RtlCompareMemory(out->Observer.Configuration,off,8)==8);
 }
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G48MapCalls,0,0);
 end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(ULONGLONG)(end.QuadPart-begin.QuadPart);
}

typedef struct {PVOID Maps[16];G48_POWER_RESULT*Result;G48_TRIAL_RESULT*Trial;ULONG CommandUsed,CancelUsed,AbortUsed,FifoWords,LastM,LastS,HaveM,HaveS,SAcks;} G48_PWR_CONTEXT;
static const G48_RANGE G48PowerRanges[16]={{0x17a20000,0x2000},{0x17100000,0x1000},{0xf10a000,0x1000},{0xf118000,0x2000},{0xc400000,0x1000},{0xc402000,0x1000},{0xc42d000,0x1000},{0xc440000,0x1000},{0xc441000,0x1000},{0xc445000,0x1000},{0x152000,0x1000},{0x118000,0x1000},{0x123000,0x1000},{0xf12c000,0x4000},{0xa90000,0x1000},{0xac0000,0x1000}};
static PULONG G48PowerAddress(G48_PWR_CONTEXT*ctx,ULONG at,BOOLEAN write)
{
 ULONG i;if(at&3)return NULL;
 if(write&&at!=0xc440ea0&&at!=0xc441220&&at!=0xc4456e0&&at!=0x17a20d34&&at!=0x17a20d38&&at!=0x17a20d3c&&at!=0x17a20d24&&at!=0x17a20d2c&&at!=0x17a20d08&&
 at!=0xf10a000&&at!=0xf10a004&&at!=0xf118000&&at!=0xf118004&&at!=0xf119000&&at!=0xf11900c&&at!=0x152008&&at!=0xf12c000&&at!=0xf12d000&&at!=0xf12e000&&at!=0xf12f000&&
 !G48EngineWriteAddress(at)&&at!=0xa9026c&&at!=0xa90270&&at!=0xa90600&&at!=0xa90604&&at!=0xa90618&&at!=0xa90648&&at!=0xa90700)return NULL;
 for(i=0;i<16;i++)if(ctx->Maps[i]&&at>=G48PowerRanges[i].Base&&at-G48PowerRanges[i].Base+4<=G48PowerRanges[i].Bytes){
  if(write&&i!=0&&i!=2&&i!=3&&i!=7&&i!=8&&i!=9&&i!=10&&i!=13&&i!=14)return NULL;
  return(PULONG)((PUCHAR)ctx->Maps[i]+at-G48PowerRanges[i].Base);
 }
 return NULL;
}
static int G48PowerRead(void*context,uint32_t at,uint32_t*value)
{
 G48_PWR_CONTEXT*ctx=context;PULONG reg=G48PowerAddress(ctx,at,FALSE);if(!reg)return 0;*value=READ_REGISTER_ULONG(reg);
 if(at==0xa90610){ctx->LastM=*value;ctx->HaveM=1;}if(at==0xa90640){ctx->LastS=*value;ctx->HaveS=1;}return 1;
}
static int G48PowerWrite(void*context,uint32_t at,uint32_t value)
{
 G48_PWR_CONTEXT*ctx=context;PULONG reg=G48PowerAddress(ctx,at,TRUE);if(!reg)return 0;
 if(at==0xc440ea0||at==0xc441220||at==0xc4456e0){if(value!=0x08000007&&value!=0x08000080&&value!=0x08000407)return 0;}
 else if(at>=0x17a20000&&at<0x17a22000){if(!G48RscWriteAllowed(at,value))return 0;}
 else if(at==0x152008){if(value!=0x40002380&&value!=0x40102380&&value!=0x40302380&&value!=0x44302380)return 0;}
 else if(at>=0xf12c000&&at<=0xf12f000){if(value!=1&&value!=0x85)return 0;}
 else if(at==0xf10a000){if(value!=1&&value!=0x81&&value!=0x281)return 0;}
 else if(at==0xf118000){if(value!=0x201&&value!=0x2c0)return 0;}
 else if(at==0xf119000){if(value!=1&&value!=0xc0)return 0;}
 else if(at==0xf10a004||at==0xf118004){if(value>3)return 0;}
 else if(at==0xf11900c){if(value)return 0;}
 else if(at==0xa90600){if(value!=0x18000000||ctx->CommandUsed>=2)return 0;if(ctx->CommandUsed==1&&(!ctx->Trial->Touch.FullBlockChecksumValid||!ctx->Trial->Touch.Report.ContractVerified||!ctx->Trial->Touch.BusQuiescent||ctx->FifoWords!=63))return 0;ctx->CommandUsed++;ctx->FifoWords=0;ctx->HaveM=ctx->HaveS=ctx->SAcks=0;}
 else if(at==0xa90604){
  if(!ctx->CommandUsed)return 0;
  if(value==4){if(ctx->CancelUsed||ctx->AbortUsed)return 0;ctx->CancelUsed=1;}
  else if(value==2){if(!ctx->CancelUsed||ctx->AbortUsed)return 0;ctx->AbortUsed=1;}else return 0;
 }
 else if(at==0xa90618){if(!ctx->CommandUsed||!ctx->HaveM||value!=ctx->LastM)return 0;ctx->HaveM=0;}
 else if(at==0xa90648){if(!ctx->CommandUsed||!ctx->HaveS||value!=ctx->LastS||ctx->SAcks)return 0;ctx->HaveS=0;ctx->SAcks++;}
 else if(at==0xa9026c||at==0xa90270){if(value!=(ctx->CommandUsed==0?250u:34u)&&value!=ctx->Trial->Touch.LengthsBefore[(at-0xa9026c)/4])return 0;}
 else if(at==0xa90700){
  ULONG i=ctx->FifoWords,expected;const UCHAR*tx=ctx->CommandUsed==2?ctx->Trial->Touch.Report.Tx:ctx->Trial->Touch.Tx;
  if(!ctx->CommandUsed||i>=(ctx->CommandUsed==1?63u:9u))return 0;expected=(ULONG)tx[i*4]|((ULONG)tx[i*4+1]<<8)|((ULONG)tx[i*4+2]<<16)|((ULONG)tx[i*4+3]<<24);
  if(value!=expected)return 0;ctx->FifoWords++;
 }
 else if(!G48EngineWriteAddress(at))return 0;
 WRITE_REGISTER_ULONG(reg,value);return 1;
}
static void G48PowerWait1(void*context)
{
 G48_PWR_CONTEXT*ctx=context;LARGE_INTEGER wait;ctx->Result->Waits1ms++;wait.QuadPart=-10000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}
static void G48PowerWait10(void*context)
{
 LARGE_INTEGER wait;UNREFERENCED_PARAMETER(context);wait.QuadPart=-100000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}
static int G48Barrier(void*context){UNREFERENCED_PARAMETER(context);KeMemoryBarrier();return 0;}
static void G48WaitMs(void*context,uint32_t ms)
{
 LARGE_INTEGER wait;UNREFERENCED_PARAMETER(context);wait.QuadPart=-(LONGLONG)ms*10000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}
static void G48WaitPoll(void*context){UNREFERENCED_PARAMETER(context);KeStallExecutionProcessor(10);}
static uint64_t G48NowUs(void*context)
{
 LARGE_INTEGER frequency,ticks;ULONGLONG f,t;UNREFERENCED_PARAMETER(context);ticks=KeQueryPerformanceCounter(&frequency);f=(ULONGLONG)frequency.QuadPart;t=(ULONGLONG)ticks.QuadPart;return t/f*1000000+(t%f)*1000000/f;
}
static int G48Ready(void*context)
{
 G48_PWR_CONTEXT*ctx=context;G48_OBS_RESULT*p=&ctx->Trial->Touch.PoweredPmic;
 G48_OBS_IO io={context,G48PowerRead,G48PowerWrite,G48ObserverWait};unsigned i;static const UCHAR cfg[8]={8,7,8,7,7,7,128,0};
 G48Observe(&io,p);if(p->Code){ctx->Trial->Power.ObserverUncertain=1;return 0;}
 if(p->Status!=0xc7)return 0;for(i=0;i<8;i++)if(p->Configuration[i]!=cfg[i])return 0;return 1;
}
static int G48NativeTouch(void*context)
{
 G48_PWR_CONTEXT*ctx=context;G48_TOUCH_IO io={context,G48PowerRead,G48PowerWrite,G48Barrier,G48Ready,G48WaitMs,G48WaitPoll,G48NowUs};
 return G48TouchRead(&io,&ctx->Trial->Touch);
}
static int G48Powered(void*context)
{
 G48_PWR_CONTEXT*ctx=context;G48_TRIAL_RESULT*t=ctx->Trial;
 G48_SPI_IO io={context,G48PowerRead,G48PowerWrite,G48ObserverWait,G48NativeTouch};
 t->PoweredHookCalled++;t->Touch.BusQuiescent=1;G48PrepareSpi(&io,&t->Spi);
 t->SafeRelease=(!t->Spi.VoteDirty||t->Spi.Restored)&&(!t->Spi.Engine.Dirty||t->Spi.Engine.Restored)&&!t->Spi.RestoreError&&!t->Spi.Engine.RestoreError&&(!t->Touch.AnalogDirty||t->Touch.Restored)&&t->Touch.BusQuiescent;
 return !t->Spi.Code&&t->Spi.Restored&&t->Touch.TransportOk&&t->Touch.FullBlockChecksumValid&&t->Touch.Report.ContractVerified&&t->Touch.Report.TransportOk&&t->Touch.Restored;
}
static int G48SafeRelease(void*context){return((G48_PWR_CONTEXT*)context)->Trial->SafeRelease!=0;}
static VOID G48CaptureTrial(G48_TRIAL*out)
{
 G48_PWR_CONTEXT context;G48_POWER_IO io;G48_SNAPSHOT before,after;
 LARGE_INTEGER begin,end,frequency;ULONG i;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&context,sizeof(context));G48Status(&out->Status);context.Trial=&out->Trial;context.Result=&out->Trial.Power;out->Trial.SafeRelease=1;
 begin=KeQueryPerformanceCounter(&frequency);out->CounterFrequency=(ULONGLONG)frequency.QuadPart;
 if(InterlockedCompareExchange(&G48TrialUsed,1,0)!=0){out->Trial.Power.Code=1002;goto done;}
 out->Attempt=1;
 if(InterlockedCompareExchange(&G48ObserverAttempts,0,0)!=1||!InterlockedCompareExchange(&G48OffPmicVerified,0,0)||InterlockedCompareExchange(&G48ObserverFault,0,0)){out->Trial.Power.Code=1003;goto done;}
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Trial.Power.Code=1004;goto done;}
 status=G48Snapshot(&before);
 if(!NT_SUCCESS(status)||!G48FixedBaseline(before.Values)){out->Trial.Power.Code=1005;goto done;}
 for(i=0;i<16;i++){
  PHYSICAL_ADDRESS at;at.QuadPart=(LONGLONG)G48PowerRanges[i].Base;InterlockedIncrement(&G48MapCalls);
  context.Maps[i]=MmMapIoSpaceEx(at,G48PowerRanges[i].Bytes,(i==0||i==2||i==3||i==7||i==8||i==9||i==10||i==13||i==14?PAGE_READWRITE:PAGE_READONLY)|PAGE_NOCACHE);
  if(!context.Maps[i]){out->Trial.Power.Code=1006;goto done;}
 }
 io.Rsc.Context=&context;io.Rsc.Read=G48PowerRead;io.Rsc.Write=G48PowerWrite;io.Rsc.WaitMillisecond=G48PowerWait1;
 io.Observer.Context=&context;io.Observer.Read=G48PowerRead;io.Observer.Write=G48PowerWrite;io.Observer.WaitMicrosecond=G48ObserverWait;io.WaitTenMilliseconds=G48PowerWait10;io.Powered=G48Powered;io.SafeToRelease=G48SafeRelease;
 G48PowerTrial(&io,&out->Trial.Power);
 if(out->Trial.Power.Restored&&out->Trial.Touch.Restored){
  G48_TOUCH_IO finalIo={&context,G48PowerRead,G48PowerWrite,G48Barrier,G48Ready,G48WaitMs,G48WaitPoll,G48NowUs};
  if(!G48VerifyTouchOff(&finalIo,&out->Trial.Touch)){out->Trial.Power.Restored=0;if(!out->Trial.Power.Code)out->Trial.Power.Code=109;}
 }
 done:
 for(i=16;i>0;i--)if(context.Maps[i-1])MmUnmapIoSpace(context.Maps[i-1],G48PowerRanges[i-1].Bytes);
 if(out->Trial.Power.Code<1000){
  status=G48Snapshot(&after);
  if(NT_SUCCESS(status)&&G48FixedSameRestorable(before.Values,after.Values))out->FixedRegistersUnchanged=1;
  else if(!out->Trial.Power.Code)out->Trial.Power.Code=1007;
 }
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G48MapCalls,0,0);
 end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(ULONGLONG)(end.QuadPart-begin.QuadPart);
}

VOID G48Control(WDFQUEUE Queue,WDFREQUEST Request,size_t OutputLength,size_t InputLength,ULONG Code)
{
 G48_REQUEST *input;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;
 UNREFERENCED_PARAMETER(Queue);
 if(Code!=G48_IOCTL_STATUS&&Code!=G48_IOCTL_SNAPSHOT&&Code!=G48_IOCTL_PMIC&&Code!=G48_IOCTL_POWER){status=STATUS_INVALID_DEVICE_REQUEST;goto complete;}
 if(InputLength!=sizeof(G48_REQUEST)){status=STATUS_INVALID_PARAMETER;goto complete;}
 status=WdfRequestRetrieveInputBuffer(Request,sizeof(G48_REQUEST),(PVOID*)&input,NULL);
 if(!NT_SUCCESS(status))goto complete;
 if(input->Size!=sizeof(*input)||input->Version!=G48_ABI||input->Magic!=G48_MAGIC){status=STATUS_INVALID_PARAMETER;goto complete;}
 needed=Code==G48_IOCTL_STATUS?sizeof(G48_STATUS):Code==G48_IOCTL_SNAPSHOT?sizeof(G48_SNAPSHOT):Code==G48_IOCTL_PMIC?sizeof(G48_PMIC):sizeof(G48_TRIAL);
 if(OutputLength<needed){status=STATUS_BUFFER_TOO_SMALL;goto complete;}
 status=WdfRequestRetrieveOutputBuffer(Request,needed,&output,NULL);if(!NT_SUCCESS(status))goto complete;
 if(Code==G48_IOCTL_STATUS){G48Status((G48_STATUS*)output);status=STATUS_SUCCESS;}
 else if(Code==G48_IOCTL_PMIC){G48CapturePmic((G48_PMIC*)output);status=STATUS_SUCCESS;}
 else if(Code==G48_IOCTL_POWER){G48CaptureTrial((G48_TRIAL*)output);status=STATUS_SUCCESS;}
 else status=G48Snapshot((G48_SNAPSHOT*)output);
 if(NT_SUCCESS(status))information=needed;
 complete:WdfRequestCompleteWithInformation(Request,status,information);
}
VOID G48FileCreate(WDFDEVICE Device,WDFREQUEST Request,WDFFILEOBJECT FileObject)
{
 PUNICODE_STRING name=WdfFileObjectGetFileName(FileObject);UNREFERENCED_PARAMETER(Device);
 WdfRequestComplete(Request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);
}
VOID G48Unload(WDFDRIVER Driver){UNREFERENCED_PARAMETER(Driver);}
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath)
{
 WDF_DRIVER_CONFIG config;WDFDRIVER driver;PWDFDEVICE_INIT init=NULL;WDFDEVICE device;
 WDF_OBJECT_ATTRIBUTES attributes;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG files;NTSTATUS status;
 DECLARE_CONST_UNICODE_STRING(sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
 DECLARE_CONST_UNICODE_STRING(name,L"\\Device\\OpenG48");
 DECLARE_CONST_UNICODE_STRING(link,L"\\DosDevices\\OpenG48");
 WDF_DRIVER_CONFIG_INIT(&config,WDF_NO_EVENT_CALLBACK);config.DriverInitFlags|=WdfDriverInitNonPnpDriver;config.EvtDriverUnload=G48Unload;
 status=WdfDriverCreate(DriverObject,RegistryPath,WDF_NO_OBJECT_ATTRIBUTES,&config,&driver);if(!NT_SUCCESS(status))return status;
 status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 init=WdfControlDeviceInitAllocate(driver,&sddl);if(!init)return STATUS_INSUFFICIENT_RESOURCES;
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);
 WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&files,G48FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);
 WdfDeviceInitSetFileObjectConfig(init,&files,WDF_NO_OBJECT_ATTRIBUTES);
 status=WdfDeviceInitAssignName(init,&name);if(!NT_SUCCESS(status))goto done;
 WDF_OBJECT_ATTRIBUTES_INIT(&attributes);attributes.ExecutionLevel=WdfExecutionLevelPassive;attributes.SynchronizationScope=WdfSynchronizationScopeDevice;
 status=WdfDeviceCreate(&init,&attributes,&device);if(!NT_SUCCESS(status))goto done;
 status=WdfDeviceCreateSymbolicLink(device,&link);if(!NT_SUCCESS(status))goto done;
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfFalse;queue.EvtIoDeviceControl=G48Control;
 status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))goto done;
 WdfControlFinishInitializing(device);
 done:if(init)WdfDeviceInitFree(init);return status;
}
