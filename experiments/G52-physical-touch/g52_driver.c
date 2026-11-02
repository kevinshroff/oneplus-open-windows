/* SPDX-License-Identifier: MIT
 * Temporary source-built KMDF diagnostic. Fixed qualified register/PMIC reads.
 * This control device is not the eventual PnP bus/regulator owner.
 */
#include <ntddk.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g52_binding.h"
#include "g52_observer.h"
#include "g52_trial.h"
#include "g52_protocol.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G52Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G52Control;
EVT_WDF_DEVICE_FILE_CREATE G52FileCreate;
static volatile LONG64 G52Sequence;
static volatile LONG G52MapCalls;
static volatile LONG G52ObserverAttempts;
static volatile LONG G52ObserverFault;
static volatile LONG G52OffPmicVerified;
static volatile LONG G52TrialUsed;

static VOID G52Status(G52_STATUS *out)
{
 UCHAR table[sizeof(G52ExpectedDsdt)];ULONG bytes=0;
 RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=G52_ABI;out->Magic=G52_MAGIC;
 out->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
 out->CurrentIrql=KeGetCurrentIrql();out->RegisterCount=G52_REGISTER_COUNT;
 out->MapCalls=(ULONG)InterlockedCompareExchange(&G52MapCalls,0,0);
 out->Sequence=(ULONGLONG)InterlockedIncrement64(&G52Sequence);out->InterruptTime=KeQueryInterruptTime();
 RtlCopyMemory(out->BuildId,"G52-capture1",sizeof("G52-capture1"));
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);
 if(NT_SUCCESS(RtlGetVersion(&version)))out->KernelBuild=version.dwBuildNumber;
 RtlZeroMemory(table,sizeof(table));
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);
 out->FirmwareStatus=(ULONG)status;out->FirmwareBytes=bytes;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G52ExpectedDsdt,sizeof(table))==sizeof(table))out->FirmwareMatch=1;
}

static NTSTATUS G52Snapshot(G52_SNAPSHOT *out)
{
 PVOID maps[RTL_NUMBER_OF(G52Ranges)];NTSTATUS status=STATUS_SUCCESS;ULONG i;
 RtlZeroMemory(out,sizeof(*out));G52Status(&out->Status);
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL)return STATUS_NOT_SUPPORTED;
 RtlZeroMemory(maps,sizeof(maps));
 for(i=0;i<RTL_NUMBER_OF(G52Ranges);i++){
  PHYSICAL_ADDRESS address;address.QuadPart=(LONGLONG)G52Ranges[i].Base;
  InterlockedIncrement(&G52MapCalls);
  maps[i]=MmMapIoSpaceEx(address,G52Ranges[i].Bytes,PAGE_READONLY|PAGE_NOCACHE);
  if(maps[i]==NULL){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 }
 for(i=0;i<G52_REGISTER_COUNT;i++){
  const G52_FIELD *field=&G52Fields[i];
  out->Values[i]=READ_REGISTER_ULONG((PULONG)((PUCHAR)maps[field->Range]+field->Offset));
 }
 out->Count=G52_REGISTER_COUNT;
 done:
 for(i=RTL_NUMBER_OF(G52Ranges);i>0;i--)if(maps[i-1])MmUnmapIoSpace(maps[i-1],G52Ranges[i-1].Bytes);
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G52MapCalls,0,0);
 return status;
}

/* RESP_DATA is read-only transaction history: reset observed0, final MODE
 * query observed7. It is never writable or part of exact register undo.
 * Keep it reported and allow only these two separately observed boundaries;
 * every other one of the fixed50 words must still match exactly. */
static int G52FixedBaseline(const ULONG*values)
{
 if(G52_REGISTER_COUNT!=50||G52Fields[12].Range!=0||G52Fields[12].Offset!=0xd44||G52Ranges[0].Base!=0x17a20000)return 0;
 ULONG i;for(i=0;i<G52_REGISTER_COUNT;i++){
  if(i==12){if(values[i]!=0&&values[i]!=7)return 0;}
  else if(values[i]!=G52ExpectedValues[i])return 0;
 }return 1;
}
static int G52FixedSameRestorable(const ULONG*before,const ULONG*after)
{
 ULONG i;if(!G52FixedBaseline(before)||!G52FixedBaseline(after))return 0;
 for(i=0;i<G52_REGISTER_COUNT;i++)if(i!=12&&before[i]!=after[i])return 0;
 return 1;
}

typedef struct {PVOID Maps[7];} G52_OBS_CONTEXT;
static const ULONG G52ObserverPages[6]={0xc400000,0xc402000,0xc42d000,0xc440000,0xc441000,0xc445000};
static PULONG G52ObserverAddress(G52_OBS_CONTEXT *ctx,ULONG at,BOOLEAN write)
{
 ULONG i;
 if((at&3)!=0)return NULL;
 if(write&&at!=0xc440ea0&&at!=0xc441220&&at!=0xc4456e0)return NULL;
 for(i=0;i<6;i++)if(ctx->Maps[i]&&at>=G52ObserverPages[i]&&at-G52ObserverPages[i]<=0xffc){
  if(write&&i<3)return NULL;
  return(PULONG)((PUCHAR)ctx->Maps[i]+at-G52ObserverPages[i]);
 }
 return NULL;
}
static int G52ObserverRead(void *context,uint32_t at,uint32_t *value)
{
 PULONG reg=G52ObserverAddress((G52_OBS_CONTEXT*)context,at,FALSE);
 if(!reg)return 0;*value=READ_REGISTER_ULONG(reg);return 1;
}
static int G52ObserverWrite(void *context,uint32_t at,uint32_t value)
{
 PULONG reg=G52ObserverAddress((G52_OBS_CONTEXT*)context,at,TRUE);
 if(!reg||!((value==0x08000007)||(value==0x08000080)||(value==0x08000407)))return 0;
 WRITE_REGISTER_ULONG(reg,value);return 1;
}
static void G52ObserverWait(void *context){UNREFERENCED_PARAMETER(context);KeStallExecutionProcessor(1);}
static VOID G52CapturePmic(G52_PMIC *out)
{
 G52_OBS_CONTEXT context;G52_OBS_IO io;G52_SNAPSHOT before,after;
 LARGE_INTEGER begin,end,frequency;LONG previous;ULONG i;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&context,sizeof(context));
 G52Status(&out->Status);begin=KeQueryPerformanceCounter(&frequency);
 out->CounterFrequency=(ULONGLONG)frequency.QuadPart;
 previous=InterlockedCompareExchange(&G52ObserverAttempts,0,0);out->Attempt=(ULONG)previous;
 if(InterlockedCompareExchange(&G52ObserverFault,0,0)){out->Observer.Code=1001;goto done;}
 if(previous>=2){out->Observer.Code=1002;goto done;}
 if(InterlockedCompareExchange(&G52ObserverAttempts,previous+1,previous)!=previous){out->Observer.Code=1003;goto done;}
 out->Attempt=(ULONG)previous+1;
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Observer.Code=1004;goto done;}
 status=G52Snapshot(&before);
 if(!NT_SUCCESS(status)||!G52FixedBaseline(before.Values)){
  out->Observer.Code=1005;goto done;
 }
 for(i=0;i<6;i++){
  PHYSICAL_ADDRESS at;at.QuadPart=G52ObserverPages[i];InterlockedIncrement(&G52MapCalls);
  context.Maps[i]=MmMapIoSpaceEx(at,0x1000,(i<3?PAGE_READONLY:PAGE_READWRITE)|PAGE_NOCACHE);
  if(!context.Maps[i]){out->Observer.Code=1006;goto done;}
 }
 io.Context=&context;io.Read=G52ObserverRead;io.Write=G52ObserverWrite;io.WaitMicrosecond=G52ObserverWait;
 G52Observe(&io,&out->Observer);
 done:
 for(i=6;i>0;i--)if(context.Maps[i-1])MmUnmapIoSpace(context.Maps[i-1],0x1000);
 if(out->Attempt==(ULONG)previous+1){
  if(out->Observer.Code==0){
   status=G52Snapshot(&after);
   if(NT_SUCCESS(status)&&RtlCompareMemory(before.Values,after.Values,sizeof(before.Values))==sizeof(before.Values))out->FixedRegistersUnchanged=1;
   else out->Observer.Code=1007;
  }
  if(out->Observer.Code!=0)InterlockedExchange(&G52ObserverFault,1);
 }
 if(out->Observer.Code==0&&out->FixedRegistersUnchanged){
  static const UCHAR off[8]={8,7,0,0,7,7,0,0};
  InterlockedExchange(&G52OffPmicVerified,out->Observer.Status==0x43&&RtlCompareMemory(out->Observer.Configuration,off,8)==8);
 }
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G52MapCalls,0,0);
 end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(ULONGLONG)(end.QuadPart-begin.QuadPart);
}

typedef struct {PVOID Maps[16];G52_POWER_RESULT*Result;G52_TRIAL_RESULT*Trial;ULONG CommandUsed,CancelUsed,AbortUsed,FifoWords,LastM,LastS,HaveM,HaveS,SAcks;} G52_PWR_CONTEXT;
static const G52_RANGE G52PowerRanges[16]={{0x17a20000,0x2000},{0x17100000,0x1000},{0xf10a000,0x1000},{0xf118000,0x2000},{0xc400000,0x1000},{0xc402000,0x1000},{0xc42d000,0x1000},{0xc440000,0x1000},{0xc441000,0x1000},{0xc445000,0x1000},{0x152000,0x1000},{0x118000,0x1000},{0x123000,0x1000},{0xf12c000,0x4000},{0xa90000,0x1000},{0xac0000,0x1000}};
static PULONG G52PowerAddress(G52_PWR_CONTEXT*ctx,ULONG at,BOOLEAN write)
{
 ULONG i;if(at&3)return NULL;
 if(write&&at!=0xc440ea0&&at!=0xc441220&&at!=0xc4456e0&&at!=0x17a20d34&&at!=0x17a20d38&&at!=0x17a20d3c&&at!=0x17a20d24&&at!=0x17a20d2c&&at!=0x17a20d08&&
 at!=0xf10a000&&at!=0xf10a004&&at!=0xf118000&&at!=0xf118004&&at!=0xf119000&&at!=0xf11900c&&at!=0x152008&&at!=0xf12c000&&at!=0xf12d000&&at!=0xf12e000&&at!=0xf12f000&&
 !G52EngineWriteAddress(at)&&at!=0xa9026c&&at!=0xa90270&&at!=0xa90600&&at!=0xa90604&&at!=0xa90618&&at!=0xa90648&&at!=0xa90700)return NULL;
 for(i=0;i<16;i++)if(ctx->Maps[i]&&at>=G52PowerRanges[i].Base&&at-G52PowerRanges[i].Base+4<=G52PowerRanges[i].Bytes){
  if(write&&i!=0&&i!=2&&i!=3&&i!=7&&i!=8&&i!=9&&i!=10&&i!=13&&i!=14)return NULL;
  return(PULONG)((PUCHAR)ctx->Maps[i]+at-G52PowerRanges[i].Base);
 }
 return NULL;
}
static int G52PowerRead(void*context,uint32_t at,uint32_t*value)
{
 G52_PWR_CONTEXT*ctx=context;PULONG reg=G52PowerAddress(ctx,at,FALSE);if(!reg)return 0;*value=READ_REGISTER_ULONG(reg);
 if(at==0xa90610){ctx->LastM=*value;ctx->HaveM=1;}if(at==0xa90640){ctx->LastS=*value;ctx->HaveS=1;}return 1;
}
static int G52PowerWrite(void*context,uint32_t at,uint32_t value)
{
 G52_PWR_CONTEXT*ctx=context;PULONG reg=G52PowerAddress(ctx,at,TRUE);if(!reg)return 0;
 if(at==0xc440ea0||at==0xc441220||at==0xc4456e0){if(value!=0x08000007&&value!=0x08000080&&value!=0x08000407)return 0;}
 else if(at>=0x17a20000&&at<0x17a22000){if(!G52RscWriteAllowed(at,value))return 0;}
 else if(at==0x152008){if(value!=0x40002380&&value!=0x40102380&&value!=0x40302380&&value!=0x44302380)return 0;}
 else if(at>=0xf12c000&&at<=0xf12f000){if(value!=1&&value!=0x85)return 0;}
 else if(at==0xf10a000){if(value!=1&&value!=0x81&&value!=0x281)return 0;}
 else if(at==0xf118000){if(value!=0x201&&value!=0x2c0)return 0;}
 else if(at==0xf119000){if(value!=1&&value!=0xc0)return 0;}
 else if(at==0xf10a004||at==0xf118004){if(value>3)return 0;}
 else if(at==0xf11900c){if(value)return 0;}
 else if(at==0xa90600){
  ULONG used=ctx->CommandUsed;G52_TOUCH_RESULT*t=&ctx->Trial->Touch;
  if(used>=4||value!=(used==2?0x08000000u:0x18000000u))return 0;
  if(used==1&&(!t->FullBlockChecksumValid||!t->Report.ContractVerified||!t->BusQuiescent||ctx->FifoWords!=63))return 0;
  if(used==2&&(!G52AckEligible(&t->Report)||!t->Ack.ContractVerified||!t->BusQuiescent||ctx->FifoWords!=9))return 0;
  if(used==3&&(!t->Ack.TransportOk||!t->Post.ContractVerified||!t->BusQuiescent||ctx->FifoWords!=2))return 0;
  ctx->CommandUsed++;ctx->FifoWords=0;ctx->HaveM=ctx->HaveS=ctx->SAcks=0;
 }
 else if(at==0xa90604){
  if(!ctx->CommandUsed)return 0;
  if(value==4){if(ctx->CancelUsed||ctx->AbortUsed)return 0;ctx->CancelUsed=1;}
  else if(value==2){if(!ctx->CancelUsed||ctx->AbortUsed)return 0;ctx->AbortUsed=1;}else return 0;
 }
 else if(at==0xa90618){if(!ctx->CommandUsed||!ctx->HaveM||value!=ctx->LastM)return 0;ctx->HaveM=0;}
 else if(at==0xa90648){if(!ctx->CommandUsed||!ctx->HaveS||value!=ctx->LastS||ctx->SAcks)return 0;ctx->HaveS=0;ctx->SAcks++;}
 else if(at==0xa9026c||at==0xa90270){
  static const ULONG txlen[4]={250,34,6,34},rxlen[4]={250,34,34,34};ULONG i=(at-0xa9026c)/4;
  ULONG next=ctx->CommandUsed<4?(i?rxlen[ctx->CommandUsed]:txlen[ctx->CommandUsed]):0;
  if(value!=next&&value!=ctx->Trial->Touch.LengthsBefore[i])return 0;
 }
 else if(at==0xa90700){
  static const UCHAR clear[8]={0xf0,0,1,2,0x74,0,0,0};static const ULONG words[4]={63,9,2,9};
  ULONG i=ctx->FifoWords,used=ctx->CommandUsed,expected;const UCHAR*tx;
  if(!used||used>4||i>=words[used-1])return 0;
  tx=used==1?ctx->Trial->Touch.Tx:used==2?ctx->Trial->Touch.Report.Tx:used==3?clear:ctx->Trial->Touch.Post.Tx;
  expected=(ULONG)tx[i*4]|((ULONG)tx[i*4+1]<<8)|((ULONG)tx[i*4+2]<<16)|((ULONG)tx[i*4+3]<<24);
  if(value!=expected)return 0;ctx->FifoWords++;
 }
 else if(!G52EngineWriteAddress(at))return 0;
 WRITE_REGISTER_ULONG(reg,value);return 1;
}
static void G52PowerWait1(void*context)
{
 G52_PWR_CONTEXT*ctx=context;LARGE_INTEGER wait;ctx->Result->Waits1ms++;wait.QuadPart=-10000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}
static void G52PowerWait10(void*context)
{
 LARGE_INTEGER wait;UNREFERENCED_PARAMETER(context);wait.QuadPart=-100000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}
static int G52Barrier(void*context){UNREFERENCED_PARAMETER(context);KeMemoryBarrier();return 0;}
static void G52WaitMs(void*context,uint32_t ms)
{
 LARGE_INTEGER wait;UNREFERENCED_PARAMETER(context);wait.QuadPart=-(LONGLONG)ms*10000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}
static void G52WaitPoll(void*context){UNREFERENCED_PARAMETER(context);KeStallExecutionProcessor(10);}
static uint64_t G52NowUs(void*context)
{
 LARGE_INTEGER frequency,ticks;ULONGLONG f,t;UNREFERENCED_PARAMETER(context);ticks=KeQueryPerformanceCounter(&frequency);f=(ULONGLONG)frequency.QuadPart;t=(ULONGLONG)ticks.QuadPart;return t/f*1000000+(t%f)*1000000/f;
}
static int G52Ready(void*context)
{
 G52_PWR_CONTEXT*ctx=context;G52_OBS_RESULT*p=&ctx->Trial->Touch.PoweredPmic;
 G52_OBS_IO io={context,G52PowerRead,G52PowerWrite,G52ObserverWait};unsigned i;static const UCHAR cfg[8]={8,7,8,7,7,7,128,0};
 G52Observe(&io,p);if(p->Code){ctx->Trial->Power.ObserverUncertain=1;return 0;}
 if(p->Status!=0xc7)return 0;for(i=0;i<8;i++)if(p->Configuration[i]!=cfg[i])return 0;return 1;
}
static int G52NativeTouch(void*context)
{
 G52_PWR_CONTEXT*ctx=context;G52_TOUCH_IO io={context,G52PowerRead,G52PowerWrite,G52Barrier,G52Ready,G52WaitMs,G52WaitPoll,G52NowUs};
 return G52TouchRead(&io,&ctx->Trial->Touch);
}
static int G52Powered(void*context)
{
 G52_PWR_CONTEXT*ctx=context;G52_TRIAL_RESULT*t=ctx->Trial;
 G52_SPI_IO io={context,G52PowerRead,G52PowerWrite,G52ObserverWait,G52NativeTouch};
 t->PoweredHookCalled++;t->Touch.BusQuiescent=1;G52PrepareSpi(&io,&t->Spi);
 t->SafeRelease=(!t->Spi.VoteDirty||t->Spi.Restored)&&(!t->Spi.Engine.Dirty||t->Spi.Engine.Restored)&&!t->Spi.RestoreError&&!t->Spi.Engine.RestoreError&&(!t->Touch.AnalogDirty||t->Touch.Restored)&&t->Touch.BusQuiescent;
 return !t->Spi.Code&&t->Spi.Restored&&t->Touch.TransportOk&&t->Touch.FullBlockChecksumValid&&t->Touch.Report.ContractVerified&&t->Touch.Report.TransportOk&&t->Touch.Ack.TransportOk&&t->Touch.Post.TransportOk&&t->Touch.Restored;
}
static int G52SafeRelease(void*context){return((G52_PWR_CONTEXT*)context)->Trial->SafeRelease!=0;}
static VOID G52CaptureTrial(G52_TRIAL*out)
{
 G52_PWR_CONTEXT context;G52_POWER_IO io;G52_SNAPSHOT before,after;
 LARGE_INTEGER begin,end,frequency;ULONG i;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&context,sizeof(context));G52Status(&out->Status);context.Trial=&out->Trial;context.Result=&out->Trial.Power;out->Trial.SafeRelease=1;
 begin=KeQueryPerformanceCounter(&frequency);out->CounterFrequency=(ULONGLONG)frequency.QuadPart;
 if(InterlockedCompareExchange(&G52TrialUsed,1,0)!=0){out->Trial.Power.Code=1002;goto done;}
 out->Attempt=1;
 if(InterlockedCompareExchange(&G52ObserverAttempts,0,0)!=1||!InterlockedCompareExchange(&G52OffPmicVerified,0,0)||InterlockedCompareExchange(&G52ObserverFault,0,0)){out->Trial.Power.Code=1003;goto done;}
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Trial.Power.Code=1004;goto done;}
 status=G52Snapshot(&before);
 if(!NT_SUCCESS(status)||!G52FixedBaseline(before.Values)){out->Trial.Power.Code=1005;goto done;}
 for(i=0;i<16;i++){
  PHYSICAL_ADDRESS at;at.QuadPart=(LONGLONG)G52PowerRanges[i].Base;InterlockedIncrement(&G52MapCalls);
  context.Maps[i]=MmMapIoSpaceEx(at,G52PowerRanges[i].Bytes,(i==0||i==2||i==3||i==7||i==8||i==9||i==10||i==13||i==14?PAGE_READWRITE:PAGE_READONLY)|PAGE_NOCACHE);
  if(!context.Maps[i]){out->Trial.Power.Code=1006;goto done;}
 }
 io.Rsc.Context=&context;io.Rsc.Read=G52PowerRead;io.Rsc.Write=G52PowerWrite;io.Rsc.WaitMillisecond=G52PowerWait1;
 io.Observer.Context=&context;io.Observer.Read=G52PowerRead;io.Observer.Write=G52PowerWrite;io.Observer.WaitMicrosecond=G52ObserverWait;io.WaitTenMilliseconds=G52PowerWait10;io.Powered=G52Powered;io.SafeToRelease=G52SafeRelease;
 G52PowerTrial(&io,&out->Trial.Power);
 if(out->Trial.Power.Restored&&out->Trial.Touch.Restored){
  G52_TOUCH_IO finalIo={&context,G52PowerRead,G52PowerWrite,G52Barrier,G52Ready,G52WaitMs,G52WaitPoll,G52NowUs};
  if(!G52VerifyTouchOff(&finalIo,&out->Trial.Touch)){out->Trial.Power.Restored=0;if(!out->Trial.Power.Code)out->Trial.Power.Code=109;}
 }
 done:
 for(i=16;i>0;i--)if(context.Maps[i-1])MmUnmapIoSpace(context.Maps[i-1],G52PowerRanges[i-1].Bytes);
 if(out->Trial.Power.Code<1000){
  status=G52Snapshot(&after);
  if(NT_SUCCESS(status)&&G52FixedSameRestorable(before.Values,after.Values))out->FixedRegistersUnchanged=1;
  else if(!out->Trial.Power.Code)out->Trial.Power.Code=1007;
 }
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G52MapCalls,0,0);
 end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(ULONGLONG)(end.QuadPart-begin.QuadPart);
}

VOID G52Control(WDFQUEUE Queue,WDFREQUEST Request,size_t OutputLength,size_t InputLength,ULONG Code)
{
 G52_REQUEST *input;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR information=0;
 UNREFERENCED_PARAMETER(Queue);
 if(Code!=G52_IOCTL_STATUS&&Code!=G52_IOCTL_SNAPSHOT&&Code!=G52_IOCTL_PMIC&&Code!=G52_IOCTL_POWER){status=STATUS_INVALID_DEVICE_REQUEST;goto complete;}
 if(InputLength!=sizeof(G52_REQUEST)){status=STATUS_INVALID_PARAMETER;goto complete;}
 status=WdfRequestRetrieveInputBuffer(Request,sizeof(G52_REQUEST),(PVOID*)&input,NULL);
 if(!NT_SUCCESS(status))goto complete;
 if(input->Size!=sizeof(*input)||input->Version!=G52_ABI||input->Magic!=G52_MAGIC){status=STATUS_INVALID_PARAMETER;goto complete;}
 needed=Code==G52_IOCTL_STATUS?sizeof(G52_STATUS):Code==G52_IOCTL_SNAPSHOT?sizeof(G52_SNAPSHOT):Code==G52_IOCTL_PMIC?sizeof(G52_PMIC):sizeof(G52_TRIAL);
 if(OutputLength<needed){status=STATUS_BUFFER_TOO_SMALL;goto complete;}
 status=WdfRequestRetrieveOutputBuffer(Request,needed,&output,NULL);if(!NT_SUCCESS(status))goto complete;
 if(Code==G52_IOCTL_STATUS){G52Status((G52_STATUS*)output);status=STATUS_SUCCESS;}
 else if(Code==G52_IOCTL_PMIC){G52CapturePmic((G52_PMIC*)output);status=STATUS_SUCCESS;}
 else if(Code==G52_IOCTL_POWER){G52CaptureTrial((G52_TRIAL*)output);status=STATUS_SUCCESS;}
 else status=G52Snapshot((G52_SNAPSHOT*)output);
 if(NT_SUCCESS(status))information=needed;
 complete:WdfRequestCompleteWithInformation(Request,status,information);
}
VOID G52FileCreate(WDFDEVICE Device,WDFREQUEST Request,WDFFILEOBJECT FileObject)
{
 PUNICODE_STRING name=WdfFileObjectGetFileName(FileObject);UNREFERENCED_PARAMETER(Device);
 WdfRequestComplete(Request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);
}
VOID G52Unload(WDFDRIVER Driver){UNREFERENCED_PARAMETER(Driver);}
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath)
{
 WDF_DRIVER_CONFIG config;WDFDRIVER driver;PWDFDEVICE_INIT init=NULL;WDFDEVICE device;
 WDF_OBJECT_ATTRIBUTES attributes;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG files;NTSTATUS status;
 DECLARE_CONST_UNICODE_STRING(sddl,L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
 DECLARE_CONST_UNICODE_STRING(name,L"\\Device\\OpenG52");
 DECLARE_CONST_UNICODE_STRING(link,L"\\DosDevices\\OpenG52");
 WDF_DRIVER_CONFIG_INIT(&config,WDF_NO_EVENT_CALLBACK);config.DriverInitFlags|=WdfDriverInitNonPnpDriver;config.EvtDriverUnload=G52Unload;
 status=WdfDriverCreate(DriverObject,RegistryPath,WDF_NO_OBJECT_ATTRIBUTES,&config,&driver);if(!NT_SUCCESS(status))return status;
 status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 init=WdfControlDeviceInitAllocate(driver,&sddl);if(!init)return STATUS_INSUFFICIENT_RESOURCES;
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);
 WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&files,G52FileCreate,WDF_NO_EVENT_CALLBACK,WDF_NO_EVENT_CALLBACK);
 WdfDeviceInitSetFileObjectConfig(init,&files,WDF_NO_OBJECT_ATTRIBUTES);
 status=WdfDeviceInitAssignName(init,&name);if(!NT_SUCCESS(status))goto done;
 WDF_OBJECT_ATTRIBUTES_INIT(&attributes);attributes.ExecutionLevel=WdfExecutionLevelPassive;attributes.SynchronizationScope=WdfSynchronizationScopeDevice;
 status=WdfDeviceCreate(&init,&attributes,&device);if(!NT_SUCCESS(status))goto done;
 status=WdfDeviceCreateSymbolicLink(device,&link);if(!NT_SUCCESS(status))goto done;
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfFalse;queue.EvtIoDeviceControl=G52Control;
 status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))goto done;
 WdfControlFinishInitializing(device);
 done:if(init)WdfDeviceInitFree(init);return status;
}
