/* SPDX-License-Identifier: MIT
 * Temporary source-built KMDF diagnostic. Fixed qualified register/PMIC reads.
 * This control device is not the eventual PnP bus/regulator owner.
 */
#include <ntddk.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g97_binding.h"
#include "g97_observer.h"
#include "g97_trial.h"
#include "g97_protocol.h"
#include "g97_hwapi.h"
static volatile LONG64 G97Sequence;
static volatile LONG G97MapCalls;
static volatile LONG G97ObserverAttempts;
static volatile LONG G97ObserverFault;
static volatile LONG G97OffPmicVerified;
static volatile LONG G97TrialUsed;
static int G97Available(const G97_STREAM_IO*stream)
{
 return stream&&stream->Available&&stream->Available(stream->Context);
}

VOID G97HardwareStatus(G97_STATUS *out)
{
 UCHAR table[sizeof(G97ExpectedDsdt)];ULONG bytes=0;
 RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=G97_ABI;out->Magic=G97_MAGIC;
 out->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
 out->CurrentIrql=KeGetCurrentIrql();out->RegisterCount=G97_REGISTER_COUNT;
 out->MapCalls=(ULONG)InterlockedCompareExchange(&G97MapCalls,0,0);
 out->Sequence=(ULONGLONG)InterlockedIncrement64(&G97Sequence);out->InterruptTime=KeQueryInterruptTime();
 RtlCopyMemory(out->BuildId,"G97-livehw1",sizeof("G97-livehw1"));
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);
 if(NT_SUCCESS(RtlGetVersion(&version)))out->KernelBuild=version.dwBuildNumber;
 RtlZeroMemory(table,sizeof(table));
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);
 out->FirmwareStatus=(ULONG)status;out->FirmwareBytes=bytes;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G97ExpectedDsdt,sizeof(table))==sizeof(table))out->FirmwareMatch=1;
}

NTSTATUS G97HardwareSnapshot(G97_SNAPSHOT *out,const G97_STREAM_IO*stream)
{
 PVOID maps[RTL_NUMBER_OF(G97Ranges)];NTSTATUS status=STATUS_SUCCESS;ULONG i;
 RtlZeroMemory(out,sizeof(*out));G97HardwareStatus(&out->Status);
 if(!G97Available(stream))return STATUS_DEVICE_REMOVED;
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL)return STATUS_NOT_SUPPORTED;
 RtlZeroMemory(maps,sizeof(maps));
 for(i=0;i<RTL_NUMBER_OF(G97Ranges);i++){
  if(!G97Available(stream)){status=STATUS_DEVICE_REMOVED;goto done;}
  PHYSICAL_ADDRESS address;address.QuadPart=(LONGLONG)G97Ranges[i].Base;
  InterlockedIncrement(&G97MapCalls);
  maps[i]=MmMapIoSpaceEx(address,G97Ranges[i].Bytes,PAGE_READONLY|PAGE_NOCACHE);
  if(maps[i]==NULL){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 }
 for(i=0;i<G97_REGISTER_COUNT;i++){
  const G97_FIELD *field=&G97Fields[i];
  if(!G97Available(stream)){status=STATUS_DEVICE_REMOVED;goto done;}
  out->Values[i]=READ_REGISTER_ULONG((PULONG)((PUCHAR)maps[field->Range]+field->Offset));
 }
 out->Count=G97_REGISTER_COUNT;
 done:
 for(i=RTL_NUMBER_OF(G97Ranges);i>0;i--)if(maps[i-1])MmUnmapIoSpace(maps[i-1],G97Ranges[i-1].Bytes);
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G97MapCalls,0,0);
 return status;
}

/* RESP_DATA is read-only transaction history: reset observed0, final MODE
 * query observed7. It is never writable or part of exact register undo.
 * Keep it reported and allow only these two separately observed boundaries;
 * every other one of the fixed50 words must still match exactly. */
static int G97FixedBaseline(const ULONG*values)
{
 if(G97_REGISTER_COUNT!=50||G97Fields[12].Range!=0||G97Fields[12].Offset!=0xd44||G97Ranges[0].Base!=0x17a20000)return 0;
 ULONG i;for(i=0;i<G97_REGISTER_COUNT;i++){
  if(i==12){if(values[i]!=0&&values[i]!=7)return 0;}
  else if(values[i]!=G97ExpectedValues[i])return 0;
 }return 1;
}
static int G97FixedSameRestorable(const ULONG*before,const ULONG*after)
{
 ULONG i;if(!G97FixedBaseline(before)||!G97FixedBaseline(after))return 0;
 for(i=0;i<G97_REGISTER_COUNT;i++)if(i!=12&&before[i]!=after[i])return 0;
 return 1;
}

typedef struct {PVOID Maps[7];const G97_STREAM_IO*Stream;} G97_OBS_CONTEXT;
static const ULONG G97ObserverPages[6]={0xc400000,0xc402000,0xc42d000,0xc440000,0xc441000,0xc445000};
static PULONG G97ObserverAddress(G97_OBS_CONTEXT *ctx,ULONG at,BOOLEAN write)
{
 ULONG i;
 if((at&3)!=0)return NULL;
 if(write&&at!=0xc440ea0&&at!=0xc441220&&at!=0xc4456e0)return NULL;
 for(i=0;i<6;i++)if(ctx->Maps[i]&&at>=G97ObserverPages[i]&&at-G97ObserverPages[i]<=0xffc){
  if(write&&i<3)return NULL;
  return(PULONG)((PUCHAR)ctx->Maps[i]+at-G97ObserverPages[i]);
 }
 return NULL;
}
static int G97ObserverRead(void *context,uint32_t at,uint32_t *value)
{
 if(!G97Available(((G97_OBS_CONTEXT*)context)->Stream))return 0;
 PULONG reg=G97ObserverAddress((G97_OBS_CONTEXT*)context,at,FALSE);
 if(!reg)return 0;*value=READ_REGISTER_ULONG(reg);return 1;
}
static int G97ObserverWrite(void *context,uint32_t at,uint32_t value)
{
 if(!G97Available(((G97_OBS_CONTEXT*)context)->Stream))return 0;
 PULONG reg=G97ObserverAddress((G97_OBS_CONTEXT*)context,at,TRUE);
 if(!reg||!((value==0x08000007)||(value==0x08000080)||(value==0x08000407)))return 0;
 WRITE_REGISTER_ULONG(reg,value);return 1;
}
static void G97ObserverWait(void *context){UNREFERENCED_PARAMETER(context);KeStallExecutionProcessor(1);}
VOID G97HardwarePmic(G97_PMIC *out,const G97_STREAM_IO*stream)
{
 G97_OBS_CONTEXT context;G97_OBS_IO io;G97_SNAPSHOT before,after;
 LARGE_INTEGER begin,end,frequency;LONG previous=0;ULONG i;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&context,sizeof(context));
 context.Stream=stream;
 G97HardwareStatus(&out->Status);begin=KeQueryPerformanceCounter(&frequency);
 out->CounterFrequency=(ULONGLONG)frequency.QuadPart;
 if(!G97Available(stream)){out->Observer.Code=1009;goto done;}
 previous=InterlockedCompareExchange(&G97ObserverAttempts,0,0);out->Attempt=(ULONG)previous;
 if(InterlockedCompareExchange(&G97ObserverFault,0,0)){out->Observer.Code=1001;goto done;}
 if(previous>=2){out->Observer.Code=1002;goto done;}
 if(InterlockedCompareExchange(&G97ObserverAttempts,previous+1,previous)!=previous){out->Observer.Code=1003;goto done;}
 out->Attempt=(ULONG)previous+1;
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Observer.Code=1004;goto done;}
 status=G97HardwareSnapshot(&before,stream);
 if(!NT_SUCCESS(status)||!G97FixedBaseline(before.Values)){
  out->Observer.Code=1005;goto done;
 }
 for(i=0;i<6;i++){
  if(!G97Available(stream)){out->Observer.Code=1009;goto done;}
  PHYSICAL_ADDRESS at;at.QuadPart=G97ObserverPages[i];InterlockedIncrement(&G97MapCalls);
  context.Maps[i]=MmMapIoSpaceEx(at,0x1000,(i<3?PAGE_READONLY:PAGE_READWRITE)|PAGE_NOCACHE);
  if(!context.Maps[i]){out->Observer.Code=1006;goto done;}
 }
 io.Context=&context;io.Read=G97ObserverRead;io.Write=G97ObserverWrite;io.WaitMicrosecond=G97ObserverWait;
 G97Observe(&io,&out->Observer);
 done:
 for(i=6;i>0;i--)if(context.Maps[i-1])MmUnmapIoSpace(context.Maps[i-1],0x1000);
 if(out->Attempt==(ULONG)previous+1){
  if(out->Observer.Code==0){
   status=G97HardwareSnapshot(&after,stream);
   if(NT_SUCCESS(status)&&RtlCompareMemory(before.Values,after.Values,sizeof(before.Values))==sizeof(before.Values))out->FixedRegistersUnchanged=1;
   else out->Observer.Code=1007;
  }
  if(out->Observer.Code!=0)InterlockedExchange(&G97ObserverFault,1);
 }
 if(out->Observer.Code==0&&out->FixedRegistersUnchanged){
  static const UCHAR off[8]={8,7,0,0,7,7,0,0};
  InterlockedExchange(&G97OffPmicVerified,(out->Observer.Status==3||out->Observer.Status==0x43)&&RtlCompareMemory(out->Observer.Configuration,off,8)==8);
 }
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G97MapCalls,0,0);
 end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(ULONGLONG)(end.QuadPart-begin.QuadPart);
}

typedef struct {PVOID Maps[16];G97_POWER_RESULT*Result;G97_TRIAL_RESULT*Trial;const G97_STREAM_IO*Stream;ULONG CommandUsed,CancelUsed,AbortUsed,FifoWords,LastM,LastS,HaveM,HaveS,SAcks,ActiveAddress,ActiveBytes,ActiveRead,ActiveWords,ClearUsed,CycleBase,CompletedCycles;} G97_PWR_CONTEXT;
static const G97_RANGE G97PowerRanges[16]={{0x17a20000,0x2000},{0x17100000,0x1000},{0xf10a000,0x1000},{0xf118000,0x2000},{0xc400000,0x1000},{0xc402000,0x1000},{0xc42d000,0x1000},{0xc440000,0x1000},{0xc441000,0x1000},{0xc445000,0x1000},{0x152000,0x1000},{0x118000,0x1000},{0x123000,0x1000},{0xf12c000,0x4000},{0xa90000,0x1000},{0xac0000,0x1000}};
static PULONG G97PowerAddress(G97_PWR_CONTEXT*ctx,ULONG at,BOOLEAN write)
{
 ULONG i;if(at&3)return NULL;
 if(write&&at!=0xc440ea0&&at!=0xc441220&&at!=0xc4456e0&&at!=0x17a20d34&&at!=0x17a20d38&&at!=0x17a20d3c&&at!=0x17a20d24&&at!=0x17a20d2c&&at!=0x17a20d08&&
 at!=0xf10a000&&at!=0xf10a004&&at!=0xf118000&&at!=0xf118004&&at!=0xf119000&&at!=0xf11900c&&at!=0x152008&&at!=0xf12c000&&at!=0xf12d000&&at!=0xf12e000&&at!=0xf12f000&&
 !G97EngineWriteAddress(at)&&at!=0xa9026c&&at!=0xa90270&&at!=0xa90600&&at!=0xa90604&&at!=0xa90618&&at!=0xa90648&&at!=0xa90700)return NULL;
 for(i=0;i<16;i++)if(ctx->Maps[i]&&at>=G97PowerRanges[i].Base&&at-G97PowerRanges[i].Base+4<=G97PowerRanges[i].Bytes){
  if(write&&i!=0&&i!=2&&i!=3&&i!=7&&i!=8&&i!=9&&i!=10&&i!=13&&i!=14)return NULL;
  return(PULONG)((PUCHAR)ctx->Maps[i]+at-G97PowerRanges[i].Base);
 }
 return NULL;
}
static int G97PowerRead(void*context,uint32_t at,uint32_t*value)
{
 if(!G97Available(((G97_PWR_CONTEXT*)context)->Stream))return 0;
 G97_PWR_CONTEXT*ctx=context;PULONG reg=G97PowerAddress(ctx,at,FALSE);if(!reg)return 0;*value=READ_REGISTER_ULONG(reg);
 if(at==0xa90610){ctx->LastM=*value;ctx->HaveM=1;}if(at==0xa90640){ctx->LastS=*value;ctx->HaveS=1;}return 1;
}
/* Initial four qualified commands, then raw-history-authorized poll frames. */
static int G97NativePlan(G97_PWR_CONTEXT*ctx,ULONG used,ULONG*address,ULONG*bytes,ULONG*read)
{
 static const ULONG sizes[4]={250,34,6,34};G97_TOUCH_RESULT*t=&ctx->Trial->Touch;
 if(used<4){*address=used?0x10274:0x10070;*bytes=sizes[used];*read=used!=2;return 1;}
 if(t->Poll.Limit==0||t->Poll.Limit>G97_POLL_CYCLES||used>=4+4*t->Poll.Limit||ctx->CompletedCycles>=t->Poll.Limit||t->Poll.Cycles!=ctx->CompletedCycles+1||!G97PollPlan(t,ctx->CycleBase,used-4))return 0;
 {const G97_WIRE_RESULT*f=&t->PollFrames[(used-4)%G97_POLL_WIRES];*address=f->Address;*bytes=f->Kind==G97_WIRE_CLEAR?6:f->Payload+8;*read=f->Kind!=G97_WIRE_CLEAR;}
 return 1;
}
static ULONG G97NativeWord(G97_PWR_CONTEXT*ctx,ULONG index)
{
 UCHAR prefix[8];ULONG i,value=0;static const UCHAR clear[8]={0xf0,0,1,2,0x74,0,0,0};
 if(!ctx->ActiveRead){for(i=0;i<4;i++)value|=(ULONG)clear[index*4+i]<<(i*8);return value;}
 prefix[0]=0xf1;prefix[1]=(UCHAR)(ctx->ActiveAddress>>24);prefix[2]=(UCHAR)(ctx->ActiveAddress>>16);prefix[3]=(UCHAR)(ctx->ActiveAddress>>8);prefix[4]=(UCHAR)ctx->ActiveAddress;prefix[5]=prefix[6]=prefix[7]=255;
 for(i=0;i<4;i++)if(index*4+i<8)value|=(ULONG)prefix[index*4+i]<<(i*8);return value;
}
static int G97PowerWrite(void*context,uint32_t at,uint32_t value)
{
 if(!G97Available(((G97_PWR_CONTEXT*)context)->Stream))return 0;
 G97_PWR_CONTEXT*ctx=context;PULONG reg=G97PowerAddress(ctx,at,TRUE);if(!reg)return 0;
 if(at==0xc440ea0||at==0xc441220||at==0xc4456e0){if(value!=0x08000007&&value!=0x08000080&&value!=0x08000407)return 0;}
 else if(at>=0x17a20000&&at<0x17a22000){if(!G97RscWriteAllowed(at,value))return 0;}
 else if(at==0x152008){if(value!=0x40002380&&value!=0x40102380&&value!=0x40302380&&value!=0x44302380)return 0;}
 else if(at>=0xf12c000&&at<=0xf12f000){if(value!=1&&value!=0x85)return 0;}
 else if(at==0xf10a000){if(value!=1&&value!=0x81&&value!=0x281)return 0;}
 else if(at==0xf118000){if(value!=0x201&&value!=0x2c0)return 0;}
 else if(at==0xf119000){if(value!=1&&value!=0xc0)return 0;}
 else if(at==0xf10a004||at==0xf118004){if(value>3)return 0;}
 else if(at==0xf11900c){if(value)return 0;}
 else if(at==0xa90600){
  ULONG used=ctx->CommandUsed,address,bytes,read;G97_TOUCH_RESULT*t=&ctx->Trial->Touch;
  if(!G97NativePlan(ctx,used,&address,&bytes,&read)||value!=(read?0x18000000u:0x08000000u)||ctx->FifoWords!=ctx->ActiveWords)return 0;
  if(used==1&&(!t->FullBlockChecksumValid||!t->Report.ContractVerified||!t->BusQuiescent))return 0;
  if(used==2&&(!G97AckEligible(&t->Report)||!t->Ack.ContractVerified||!t->BusQuiescent))return 0;
  if(used==3&&(!t->Ack.TransportOk||!t->Post.ContractVerified||!t->BusQuiescent))return 0;
  if(used>=4&&!t->BusQuiescent)return 0;
  if(!read){if(ctx->ClearUsed>=1+ctx->Trial->Touch.Poll.Limit)return 0;ctx->ClearUsed++;}
  ctx->ActiveAddress=address;ctx->ActiveBytes=bytes;ctx->ActiveRead=read;ctx->ActiveWords=(bytes+3)/4;
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
  ULONG address,bytes,read,i=(at-0xa9026c)/4,next=0;int planned=G97NativePlan(ctx,ctx->CommandUsed,&address,&bytes,&read);
  if(planned)next=i?(read?bytes:(ctx->CommandUsed==2?34:0)):bytes;
  if(value!=ctx->Trial->Touch.LengthsBefore[i]&&(!planned||value!=next))return 0;
 }
 else if(at==0xa90700){
  ULONG i=ctx->FifoWords;
  if(!ctx->CommandUsed||i>=ctx->ActiveWords||value!=G97NativeWord(ctx,i))return 0;ctx->FifoWords++;
 }
 else if(!G97EngineWriteAddress(at))return 0;
 WRITE_REGISTER_ULONG(reg,value);return 1;
}
static void G97PowerWait1(void*context)
{
 G97_PWR_CONTEXT*ctx=context;LARGE_INTEGER wait;ctx->Result->Waits1ms++;wait.QuadPart=-10000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}
static void G97PowerWait10(void*context)
{
 LARGE_INTEGER wait;UNREFERENCED_PARAMETER(context);wait.QuadPart=-100000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}
static int G97Barrier(void*context){UNREFERENCED_PARAMETER(context);KeMemoryBarrier();return 0;}
static void G97WaitMs(void*context,uint32_t ms)
{
 LARGE_INTEGER wait;UNREFERENCED_PARAMETER(context);wait.QuadPart=-(LONGLONG)ms*10000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}
static void G97WaitPoll(void*context){UNREFERENCED_PARAMETER(context);KeStallExecutionProcessor(10);}
static uint64_t G97NowUs(void*context)
{
 LARGE_INTEGER frequency,ticks;ULONGLONG f,t;UNREFERENCED_PARAMETER(context);ticks=KeQueryPerformanceCounter(&frequency);f=(ULONGLONG)frequency.QuadPart;t=(ULONGLONG)ticks.QuadPart;return t/f*1000000+(t%f)*1000000/f;
}
uint64_t G97HardwareTimeUs(void){return G97NowUs(NULL);}
static int G97Ready(void*context)
{
 G97_PWR_CONTEXT*ctx=context;G97_OBS_RESULT*p=&ctx->Trial->Touch.PoweredPmic;
 G97_OBS_IO io={context,G97PowerRead,G97PowerWrite,G97ObserverWait};unsigned i;static const UCHAR cfg[8]={8,7,8,7,7,7,128,0};
 G97Observe(&io,p);if(p->Code){ctx->Trial->Power.ObserverUncertain=1;return 0;}
 if(p->Status!=0xc7&&p->Status!=0x87)return 0;for(i=0;i<8;i++)if(p->Configuration[i]!=cfg[i])return 0;return 1;
}
static int G97StageInput(void*context,const uint8_t*raw,uint32_t n,uint64_t at){G97_PWR_CONTEXT*ctx=context;return ctx->Stream&&ctx->Stream->Stage(ctx->Stream->Context,raw,n,at);}
static int G97PublishInput(void*context,const uint8_t*raw,uint32_t n){G97_PWR_CONTEXT*ctx=context;return ctx->Stream&&ctx->Stream->Publish(ctx->Stream->Context,raw,n);}
static int G97StopRequested(void*context){G97_PWR_CONTEXT*ctx=context;return ctx->Stream->StopRequested(ctx->Stream->Context);}
/* Separate native checkpoint: raw terminal proof plus fresh read-only bus
 * quiescence. This never resets a lifetime CMD/clear/cancel/abort allowance. */
static int G97Advance(void*context)
{
 G97_PWR_CONTEXT*ctx=context;G97_TOUCH_RESULT*t=&ctx->Trial->Touch;uint32_t value;ULONG i;
 static const ULONG addresses[12]={0xa90040,0xa90800,0xa90804,0xa90e18,0xa90e1c,0x17100130,0x17100230,0x17100330,0x17100c60,0xa90610,0xa90614,0xa90640};
 static const ULONG masks[9]={0x1001,0x0fffffff,0x81ffffff,0xffffffff,0xffffffff,0x20,0x20,0x20,0xc00};
 if(ctx->CompletedCycles>=t->Poll.Limit||t->Poll.Cycles!=ctx->CompletedCycles+1||ctx->CommandUsed!=4+t->PollFrameCount||ctx->FifoWords!=ctx->ActiveWords||!G97CycleComplete(t,ctx->CycleBase,t->PollFrameCount))return 0;
 for(i=0;i<12;i++){
  if(!G97PowerRead(ctx,addresses[i],&value))return 0;
  if(i<9&&(value&masks[i]))return 0;
  if(i==9&&(value&~0x80u))return 0;
  if(i==10&&value!=0x7fc0007fu)return 0;
  if(i==11&&value)return 0;
 }
 ctx->CycleBase=t->PollFrameCount;ctx->CompletedCycles++;return 1;
}
static int G97NativeTouch(void*context)
{
 G97_PWR_CONTEXT*ctx=context;G97_TOUCH_IO io={context,ctx->Stream->CycleLimit,G97PowerRead,G97PowerWrite,G97Barrier,G97Ready,G97WaitMs,G97WaitPoll,G97NowUs,G97StageInput,G97PublishInput,G97StopRequested,G97Advance};
 return G97TouchRead(&io,&ctx->Trial->Touch);
}
static int G97Powered(void*context)
{
 G97_PWR_CONTEXT*ctx=context;G97_TRIAL_RESULT*t=ctx->Trial;
 G97_SPI_IO io={context,G97PowerRead,G97PowerWrite,G97ObserverWait,G97NativeTouch};
 t->PoweredHookCalled++;t->Touch.BusQuiescent=1;G97PrepareSpi(&io,&t->Spi);
 t->SafeRelease=(!t->Spi.VoteDirty||t->Spi.Restored)&&(!t->Spi.Engine.Dirty||t->Spi.Engine.Restored)&&!t->Spi.RestoreError&&!t->Spi.Engine.RestoreError&&(!t->Touch.AnalogDirty||t->Touch.Restored)&&t->Touch.BusQuiescent;
 return !t->Spi.Code&&t->Spi.Restored&&t->Touch.TransportOk&&t->Touch.FullBlockChecksumValid&&t->Touch.Report.ContractVerified&&t->Touch.Report.TransportOk&&t->Touch.Ack.TransportOk&&t->Touch.Post.TransportOk&&t->Touch.Restored;
}
static int G97SafeRelease(void*context){return((G97_PWR_CONTEXT*)context)->Trial->SafeRelease!=0;}
VOID G97HardwareTrial(G97_TRIAL*out,const G97_STREAM_IO*stream)
{
 G97_PWR_CONTEXT context;G97_POWER_IO io;G97_SNAPSHOT before,after;
 LARGE_INTEGER begin,end,frequency;ULONG i;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&context,sizeof(context));G97HardwareStatus(&out->Status);context.Trial=&out->Trial;context.Result=&out->Trial.Power;context.Stream=stream;out->Trial.SafeRelease=1;
 begin=KeQueryPerformanceCounter(&frequency);out->CounterFrequency=(ULONGLONG)frequency.QuadPart;
 if(!stream||(stream->CycleLimit!=G97_NATIVE_CYCLES&&stream->CycleLimit!=G97_PLAY_CYCLES)||!stream->Stage||!stream->Publish||!stream->StopRequested||!G97Available(stream)){out->Trial.Power.Code=1008;goto done;}
 if(InterlockedCompareExchange(&G97TrialUsed,1,0)!=0){out->Trial.Power.Code=1002;goto done;}
 out->Attempt=1;
 if(InterlockedCompareExchange(&G97ObserverAttempts,0,0)!=1||!InterlockedCompareExchange(&G97OffPmicVerified,0,0)||InterlockedCompareExchange(&G97ObserverFault,0,0)){out->Trial.Power.Code=1003;goto done;}
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Trial.Power.Code=1004;goto done;}
 status=G97HardwareSnapshot(&before,stream);
 if(!NT_SUCCESS(status)||!G97FixedBaseline(before.Values)){out->Trial.Power.Code=1005;goto done;}
 for(i=0;i<16;i++){
  if(!G97Available(stream)){out->Trial.Power.Code=1009;goto done;}
  PHYSICAL_ADDRESS at;at.QuadPart=(LONGLONG)G97PowerRanges[i].Base;InterlockedIncrement(&G97MapCalls);
  context.Maps[i]=MmMapIoSpaceEx(at,G97PowerRanges[i].Bytes,(i==0||i==2||i==3||i==7||i==8||i==9||i==10||i==13||i==14?PAGE_READWRITE:PAGE_READONLY)|PAGE_NOCACHE);
  if(!context.Maps[i]){out->Trial.Power.Code=1006;goto done;}
 }
 io.Rsc.Context=&context;io.Rsc.Read=G97PowerRead;io.Rsc.Write=G97PowerWrite;io.Rsc.WaitMillisecond=G97PowerWait1;
 io.Observer.Context=&context;io.Observer.Read=G97PowerRead;io.Observer.Write=G97PowerWrite;io.Observer.WaitMicrosecond=G97ObserverWait;io.WaitTenMilliseconds=G97PowerWait10;io.Powered=G97Powered;io.SafeToRelease=G97SafeRelease;
 G97PowerTrial(&io,&out->Trial.Power);
 if(out->Trial.Power.Restored&&out->Trial.Touch.Restored){
  G97_TOUCH_IO finalIo={&context,stream->CycleLimit,G97PowerRead,G97PowerWrite,G97Barrier,G97Ready,G97WaitMs,G97WaitPoll,G97NowUs,G97StageInput,G97PublishInput,G97StopRequested,G97Advance};
  if(!G97VerifyTouchOff(&finalIo,&out->Trial.Touch)){out->Trial.Power.Restored=0;if(!out->Trial.Power.Code)out->Trial.Power.Code=109;}
 }
 done:
 for(i=16;i>0;i--)if(context.Maps[i-1])MmUnmapIoSpace(context.Maps[i-1],G97PowerRanges[i-1].Bytes);
 if(out->Trial.Power.Code<1000){
  status=G97HardwareSnapshot(&after,stream);
  if(NT_SUCCESS(status)&&G97FixedSameRestorable(before.Values,after.Values))out->FixedRegistersUnchanged=1;
  else if(!out->Trial.Power.Code)out->Trial.Power.Code=1007;
 }
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G97MapCalls,0,0);
 end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(ULONGLONG)(end.QuadPart-begin.QuadPart);
}
