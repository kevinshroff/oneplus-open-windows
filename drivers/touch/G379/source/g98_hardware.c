#include "g98_spi_vote.h"
/* SPDX-License-Identifier: MIT
 * Temporary source-built KMDF diagnostic. Fixed qualified register/PMIC reads.
 * This control device is not the eventual PnP bus/regulator owner.
 */
#include <ntddk.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g98_binding.h"
#include "g98_observer.h"
#include "g98_trial.h"
#include "g98_protocol.h"
#include "g98_hwapi.h"
#include "g100_bus.h"
#include "g98_rsc_profile.h"
static volatile LONG64 G98Sequence;
static volatile LONG G98MapCalls;
static volatile LONG G98ObserverAttempts;
static volatile LONG G98ObserverFault;
static volatile LONG G98OffPmicVerified;
static volatile LONG G98TrialUsed;
static volatile LONG G98LastReleaseVerified;
static int G98Available(const G98_STREAM_IO*stream)
{
 return stream&&stream->Available&&stream->Available(stream->Context);
}

VOID G98HardwareStatus(G98_STATUS *out)
{
 UCHAR table[sizeof(G98ExpectedDsdt)];ULONG bytes=0;
 RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=G98_ABI;out->Magic=G98_MAGIC;
 out->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
 out->CurrentIrql=KeGetCurrentIrql();out->RegisterCount=G98_REGISTER_COUNT;
 out->MapCalls=(ULONG)InterlockedCompareExchange(&G98MapCalls,0,0);
 out->Sequence=(ULONGLONG)InterlockedIncrement64(&G98Sequence);out->InterruptTime=KeQueryInterruptTime();
 RtlCopyMemory(out->BuildId,"G98-livehw1",sizeof("G98-livehw1"));
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);
 if(NT_SUCCESS(RtlGetVersion(&version)))out->KernelBuild=version.dwBuildNumber;
 RtlZeroMemory(table,sizeof(table));
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);
 out->FirmwareStatus=(ULONG)status;out->FirmwareBytes=bytes;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G98ExpectedDsdt,sizeof(table))==sizeof(table))out->FirmwareMatch=1;
}

NTSTATUS G98HardwareSnapshot(G98_SNAPSHOT *out,const G98_STREAM_IO*stream)
{
 PVOID maps[RTL_NUMBER_OF(G98Ranges)];NTSTATUS status=STATUS_SUCCESS;ULONG i;
 RtlZeroMemory(out,sizeof(*out));G98HardwareStatus(&out->Status);
 if(!G98Available(stream))return STATUS_DEVICE_REMOVED;
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL)return STATUS_NOT_SUPPORTED;
 RtlZeroMemory(maps,sizeof(maps));
 for(i=0;i<RTL_NUMBER_OF(G98Ranges);i++){
  if(!G98Available(stream)){status=STATUS_DEVICE_REMOVED;goto done;}
  PHYSICAL_ADDRESS address;address.QuadPart=(LONGLONG)G98Ranges[i].Base;
  InterlockedIncrement(&G98MapCalls);
  maps[i]=MmMapIoSpaceEx(address,G98Ranges[i].Bytes,PAGE_READONLY|PAGE_NOCACHE);
  if(maps[i]==NULL){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 }
 for(i=0;i<G98_REGISTER_COUNT;i++){
  const G98_FIELD *field=&G98Fields[i];
  if(!G98Available(stream)){status=STATUS_DEVICE_REMOVED;goto done;}
  out->Values[i]=READ_REGISTER_ULONG((PULONG)((PUCHAR)maps[field->Range]+field->Offset));
 }
 out->Count=G98_REGISTER_COUNT;
 done:
 for(i=RTL_NUMBER_OF(G98Ranges);i>0;i--)if(maps[i-1])MmUnmapIoSpace(maps[i-1],G98Ranges[i-1].Bytes);
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G98MapCalls,0,0);
 return status;
}

/* RESP_DATA is read-only transaction history: reset observed0, final MODE
 * query observed7. It is never writable or part of exact register undo.
 * Keep it reported and allow only these two separately observed boundaries;
 * every other one of the fixed50 words must still match exactly. */
static int G98FixedBaseline(const ULONG*values)
{
 if(G98_REGISTER_COUNT!=50||G98Fields[12].Range!=0||G98Fields[12].Offset!=0xd44||G98Ranges[0].Base!=0x17a20000)return 0;
 /* ADDR/DATA are inactive history; transfer privately double-captures them. */
 ULONG i;for(i=0;i<G98_REGISTER_COUNT;i++){
  if(i==12){if(values[i]!=0&&values[i]!=7)return 0;}
  else if(i!=9&&i!=10&&values[i]!=G98ExpectedValues[i])return 0;
 }return 1;
}
static int G98FixedSameRestorable(const ULONG*before,const ULONG*after)
{
 ULONG i;if(!G98FixedBaseline(before)||!G98FixedBaseline(after))return 0;
 for(i=0;i<G98_REGISTER_COUNT;i++)if(i!=12&&before[i]!=after[i])return 0;
 return 1;
}

typedef struct {PVOID Maps[7];const G98_STREAM_IO*Stream;ULONG GateHeld;} G98_OBS_CONTEXT;
static const ULONG G98ObserverPages[6]={0xc400000,0xc402000,0xc42d000,0xc440000,0xc441000,0xc445000};
static PULONG G98ObserverAddress(G98_OBS_CONTEXT *ctx,ULONG at,BOOLEAN write)
{
 ULONG i;
 if((at&3)!=0)return NULL;
 if(write&&at!=0xc440ea0&&at!=0xc441220&&at!=0xc4456e0)return NULL;
 for(i=0;i<6;i++)if(ctx->Maps[i]&&at>=G98ObserverPages[i]&&at-G98ObserverPages[i]<=0xffc){
  if(write&&i<3)return NULL;
  return(PULONG)((PUCHAR)ctx->Maps[i]+at-G98ObserverPages[i]);
 }
 return NULL;
}
static int G98ObserverRead(void *context,uint32_t at,uint32_t *value)
{
 if(!((G98_OBS_CONTEXT*)context)->GateHeld||!G98Available(((G98_OBS_CONTEXT*)context)->Stream))return 0;
 PULONG reg=G98ObserverAddress((G98_OBS_CONTEXT*)context,at,FALSE);
 if(!reg)return 0;*value=READ_REGISTER_ULONG(reg);return 1;
}
static int G98ObserverWrite(void *context,uint32_t at,uint32_t value)
{
 if(!((G98_OBS_CONTEXT*)context)->GateHeld||!G98Available(((G98_OBS_CONTEXT*)context)->Stream))return 0;
 PULONG reg=G98ObserverAddress((G98_OBS_CONTEXT*)context,at,TRUE);
 if(!reg||!((value==0x08000007)||(value==0x08000080)||(value==0x08000407)))return 0;
 WRITE_REGISTER_ULONG(reg,value);return 1;
}
static void G98ObserverWait(void *context){UNREFERENCED_PARAMETER(context);KeStallExecutionProcessor(1);}
static int G98ObserverPresent(void*x){return G98Available(((G98_OBS_CONTEXT*)x)->Stream);}
static int G98ObserverAcquire(void*x){G98_OBS_CONTEXT*c=x;return G100BusAcquire(&c->GateHeld,G98ObserverPresent,x);}
static void G98ObserverRelease(void*x,int uncertain){G98_OBS_CONTEXT*c=x;G100BusRelease(&c->GateHeld,uncertain);}
VOID G98HardwarePmic(G98_PMIC *out,const G98_STREAM_IO*stream)
{
 G98_OBS_CONTEXT context;G98_OBS_IO io;G98_SNAPSHOT before,after;
 LARGE_INTEGER begin,end,frequency;LONG previous=0;ULONG i;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&context,sizeof(context));
 context.Stream=stream;
 G98HardwareStatus(&out->Status);begin=KeQueryPerformanceCounter(&frequency);
 out->CounterFrequency=(ULONGLONG)frequency.QuadPart;
 if(!G98Available(stream)){out->Observer.Code=1009;goto done;}
 previous=InterlockedCompareExchange(&G98ObserverAttempts,0,0);out->Attempt=(ULONG)previous;
 if(InterlockedCompareExchange(&G98ObserverFault,0,0)){out->Observer.Code=1001;goto done;}
 if(previous>=2){out->Observer.Code=1002;goto done;}
 if(InterlockedCompareExchange(&G98ObserverAttempts,previous+1,previous)!=previous){out->Observer.Code=1003;goto done;}
 out->Attempt=(ULONG)previous+1;
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Observer.Code=1004;goto done;}
 status=G98HardwareSnapshot(&before,stream);
 if(!NT_SUCCESS(status)||!G98FixedBaseline(before.Values)){
  out->Observer.Code=1005;goto done;
 }
 for(i=0;i<6;i++){
  if(!G98Available(stream)){out->Observer.Code=1009;goto done;}
  PHYSICAL_ADDRESS at;at.QuadPart=G98ObserverPages[i];InterlockedIncrement(&G98MapCalls);
  context.Maps[i]=MmMapIoSpaceEx(at,0x1000,(i<3?PAGE_READONLY:PAGE_READWRITE)|PAGE_NOCACHE);
  if(!context.Maps[i]){out->Observer.Code=1006;goto done;}
 }
 io.Context=&context;io.Read=G98ObserverRead;io.Write=G98ObserverWrite;io.WaitMicrosecond=G98ObserverWait;io.Acquire=G98ObserverAcquire;io.Release=G98ObserverRelease;
 G98Observe(&io,&out->Observer);
 done:
 for(i=6;i>0;i--)if(context.Maps[i-1])MmUnmapIoSpace(context.Maps[i-1],0x1000);
 if(out->Attempt==(ULONG)previous+1){
  if(out->Observer.Code==0){
   status=G98HardwareSnapshot(&after,stream);
   if(NT_SUCCESS(status)&&RtlCompareMemory(before.Values,after.Values,sizeof(before.Values))==sizeof(before.Values))out->FixedRegistersUnchanged=1;
   else out->Observer.Code=1007;
  }
  if(out->Observer.Code!=0)InterlockedExchange(&G98ObserverFault,1);
 }
 if(out->Observer.Code==0&&out->FixedRegistersUnchanged){
  static const UCHAR off[8]={8,7,0,0,7,7,0,0};
  InterlockedExchange(&G98OffPmicVerified,(out->Observer.Status==3||out->Observer.Status==0x43)&&RtlCompareMemory(out->Observer.Configuration,off,8)==8);
 }
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G98MapCalls,0,0);
 end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(ULONGLONG)(end.QuadPart-begin.QuadPart);
}

typedef struct {PVOID Maps[16];G98_POWER_RESULT*Result;G98_TRIAL_RESULT*Trial;const G98_STREAM_IO*Stream;ULONG CommandUsed,CancelUsed,AbortUsed,FifoWords,LastM,LastS,HaveM,HaveS,SAcks,ActiveAddress,ActiveBytes,ActiveRead,ActiveWords,ClearUsed,CycleBase,CompletedCycles,LastCycleBase;ULONG GateHeld,SpiVoteArmed;uint32_t SpiVoteBefore,SpiVoteExpected;} G98_PWR_CONTEXT;
static const G98_RANGE G98PowerRanges[16]={{0x17a20000,0x2000},{0x17100000,0x1000},{0xf10a000,0x1000},{0xf118000,0x2000},{0xc400000,0x1000},{0xc402000,0x1000},{0xc42d000,0x1000},{0xc440000,0x1000},{0xc441000,0x1000},{0xc445000,0x1000},{0x152000,0x1000},{0x118000,0x1000},{0x123000,0x1000},{0xf12c000,0x4000},{0xa90000,0x1000},{0xac0000,0x1000}};
static PULONG G98PowerAddress(G98_PWR_CONTEXT*ctx,ULONG at,BOOLEAN write)
{
 ULONG i;if(at&3)return NULL;
 if(write&&at!=0xc440ea0&&at!=0xc441220&&at!=0xc4456e0&&at!=0x17a20d34&&at!=0x17a20d38&&at!=0x17a20d3c&&at!=0x17a20d24&&at!=0x17a20d2c&&at!=0x17a20d08&&
 at!=0xf10a000&&at!=0xf10a004&&at!=0xf118000&&at!=0xf118004&&at!=0xf119000&&at!=0xf11900c&&at!=0x152008&&at!=0xf12c000&&at!=0xf12d000&&at!=0xf12e000&&at!=0xf12f000&&
 !G98EngineWriteAddress(at)&&at!=0xa9026c&&at!=0xa90270&&at!=0xa90600&&at!=0xa90604&&at!=0xa90618&&at!=0xa90648&&at!=0xa90700)return NULL;
 for(i=0;i<16;i++)if(ctx->Maps[i]&&at>=G98PowerRanges[i].Base&&at-G98PowerRanges[i].Base+4<=G98PowerRanges[i].Bytes){
  if(write&&i!=0&&i!=2&&i!=3&&i!=7&&i!=8&&i!=9&&i!=10&&i!=13&&i!=14)return NULL;
  return(PULONG)((PUCHAR)ctx->Maps[i]+at-G98PowerRanges[i].Base);
 }
 return NULL;
}
static int G98PowerRead(void*context,uint32_t at,uint32_t*value)
{
 if(at>=0xc440000&&at<0xc446000&&!((G98_PWR_CONTEXT*)context)->GateHeld)return 0;
 if(!G98Available(((G98_PWR_CONTEXT*)context)->Stream))return 0;
 G98_PWR_CONTEXT*ctx=context;PULONG reg=G98PowerAddress(ctx,at,FALSE);if(!reg)return 0;*value=READ_REGISTER_ULONG(reg);
 if(at==0xa90610){ctx->LastM=*value;ctx->HaveM=1;}if(at==0xa90640){ctx->LastS=*value;ctx->HaveS=1;}return 1;
}
/* Initial four qualified commands, then raw-history-authorized poll frames. */
static int G98NativePlan(G98_PWR_CONTEXT*ctx,ULONG used,ULONG*address,ULONG*bytes,ULONG*read)
{
 static const ULONG sizes[4]={250,34,6,34};G98_TOUCH_RESULT*t=&ctx->Trial->Touch;
 if(used<4){*address=used?0x10274:0x10070;*bytes=sizes[used];*read=used!=2;return 1;}
 if(t->Poll.Limit==0||t->Poll.Limit>G98_POLL_CYCLES||used>=4+4*t->Poll.Limit||ctx->CompletedCycles>=t->Poll.Limit||t->Poll.Cycles!=ctx->CompletedCycles+1||!G98PollPlan(t,ctx->CycleBase,used-4))return 0;
 {const G98_WIRE_RESULT*f=&t->PollFrames[(used-4)%G98_POLL_WIRES];*address=f->Address;*bytes=f->Kind==G98_WIRE_CLEAR?6:f->Payload+8;*read=f->Kind!=G98_WIRE_CLEAR;}
 return 1;
}
static ULONG G98NativeWord(G98_PWR_CONTEXT*ctx,ULONG index)
{
 UCHAR prefix[8];ULONG i,value=0;static const UCHAR clear[8]={0xf0,0,1,2,0x74,0,0,0};
 if(!ctx->ActiveRead){for(i=0;i<4;i++)value|=(ULONG)clear[index*4+i]<<(i*8);return value;}
 prefix[0]=0xf1;prefix[1]=(UCHAR)(ctx->ActiveAddress>>24);prefix[2]=(UCHAR)(ctx->ActiveAddress>>16);prefix[3]=(UCHAR)(ctx->ActiveAddress>>8);prefix[4]=(UCHAR)ctx->ActiveAddress;prefix[5]=prefix[6]=prefix[7]=255;
 for(i=0;i<4;i++)if(index*4+i<8)value|=(ULONG)prefix[index*4+i]<<(i*8);return value;
}
static int G98PowerWrite(void*context,uint32_t at,uint32_t value)
{
 if(at>=0xc440000&&at<0xc446000&&!((G98_PWR_CONTEXT*)context)->GateHeld)return 0;
 if(!G98Available(((G98_PWR_CONTEXT*)context)->Stream))return 0;
 G98_PWR_CONTEXT*ctx=context;PULONG reg=G98PowerAddress(ctx,at,TRUE);if(!reg)return 0;
 if(at==0xc440ea0||at==0xc441220||at==0xc4456e0){if(value!=0x08000007&&value!=0x08000080&&value!=0x08000407)return 0;}
 else if(at>=0x17a20000&&at<0x17a22000){
  G98_RSC_RESULT*r=NULL;ULONG n=ctx->Result->TxnCount;
  if(n&&n<=G98_TXNS)r=&ctx->Result->Transactions[n-1];
  if((at==0x17a20d38||at==0x17a20d3c)&&r&&r->Stage==91){
   uint32_t state;
   if(!G98RscRestoreAllowed(r,at,value)||
      !G98PowerRead(ctx,0x17a20d28,&state)||state!=1||
      !G98PowerRead(ctx,0x17a20d24,&state)||state||
      !G98PowerRead(ctx,0x17a20d2c,&state)||state||
      !G98PowerRead(ctx,0x17a20d04,&state)||state)return 0;
   for(ULONG i=8;i<=10;i++){
    uint32_t own=i==8?r->MsgId:i==9?r->RequestAddress:r->RequestData;
    if(!G98PowerRead(ctx,0x17a20d34+(i-8)*4,&state)||
       (state!=r->Before[i]&&state!=own))return 0;
   }
  }else if(!G98RscWriteAllowed(at,value))return 0;
 }
 else if(at==0x152008){
  uint32_t current;
  if(!ctx->SpiVoteArmed||!G98SpiVoteTransition(ctx->SpiVoteBefore,ctx->SpiVoteExpected,value)||
     !G98PowerRead(ctx,at,&current)||current!=ctx->SpiVoteExpected)return 0;
  /* Private expected advances only for this exact validated MMIO write. */
  WRITE_REGISTER_ULONG(reg,value);ctx->SpiVoteExpected=value;return 1;
 }
 else if(at>=0xf12c000&&at<=0xf12f000){if(value!=1&&value!=0x85)return 0;}
 else if(at==0xf10a000){if(value!=1&&value!=0x81&&value!=0x281)return 0;}
 else if(at==0xf118000){if(value!=0x201&&value!=0x2c0)return 0;}
 else if(at==0xf119000){if(value!=1&&value!=0xc0)return 0;}
 else if(at==0xf10a004||at==0xf118004){if(value>3)return 0;}
 else if(at==0xf11900c){if(value)return 0;}
 else if(at==0xa90600){
  ULONG used=ctx->CommandUsed,address,bytes,read;G98_TOUCH_RESULT*t=&ctx->Trial->Touch;
  if(!G98NativePlan(ctx,used,&address,&bytes,&read)||value!=(read?0x18000000u:0x08000000u)||ctx->FifoWords!=ctx->ActiveWords)return 0;
  if(used==1&&(!t->FullBlockChecksumValid||!t->Report.ContractVerified||!t->BusQuiescent))return 0;
  if(used==2&&(!G98AckEligible(&t->Report)||!t->Ack.ContractVerified||!t->BusQuiescent))return 0;
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
  ULONG address,bytes,read,i=(at-0xa9026c)/4,next=0;int planned=G98NativePlan(ctx,ctx->CommandUsed,&address,&bytes,&read);
  if(planned)next=i?(read?bytes:(ctx->CommandUsed==2?34:0)):bytes;
  if(value!=ctx->Trial->Touch.LengthsBefore[i]&&(!planned||value!=next))return 0;
 }
 else if(at==0xa90700){
  ULONG i=ctx->FifoWords;
  if(!ctx->CommandUsed||i>=ctx->ActiveWords||value!=G98NativeWord(ctx,i))return 0;ctx->FifoWords++;
 }
 else if(!G98EngineWriteAddress(at))return 0;
 WRITE_REGISTER_ULONG(reg,value);return 1;
}
static void G98PowerWait1(void*context)
{
 G98_PWR_CONTEXT*ctx=context;LARGE_INTEGER wait;ctx->Result->Waits1ms++;wait.QuadPart=-10000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}
static void G98PowerWait10(void*context)
{
 LARGE_INTEGER wait;UNREFERENCED_PARAMETER(context);wait.QuadPart=-100000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}
static int G98Barrier(void*context){UNREFERENCED_PARAMETER(context);KeMemoryBarrier();return 0;}
static void G98WaitMs(void*context,uint32_t ms)
{
 LARGE_INTEGER wait;UNREFERENCED_PARAMETER(context);wait.QuadPart=-(LONGLONG)ms*10000;KeDelayExecutionThread(KernelMode,FALSE,&wait);
}
static void G98WaitPoll(void*context){UNREFERENCED_PARAMETER(context);KeStallExecutionProcessor(10);}
static uint64_t G98NowUs(void*context)
{
 LARGE_INTEGER frequency,ticks;ULONGLONG f,t;UNREFERENCED_PARAMETER(context);ticks=KeQueryPerformanceCounter(&frequency);f=(ULONGLONG)frequency.QuadPart;t=(ULONGLONG)ticks.QuadPart;return t/f*1000000+(t%f)*1000000/f;
}
uint64_t G98HardwareTimeUs(void){return G98NowUs(NULL);}
static int G98PowerPresent(void*x){return G98Available(((G98_PWR_CONTEXT*)x)->Stream);}
static int G98PowerAcquire(void*x){G98_PWR_CONTEXT*c=x;return G100BusAcquire(&c->GateHeld,G98PowerPresent,x);}
static void G98PowerRelease(void*x,int uncertain){G98_PWR_CONTEXT*c=x;G100BusRelease(&c->GateHeld,uncertain);}
static int G98Ready(void*context)
{
 G98_PWR_CONTEXT*ctx=context;G98_OBS_RESULT*p=&ctx->Trial->Touch.PoweredPmic;
 G98_OBS_IO io={context,G98PowerRead,G98PowerWrite,G98ObserverWait,G98PowerAcquire,G98PowerRelease};unsigned i;static const UCHAR cfg[8]={8,7,8,7,7,7,128,0};
 G98Observe(&io,p);if(p->Code){ctx->Trial->Power.ObserverUncertain=1;return 0;}
 if(p->Status!=0xc7&&p->Status!=0x87)return 0;for(i=0;i<8;i++)if(p->Configuration[i]!=cfg[i])return 0;return 1;
}
static int G98StageInput(void*context,const uint8_t*raw,uint32_t n,uint64_t at){G98_PWR_CONTEXT*ctx=context;return ctx->Stream&&ctx->Stream->Stage(ctx->Stream->Context,raw,n,at);}
static int G98PublishInput(void*context,const uint8_t*raw,uint32_t n){G98_PWR_CONTEXT*ctx=context;return ctx->Stream&&ctx->Stream->Publish(ctx->Stream->Context,raw,n);}
static int G98StopRequested(void*context){G98_PWR_CONTEXT*ctx=context;return ctx->Stream->StopRequested(ctx->Stream->Context);}
/* Separate native checkpoint: raw terminal proof plus fresh read-only bus
 * quiescence. This never resets a lifetime CMD/clear/cancel/abort allowance. */
static int G98Advance(void*context)
{
 G98_PWR_CONTEXT*ctx=context;G98_TOUCH_RESULT*t=&ctx->Trial->Touch;uint32_t value;ULONG i;
 static const ULONG addresses[12]={0xa90040,0xa90800,0xa90804,0xa90e18,0xa90e1c,0x17100130,0x17100230,0x17100330,0x17100c60,0xa90610,0xa90614,0xa90640};
 static const ULONG masks[9]={0x1001,0x0fffffff,0x81ffffff,0xffffffff,0xffffffff,0x20,0x20,0x20,0xc00};
 if(ctx->CompletedCycles>=t->Poll.Limit||t->Poll.Cycles!=ctx->CompletedCycles+1||ctx->CommandUsed!=4+t->PollFrameCount||ctx->FifoWords!=ctx->ActiveWords||!G98CycleComplete(t,ctx->CycleBase,t->PollFrameCount))return 0;
 for(i=0;i<12;i++){
  if(!G98PowerRead(ctx,addresses[i],&value))return 0;
  if(i<9&&(value&masks[i]))return 0;
  if(i==9&&(value&~0x80u))return 0;
  if(i==10&&value!=0x7fc0007fu)return 0;
  if(i==11&&value)return 0;
 }
 ctx->LastCycleBase=ctx->CycleBase;ctx->CycleBase=t->PollFrameCount;ctx->CompletedCycles++;
 if(ctx->Stream->CycleComplete)ctx->Stream->CycleComplete(ctx->Stream->Context);return 1;
}
/* A persistent power lease retires complete epochs, rather than expanding
 * cumulative 32-bit command allowances forever. Old descriptors cannot regain
 * authority: both owners require the final checkpoint and 12 fresh idle reads
 * before the new epoch begins with an empty history and zero completed cycles. */
static int G98Retire(void*context)
{
 G98_PWR_CONTEXT*ctx=context;G98_TOUCH_RESULT*t=&ctx->Trial->Touch;uint32_t value;ULONG i;
 static const ULONG addresses[12]={0xa90040,0xa90800,0xa90804,0xa90e18,0xa90e1c,0x17100130,0x17100230,0x17100330,0x17100c60,0xa90610,0xa90614,0xa90640};
 static const ULONG masks[9]={0x1001,0x0fffffff,0x81ffffff,0xffffffff,0xffffffff,0x20,0x20,0x20,0xc00};
 if(!ctx->Stream->Persistent||!ctx->Stream->EpochComplete||!ctx->Stream->CycleComplete||
    ctx->Stream->CycleLimit!=G98_EPOCH_CYCLES||t->Poll.Limit!=G98_EPOCH_CYCLES||
    t->Code||t->RestoreError||t->Poll.Code||t->Poll.Cycles!=G98_EPOCH_CYCLES||
    ctx->CompletedCycles!=G98_EPOCH_CYCLES||ctx->CycleBase!=t->PollFrameCount||
    ctx->CommandUsed!=4+t->PollFrameCount||t->CommandAttempted!=ctx->CommandUsed||
    ctx->ClearUsed!=1+t->Poll.ClearCompleted||ctx->FifoWords!=ctx->ActiveWords||
    ctx->CancelUsed||ctx->AbortUsed||t->CancelSent||t->AbortSent||
    !t->Poll.BusQuiescent||!t->BusQuiescent||!G98CycleComplete(t,ctx->LastCycleBase,t->PollFrameCount))return 0;
 for(i=0;i<12;i++){
  if(!G98PowerRead(ctx,addresses[i],&value))return 0;
  if(i<9&&(value&masks[i]))return 0;
  if(i==9&&(value&~0x80u))return 0;
  if(i==10&&value!=0x7fc0007fu)return 0;
  if(i==11&&value)return 0;
 }
 ctx->Stream->EpochComplete(ctx->Stream->Context,t->Reads,t->Writes,t->PollFrameCount);
 ctx->CommandUsed=4;ctx->ClearUsed=1;ctx->CycleBase=ctx->LastCycleBase=ctx->CompletedCycles=0;
 return 1;
}
static int G98NativeTouch(void*context)
{
 G98_PWR_CONTEXT*ctx=context;G98_TOUCH_IO io={context,ctx->Stream->CycleLimit,G98PowerRead,G98PowerWrite,G98Barrier,G98Ready,G98WaitMs,G98WaitPoll,G98NowUs,G98StageInput,G98PublishInput,G98StopRequested,G98Advance,ctx->Stream->Persistent?G98Retire:NULL};
 return G98TouchRead(&io,&ctx->Trial->Touch);
}
static int G98Powered(void*context)
{
 G98_PWR_CONTEXT*ctx=context;G98_TRIAL_RESULT*t=ctx->Trial;
 G98_SPI_IO io={context,G98PowerRead,G98PowerWrite,G98ObserverWait,G98NativeTouch};
 t->PoweredHookCalled++;t->Touch.BusQuiescent=1;
 ctx->SpiVoteArmed=0;
 /* Private capture precedes the portable capture/recheck; no result buffer
  * can authorize a different clock baseline or foreign-bit update. */
 if(!G98PowerRead(ctx,0x152008,&ctx->SpiVoteBefore)||!G98SpiVoteBaseline(ctx->SpiVoteBefore)){
  t->Spi.Code=1;t->Spi.Stage=1;return 0;
 }
 ctx->SpiVoteExpected=ctx->SpiVoteBefore;ctx->SpiVoteArmed=1;
 G98PrepareSpi(&io,&t->Spi);ctx->SpiVoteArmed=0;
 t->SafeRelease=(!t->Spi.VoteDirty||t->Spi.Restored)&&(!t->Spi.Engine.Dirty||t->Spi.Engine.Restored)&&!t->Spi.RestoreError&&!t->Spi.Engine.RestoreError&&(!t->Touch.AnalogDirty||t->Touch.Restored)&&t->Touch.BusQuiescent;
 return !t->Spi.Code&&t->Spi.Restored&&t->Touch.TransportOk&&t->Touch.FullBlockChecksumValid&&t->Touch.Report.ContractVerified&&t->Touch.Report.TransportOk&&t->Touch.Ack.TransportOk&&t->Touch.Post.TransportOk&&t->Touch.Restored;
}
static int G98SafeRelease(void*context){return((G98_PWR_CONTEXT*)context)->Trial->SafeRelease!=0;}
VOID G98HardwareTrial(G98_TRIAL*out,const G98_STREAM_IO*stream)
{
 G98_PWR_CONTEXT context;G98_POWER_IO io;G98_SNAPSHOT before,after;
 LARGE_INTEGER begin,end,frequency;ULONG i;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));RtlZeroMemory(&context,sizeof(context));G98HardwareStatus(&out->Status);context.Trial=&out->Trial;context.Result=&out->Trial.Power;context.Stream=stream;out->Trial.SafeRelease=1;
 begin=KeQueryPerformanceCounter(&frequency);out->CounterFrequency=(ULONGLONG)frequency.QuadPart;
 if(!stream||(!stream->Persistent&&stream->CycleLimit!=G98_NATIVE_CYCLES&&stream->CycleLimit!=G98_PLAY_CYCLES)||(stream->Persistent&&(stream->CycleLimit!=G98_EPOCH_CYCLES||!stream->CycleComplete||!stream->EpochComplete))||!stream->Stage||!stream->Publish||!stream->StopRequested||!G98Available(stream)){out->Trial.Power.Code=1008;goto done;}
 if(InterlockedCompareExchange(&G98TrialUsed,1,0)!=0){out->Trial.Power.Code=1002;goto done;}
 InterlockedExchange(&G98LastReleaseVerified,0);
 out->Attempt=1;
 if(InterlockedCompareExchange(&G98ObserverAttempts,0,0)!=1||!InterlockedCompareExchange(&G98OffPmicVerified,0,0)||InterlockedCompareExchange(&G98ObserverFault,0,0)){out->Trial.Power.Code=1003;goto done;}
 if(!out->Status.FirmwareMatch||out->Status.Processors!=8||out->Status.CurrentIrql!=PASSIVE_LEVEL){out->Trial.Power.Code=1004;goto done;}
 status=G98HardwareSnapshot(&before,stream);
 if(!NT_SUCCESS(status)||!G98FixedBaseline(before.Values)){out->Trial.Power.Code=1005;goto done;}
 for(i=0;i<16;i++){
  if(!G98Available(stream)){out->Trial.Power.Code=1009;goto done;}
  PHYSICAL_ADDRESS at;at.QuadPart=(LONGLONG)G98PowerRanges[i].Base;InterlockedIncrement(&G98MapCalls);
  context.Maps[i]=MmMapIoSpaceEx(at,G98PowerRanges[i].Bytes,(i==0||i==2||i==3||i==7||i==8||i==9||i==10||i==13||i==14?PAGE_READWRITE:PAGE_READONLY)|PAGE_NOCACHE);
  if(!context.Maps[i]){out->Trial.Power.Code=1006;goto done;}
 }
 io.Rsc.Context=&context;io.Rsc.Read=G98PowerRead;io.Rsc.Write=G98PowerWrite;io.Rsc.WaitMillisecond=G98PowerWait1;
 io.Observer.Context=&context;io.Observer.Read=G98PowerRead;io.Observer.Write=G98PowerWrite;io.Observer.WaitMicrosecond=G98ObserverWait;io.Observer.Acquire=G98PowerAcquire;io.Observer.Release=G98PowerRelease;io.WaitTenMilliseconds=G98PowerWait10;io.Powered=G98Powered;io.SafeToRelease=G98SafeRelease;
 G98PowerTrial(&io,&out->Trial.Power);
 if(out->Trial.Power.Restored&&out->Trial.Touch.Restored){
  G98_TOUCH_IO finalIo={&context,stream->CycleLimit,G98PowerRead,G98PowerWrite,G98Barrier,G98Ready,G98WaitMs,G98WaitPoll,G98NowUs,G98StageInput,G98PublishInput,G98StopRequested,G98Advance,NULL};
  if(!G98VerifyTouchOff(&finalIo,&out->Trial.Touch)){out->Trial.Power.Restored=0;if(!out->Trial.Power.Code)out->Trial.Power.Code=109;}
 }
 done:
 for(i=16;i>0;i--)if(context.Maps[i-1])MmUnmapIoSpace(context.Maps[i-1],G98PowerRanges[i-1].Bytes);
 if(out->Trial.Power.Code<1000){
  status=G98HardwareSnapshot(&after,stream);
  if(NT_SUCCESS(status)&&G98FixedSameRestorable(before.Values,after.Values))out->FixedRegistersUnchanged=1;
  else if(!out->Trial.Power.Code)out->Trial.Power.Code=1007;
 }
 out->Status.MapCalls=(ULONG)InterlockedCompareExchange(&G98MapCalls,0,0);
 if(out->Attempt&&out->FixedRegistersUnchanged&&out->Trial.SafeRelease&&
    out->Trial.Power.Restored&&!out->Trial.Power.RestoreError&&out->Trial.Spi.Restored&&!out->Trial.Spi.RestoreError&&
    out->Trial.Spi.Engine.Restored&&!out->Trial.Spi.Engine.RestoreError&&out->Trial.Touch.Restored&&!out->Trial.Touch.RestoreError)
  InterlockedExchange(&G98LastReleaseVerified,1);
 end=KeQueryPerformanceCounter(NULL);out->ElapsedTicks=(ULONGLONG)(end.QuadPart-begin.QuadPart);
}

/* Serial caller, no powered owner. A prior lease is reusable only after every
 * layer's exact cleanup and a new independent PMIC/fixed-word off observation.
 * Uncertain cleanup or observer faults remain latched until device recovery. */
static int G334AdmitFailure(G98_TRIAL*out,uint32_t reason,const G98_PMIC*observed)
{
 G98_POWER_RESULT*p=&out->Trial.Power;
 p->Stage=33400+reason;
 p->GuardBefore[0]=(ULONG)InterlockedCompareExchange(&G98ObserverAttempts,0,0);
 p->GuardBefore[1]=(ULONG)InterlockedCompareExchange(&G98ObserverFault,0,0);
 p->GuardBefore[2]=(ULONG)InterlockedCompareExchange(&G98OffPmicVerified,0,0);
 p->GuardBefore[3]=(ULONG)InterlockedCompareExchange(&G98TrialUsed,0,0);
 p->GuardBefore[4]=(ULONG)InterlockedCompareExchange(&G98LastReleaseVerified,0,0);
 if(observed){p->PmicCount=1;p->PmicKinds[0]=334;p->Pmic[0]=observed->Observer;p->GuardBefore[5]=observed->FixedRegistersUnchanged;p->GuardBefore[6]=observed->Attempt;}
 return 0;
}
int G98HardwareAdmit(const G98_STREAM_IO*stream,G98_TRIAL*out)
{
 G98_PMIC observed;const G98_PMIC*seen=NULL;
 RtlZeroMemory(out,sizeof(*out));
 if(!G98Available(stream))return G334AdmitFailure(out,1,NULL);
 if(InterlockedCompareExchange(&G98ObserverFault,0,0))return G334AdmitFailure(out,2,NULL);
 if(InterlockedCompareExchange(&G98TrialUsed,0,0)){
  if(!InterlockedCompareExchange(&G98LastReleaseVerified,0,0))return G334AdmitFailure(out,3,NULL);
  G98HardwarePmic(&observed,stream);
  if(observed.Observer.Code||!observed.FixedRegistersUnchanged||!InterlockedCompareExchange(&G98OffPmicVerified,0,0)){InterlockedExchange(&G98ObserverFault,1);return G334AdmitFailure(out,4,&observed);}
  InterlockedExchange(&G98ObserverAttempts,1);InterlockedExchange(&G98TrialUsed,0);return 1;
 }
 if(InterlockedCompareExchange(&G98ObserverAttempts,0,0)==0){G98HardwarePmic(&observed,stream);seen=&observed;}
 if(!InterlockedCompareExchange(&G98OffPmicVerified,0,0)){InterlockedExchange(&G98ObserverFault,1);return G334AdmitFailure(out,5,seen);}
 if(InterlockedCompareExchange(&G98ObserverAttempts,0,0)!=1)return G334AdmitFailure(out,6,seen);
 if(InterlockedCompareExchange(&G98ObserverFault,0,0))return G334AdmitFailure(out,7,seen);
 return 1;
}
