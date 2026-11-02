/* SPDX-License-Identifier: MIT. No new hardware owner or user request path. */
#include "g293_keys.h"
#include "g100_bus.h"
static const ULONG Pages[5]={0xc400000,0xc402000,0xc42d000,0xc440000,0xc444000};
static void Publish(G293_KEYS*k)
{
 G293_STATUS s={0};KIRQL old;
 s.Size=sizeof(s);s.Version=1;s.Magic=G293_MAGIC;s.Epoch=k->Epoch;s.Sequence=k->Sequence;
 s.Samples=(ULONGLONG)InterlockedCompareExchange64(&k->Samples,0,0);s.AtUs=k->AtUs;
 s.PowerDowns=k->PowerDowns;s.LastDownUs=k->LastDownUs;s.ReportsEnabled=G293_POWER_REPORTS;
 s.LastStatus=(ULONG)InterlockedCompareExchange(&k->LastStatus,0,0);
 s.CoreCode=(ULONG)InterlockedCompareExchange(&k->LastCoreCode,0,0);
 s.StreamCode=(ULONG)InterlockedCompareExchange(&k->LastStreamCode,0,0);
 s.LastRaw=(ULONG)InterlockedCompareExchange(&k->LastRaw,0,0);s.StablePower=k->StablePower;
 s.LastSubmit=(ULONG)k->Vhf.LastSubmit;s.AcceptedDown=k->Vhf.Power.AcceptedDown;
 s.DeliveryUncertain=k->Vhf.Power.DeliveryUncertain;s.Running=(ULONG)k->Running;
 KeAcquireSpinLock(&k->CacheLock,&old);k->Cached=s;KeReleaseSpinLock(&k->CacheLock,old);
}
void G293KeysStatus(G293_KEYS*k,G293_STATUS*out)
{KIRQL old;KeAcquireSpinLock(&k->CacheLock,&old);*out=k->Cached;KeReleaseSpinLock(&k->CacheLock,old);}
void G308KeysFailure(G293_KEYS*k,G308_FAILURE*out)
{KIRQL old;KeAcquireSpinLock(&k->CacheLock,&old);*out=k->FirstFailure;KeReleaseSpinLock(&k->CacheLock,old);}
static void CacheFailure(G293_KEYS*k,NTSTATUS status)
{
 KIRQL old;KeAcquireSpinLock(&k->CacheLock,&old);
 if(!k->FirstFailure.Code&&k->Scratch&&k->Scratch->Code){
  G308_FAILURE*f=&k->FirstFailure;G99_RESULT*r=k->Scratch;
  f->Epoch=k->Epoch;f->AtUs=r->EndUs;f->Code=r->Code;f->Stage=r->Stage;
  f->Reads=r->Reads;f->Writes=r->Writes;f->Polls=r->Polls;f->TraceCount=r->TraceCount;
  f->Guard=k->Guard;f->NtStatus=(ULONG)status;
  if(r->TraceCount)f->Trace=r->Trace[r->TraceCount-1];
 }
 KeReleaseSpinLock(&k->CacheLock,old);
}
static int Available(void*x)
{G293_KEYS*k=x;return !KeReadStateEvent(&k->Stop)&&k->Available(k->Owner);}
static PULONG Address(G293_KEYS*k,ULONG at,int write,ULONG value)
{
 if((at&3)||(write?!G99WriteAllowed(at,value):!G99ReadAllowed(at)))return NULL;
 for(ULONG i=0;i<5;i++)if(k->Maps[i]&&at>=Pages[i]&&at-Pages[i]<=0xffc){
  if(write&&i<3)return NULL;return(PULONG)((PUCHAR)k->Maps[i]+at-Pages[i]);
 }
 return NULL;
}
static int Read(void*x,uint32_t at,uint32_t*v)
{
 G293_KEYS*k=x;PULONG p;
 if(!k->Present(k->Owner)||k->Reads>=80000||(at>=0xc440000&&at<0xc446000&&!k->GateHeld))return 0;
 p=Address(k,at,0,0);if(!p)return 0;k->Reads++;*v=READ_REGISTER_ULONG(p);return 1;
}
static int Write(void*x,uint32_t at,uint32_t value)
{
 G293_KEYS*k=x;PULONG p;G99_TRACE*proof=NULL;uint32_t map,owner,status,previous;unsigned i;
 if(!k->GateHeld||k->Writes>=G99_MAX_COMMANDS||!G99WriteAllowed(at,value)){k->Guard=1;return 0;}
 if(!Available(k)){k->Guard=4;return 0;}
 for(i=0;i<4;i++)if(at==G99Base(i))break;if(i==4){k->Guard=1;return 0;}
 if(!Read(k,0xc402000+G99Targets[i].Apid*4,&map)||!Read(k,0xc42d000+G99Targets[i].Apid*4,&owner)||
    map!=G99Targets[i].Map||owner!=G99Targets[i].Owner){k->Guard=2;return 0;}
 /* Existing trace slots carry native precheck proof only on refusal;
  * DATA stays clear. Data0=status, Data1=command with separate valid bits. */
 if(!k->Scratch||!k->Scratch->TraceCount||k->Scratch->TraceCount>G99_MAX_COMMANDS){k->Guard=1;return G99_WRITE_FAILED;}
 proof=&k->Scratch->Trace[k->Scratch->TraceCount-1];
 if(proof->Target!=i||!(proof->Flags&G99_COMMAND_ATTEMPTED)){k->Guard=1;return G99_WRITE_FAILED;}
 if(!Read(k,at+8,&status)){k->Guard=6;return G99_WRITE_FAILED;}
 proof->Data0=status;proof->Flags|=G99_NATIVE_STATUS_VALID;
 if(!Read(k,at,&previous)){k->Guard=7;return G99_WRITE_FAILED;}
 proof->Data1=previous;proof->Flags|=G99_NATIVE_COMMAND_VALID;
 if(!(status&1)&&previous){
  if(status==0){k->Guard=5;return G99_WRITE_BUSY_UNISSUED;}
  k->Guard=8;return G99_WRITE_FAILED;
 }
 p=Address(k,at,1,value);if(!p){k->Guard=1;return 0;}
 if(!Available(k)){k->Guard=4;return 0;}
 k->Writes++;WRITE_REGISTER_ULONG(p,value);return 1;
}
static void WaitUs(void*x){UNREFERENCED_PARAMETER(x);KeStallExecutionProcessor(1);}
static int Acquire(void*x){G293_KEYS*k=x;return G100BusAcquire(&k->GateHeld,Available,k);}
static void Release(void*x,int uncertain){G293_KEYS*k=x;G100BusRelease(&k->GateHeld,uncertain);}
static uint64_t NowUs(void*x)
{
 G293_KEYS*k=x;LARGE_INTEGER q=KeQueryPerformanceCounter(NULL);ULONGLONG u=(ULONGLONG)q.QuadPart;
 if(q.QuadPart<0||!k->Frequency)return 0;
 return u/k->Frequency*1000000+(u%k->Frequency)*1000000/k->Frequency;
}
static int Wait(G293_KEYS*k,LONGLONG ticks)
{LARGE_INTEGER period;period.QuadPart=-ticks;return KeWaitForSingleObject(&k->Stop,Executive,KernelMode,FALSE,&period)==STATUS_TIMEOUT;}
static void ResetCounters(G293_KEYS*k){k->Reads=k->Writes=k->Guard=0;}
#if !G293_POWER_REPORTS
static int ObserveSubmit(void*x,const uint8_t report[2])
{UNREFERENCED_PARAMETER(x);UNREFERENCED_PARAMETER(report);return 1;}
#endif
static VOID Worker(PVOID context)
{
 G293_KEYS*k=context;G99_IO io={k,Read,Write,WaitUs,NULL,Available,NowUs,Acquire,Release};
 G99_SAMPLE sample;B192_SAMPLE decoded;LARGE_INTEGER freq;NTSTATUS status=STATUS_SUCCESS;
 unsigned tries,skipStreak=0;int admission=0;
 /* Same early-hive qualification as touch. No mapping/commands until full1. */
 for(tries=0;tries<600&&Available(k);tries++){
  admission=k->Admission(k->Owner);if(admission!=2)break;
  if(!Wait(k,1000000))break;
 }
 if(!Available(k)){status=STATUS_CANCELLED;goto done;}
 if(admission!=1){status=STATUS_NOT_SUPPORTED;goto done;}
 KeQueryPerformanceCounter(&freq);k->Frequency=(ULONGLONG)freq.QuadPart;
 if(freq.QuadPart<=0||freq.QuadPart>1000000000LL){status=STATUS_INVALID_DEVICE_STATE;goto done;}
 k->Scratch=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*k->Scratch),'93GO');
 if(!k->Scratch){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 for(ULONG i=0;i<5;i++){
  PHYSICAL_ADDRESS a;a.QuadPart=Pages[i];
  if(!Available(k)){status=STATUS_CANCELLED;goto done;}
  k->Maps[i]=MmMapIoSpaceEx(a,0x1000,(i<3?PAGE_READONLY:PAGE_READWRITE)|PAGE_NOCACHE);
  if(!k->Maps[i]){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 }
 ResetCounters(k);
 if(!G293KeyStreamStart(&io,&k->Core,k->Scratch)){status=Available(k)?STATUS_DEVICE_PROTOCOL_ERROR:STATUS_CANCELLED;goto core_failure;}
#if G293_POWER_REPORTS
 status=Vhf291Create(&k->Vhf,k->Device,k->Epoch);if(!NT_SUCCESS(status))goto done;
#else
 P291Init(&k->Observe,k->Epoch,ObserveSubmit,NULL);
#endif
 while(Available(k)){
  uint32_t code,stable;
  ResetCounters(k);
  int acquired=G293KeyStreamRead(&io,&k->Core,k->Scratch,&sample);
  if(acquired==G293_STREAM_DROPPED||acquired==G293_STREAM_BUSY){
   /* Retain first acquisition-gap trace before scratch is reused. No stale HID
    * sample, synthetic release sample, controller reset or poison clearing. */
   CacheFailure(k,STATUS_DEVICE_PROTOCOL_ERROR);
   if(!G293StreamBudget((unsigned)acquired,&skipStreak)){k->Core.Fault=k->Scratch->Code;status=STATUS_DEVICE_PROTOCOL_ERROR;goto core_failure;}
#if G293_POWER_REPORTS
   if(!P291Suspend(&k->Vhf.Power)){status=STATUS_IO_DEVICE_ERROR;break;}
#else
   if(!P291Suspend(&k->Observe)){status=STATUS_IO_DEVICE_ERROR;break;}
#endif
   k->StablePower=0;InterlockedExchange(&k->LastPower,0);Publish(k);
   if(!Wait(k,200000)){status=STATUS_CANCELLED;break;}
   continue;
  }
  if(acquired!=G293_STREAM_SAMPLE){status=Available(k)?STATUS_DEVICE_PROTOCOL_ERROR:STATUS_CANCELLED;goto core_failure;}
  (void)G293StreamBudget(G293_STREAM_SAMPLE,&skipStreak);
  RtlZeroMemory(&decoded,sizeof(decoded));decoded.AtUs=sample.AtUs;RtlCopyMemory(decoded.Raw,sample.Raw,3);
  if(!Available(k)){status=STATUS_CANCELLED;break;}
  if(k->Sequence==MAXULONGLONG){status=STATUS_INTEGER_OVERFLOW;break;}
#if G293_POWER_REPORTS
  code=P291Step(&k->Vhf.Power,k->Epoch,++k->Sequence,&decoded);
  stable=k->Vhf.Power.Stream.Stable&B192_POWER;
#else
  code=P291Step(&k->Observe,k->Epoch,++k->Sequence,&decoded);
  stable=k->Observe.Stream.Stable&B192_POWER;
#endif
  InterlockedExchange(&k->LastStreamCode,(LONG)code);
  if(code){status=STATUS_DEVICE_PROTOCOL_ERROR;break;}
  InterlockedExchange(&k->LastRaw,(LONG)(sample.Raw[0]|(ULONG)sample.Raw[1]<<8|(ULONG)sample.Raw[2]<<16));
  if(stable&&!k->StablePower){
   if(k->PowerDowns==MAXULONGLONG){status=STATUS_INTEGER_OVERFLOW;break;}
   k->PowerDowns++;k->LastDownUs=sample.AtUs;
  }
  k->StablePower=stable;k->AtUs=sample.AtUs;InterlockedExchange(&k->LastPower,(LONG)stable);
  InterlockedIncrement64(&k->Samples);
  InterlockedExchange(&k->LastStatus,STATUS_SUCCESS);Publish(k);
  if(!Wait(k,200000)){status=STATUS_CANCELLED;break;}
 }
 goto done;
 core_failure:CacheFailure(k,status);InterlockedExchange(&k->LastCoreCode,(LONG)k->Core.Fault);
 done:
#if G293_POWER_REPORTS
 if(k->Vhf.Vhf&&!Vhf291StopDelete(&k->Vhf))status=STATUS_IO_DEVICE_ERROR;
#endif
 /* In-flight READ completion/poison happens inside core before unmapping. */
 NT_ASSERT(!k->GateHeld);
 for(ULONG i=5;i;i--)if(k->Maps[i-1]){MmUnmapIoSpace(k->Maps[i-1],0x1000);k->Maps[i-1]=NULL;}
 if(k->Scratch){ExFreePoolWithTag(k->Scratch,'93GO');k->Scratch=NULL;}
 InterlockedExchange(&k->LastStatus,status);InterlockedExchange(&k->Running,0);Publish(k);PsTerminateSystemThread(status);
}
void G293KeysInitialize(G293_KEYS*k,WDFDEVICE device,void*owner,int(*available)(void*),int(*admission)(void*),int(*present)(void*))
{RtlZeroMemory(k,sizeof(*k));k->Device=device;k->Owner=owner;k->Available=available;k->Admission=admission;k->Present=present;KeInitializeEvent(&k->Stop,NotificationEvent,FALSE);KeInitializeSpinLock(&k->CacheLock);k->FirstFailure.Size=sizeof(k->FirstFailure);k->FirstFailure.Version=1;k->FirstFailure.Magic=G293_MAGIC;Publish(k);}
NTSTATUS G293KeysStart(G293_KEYS*k)
{
 OBJECT_ATTRIBUTES attributes;NTSTATUS status;
 if(k->Thread)return STATUS_SUCCESS;
 if(!k->Available(k->Owner)||k->Epoch==MAXULONGLONG)return STATUS_INVALID_DEVICE_STATE;
 RtlZeroMemory(&k->Core,sizeof(k->Core));k->Sequence=0;k->Epoch++;
 k->AtUs=k->PowerDowns=k->LastDownUs=0;k->StablePower=0;
 InterlockedExchange(&k->LastStatus,STATUS_PENDING);InterlockedExchange(&k->LastCoreCode,0);InterlockedExchange(&k->LastStreamCode,0);
 KeClearEvent(&k->Stop);InitializeObjectAttributes(&attributes,NULL,OBJ_KERNEL_HANDLE,NULL,NULL);
 InterlockedExchange(&k->Running,1);Publish(k);
 status=PsCreateSystemThread(&k->Thread,THREAD_ALL_ACCESS,&attributes,NULL,NULL,Worker,k);
 if(!NT_SUCCESS(status)){k->Thread=NULL;InterlockedExchange(&k->LastStatus,status);InterlockedExchange(&k->Running,0);Publish(k);}return status;
}
NTSTATUS G293KeysStop(G293_KEYS*k)
{
 NTSTATUS status;KeSetEvent(&k->Stop,IO_NO_INCREMENT,FALSE);
 if(!k->Thread)return STATUS_SUCCESS;
 status=ZwWaitForSingleObject(k->Thread,FALSE,NULL);if(status!=STATUS_SUCCESS)return status;
 status=ZwClose(k->Thread);if(NT_SUCCESS(status))k->Thread=NULL;return status;
}
