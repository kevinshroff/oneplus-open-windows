/* SPDX-License-Identifier: MIT
 * Device-owned touch lifetime on a dedicated PASSIVE system thread.
 * No request/user buffer survives dispatch. Stop/close/suspend join the owner
 * before VHF deletion, buffer release or loss of D0. Hardware access is denied
 * after surprise-removal observation. This is still a fixed-platform prototype.
 */
#include <ntifs.h>
#include <wdf.h>
#include <aux_klib.h>
#include <vhf.h>
#include "g98hid_baseline.h"
#include "g98hid_protocol.h"
#include "g98hid_report.h"
#include "g98_input.h"
#include "g98_hwapi.h"
#include "g100_bus.h"
#include "g100_keys.h"

typedef struct {
 VHFHANDLE Handle;KMUTEX Control;ULONG ControlInitialized;
 HANDLE Thread;WDFFILEOBJECT OwnerFile;G98_TRIAL*Result;
 volatile LONG D0,Started,CreateStatus,StartStatus,Entries,Exits,Features,LiveAttempts,LastSubmit;
 volatile LONG State,StopReason,Starts,HardwareCalls,ResultReady,Outcome,StopChecks,StopSeen,Inhibit,ThreadJoined,Phase,PollCycles,ThreadCreateStatus,Removed,StopRequests;
 volatile LONG64 Sequence,BeginUs,EndUs,StopUs;
 G98_INPUT Live;ULONG LastHardwareCode,LiveComplete,CycleLimit,Persistent;
 volatile LONG64 DiagSubmitted,DiagAccepted,DiagCycles,DiagEpochs,DiagReads,DiagWrites,DiagWires,LastCycleUs,OwnerStarts,Recoveries;
 G100_KEYS Keys;G98_FAULT FirstFault;volatile LONG FaultReady;
}G98HID_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(G98HID_CONTEXT,G98HIDContext)
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD G98HIDAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP G98HIDCleanup;
EVT_WDF_DEVICE_D0_ENTRY G98HIDD0Entry;
EVT_WDF_DEVICE_D0_EXIT G98HIDD0Exit;
EVT_WDF_DEVICE_SELF_MANAGED_IO_INIT G98HIDIoInit;
EVT_WDF_DEVICE_SELF_MANAGED_IO_SUSPEND G98HIDSuspend;
EVT_WDF_DEVICE_SELF_MANAGED_IO_RESTART G98HIDRestart;
EVT_WDF_DEVICE_SURPRISE_REMOVAL G98HIDSurprise;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G98HIDControl;
EVT_WDF_DEVICE_FILE_CREATE G98HIDFileCreate;
EVT_WDF_FILE_CLEANUP G98HIDFileCleanup;
EVT_VHF_ASYNC_OPERATION G98HIDFeature;
static ULONG Counter(volatile LONG*p){return(ULONG)InterlockedCompareExchange(p,0,0);}
static ULONGLONG TimeValue(volatile LONG64*p){return(ULONGLONG)InterlockedCompareExchange64(p,0,0);}
static volatile LONG G98FullStage,G98FullStatus,G98FullType,G98FullBytes;
static int OsAdmission(void)
{
 UNICODE_STRING name;OBJECT_ATTRIBUTES attributes;HANDLE key;NTSTATUS status;ULONG bytes=0;
 union {KEY_VALUE_PARTIAL_INFORMATION Info;UCHAR Storage[128];} value;
 static const WCHAR expected[]=L"C:\\Windows";
 InterlockedExchange(&G98FullStage,1);InterlockedExchange(&G98FullStatus,0);InterlockedExchange(&G98FullType,0);InterlockedExchange(&G98FullBytes,0);
 if(KeGetCurrentIrql()!=PASSIVE_LEVEL)return 0;
 RtlInitUnicodeString(&name,L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\MiniNT");
 InitializeObjectAttributes(&attributes,&name,OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,NULL,NULL);
 InterlockedExchange(&G98FullStage,2);status=ZwOpenKey(&key,KEY_QUERY_VALUE,&attributes);InterlockedExchange(&G98FullStatus,status);
 if(NT_SUCCESS(status)){ZwClose(key);return 0;}
 if(status!=STATUS_OBJECT_NAME_NOT_FOUND&&status!=STATUS_OBJECT_PATH_NOT_FOUND)return 0;
 RtlInitUnicodeString(&name,L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
 InitializeObjectAttributes(&attributes,&name,OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,NULL,NULL);
 InterlockedExchange(&G98FullStage,3);status=ZwOpenKey(&key,KEY_QUERY_VALUE,&attributes);InterlockedExchange(&G98FullStatus,status);if(!NT_SUCCESS(status))return status==STATUS_OBJECT_NAME_NOT_FOUND||status==STATUS_OBJECT_PATH_NOT_FOUND?2:0;
 RtlInitUnicodeString(&name,L"SystemRoot");
 InterlockedExchange(&G98FullStage,4);status=ZwQueryValueKey(key,&name,KeyValuePartialInformation,&value,sizeof(value),&bytes);InterlockedExchange(&G98FullStatus,status);ZwClose(key);
 if(NT_SUCCESS(status)&&bytes>=FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION,Data)){InterlockedExchange(&G98FullType,value.Info.Type);InterlockedExchange(&G98FullBytes,value.Info.DataLength);}
 return NT_SUCCESS(status)&&bytes<=sizeof(value)&&value.Info.Type==REG_SZ&&
  (value.Info.DataLength==sizeof(expected)||value.Info.DataLength==sizeof(expected)-sizeof(WCHAR))&&
  bytes>=FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION,Data)+value.Info.DataLength&&
  RtlCompareMemory(value.Info.Data,expected,value.Info.DataLength)==value.Info.DataLength;
}
static void CycleComplete(void*x)
{
 G98HID_CONTEXT*c=x;InterlockedIncrement64(&c->DiagCycles);InterlockedExchange64(&c->LastCycleUs,(LONG64)G98HardwareTimeUs());
}
static void EpochComplete(void*x,uint32_t reads,uint32_t writes,uint32_t wires)
{
 G98HID_CONTEXT*c=x;InterlockedExchangeAdd64(&c->DiagReads,reads);InterlockedExchangeAdd64(&c->DiagWrites,writes);InterlockedExchangeAdd64(&c->DiagWires,wires);InterlockedIncrement64(&c->DiagEpochs);
}
static void OwnerLock(G98HID_CONTEXT*c){NTSTATUS s=KeWaitForSingleObject(&c->Control,Executive,KernelMode,FALSE,NULL);NT_ASSERT(s==STATUS_SUCCESS);UNREFERENCED_PARAMETER(s);}
static void OwnerUnlock(G98HID_CONTEXT*c){KeReleaseMutex(&c->Control,FALSE);}
static int Available(void*x){return !Counter(&((G98HID_CONTEXT*)x)->Removed);}
static int KeysAvailable(void*x){G98HID_CONTEXT*c=x;return Available(c)&&Counter(&c->D0)&&Counter(&c->Started)&&!Counter(&c->Inhibit);}
static int StopRequested(void*x)
{
 G98HID_CONTEXT*c=x;InterlockedIncrement(&c->StopChecks);
 InterlockedExchange(&c->Phase,c->Result->Trial.Touch.Stage);InterlockedExchange(&c->PollCycles,c->Result->Trial.Touch.Poll.Cycles);
 if(!Counter(&c->StopReason))return 0;InterlockedIncrement(&c->StopSeen);return 1;
}
static void SessionStatus(G98HID_CONTEXT*c,G98_SESSION*out)
{
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=1;out->Magic=G98HID_MAGIC;
 out->State=Counter(&c->State);out->StopReason=Counter(&c->StopReason);out->Starts=Counter(&c->Starts);out->HardwareCalls=Counter(&c->HardwareCalls);out->ResultReady=Counter(&c->ResultReady);out->Outcome=Counter(&c->Outcome);out->StopChecks=Counter(&c->StopChecks);out->StopSeen=Counter(&c->StopSeen);out->Inhibit=Counter(&c->Inhibit);out->ThreadJoined=Counter(&c->ThreadJoined);out->Phase=Counter(&c->Phase);out->PollCycles=Counter(&c->PollCycles);out->ThreadCreateStatus=Counter(&c->ThreadCreateStatus);
 out->BeginUs=TimeValue(&c->BeginUs);out->EndUs=TimeValue(&c->EndUs);out->StopUs=TimeValue(&c->StopUs);out->StopRequests=Counter(&c->StopRequests);
}
static VOID Status(G98HID_CONTEXT*c,G98HID_STATUS*out)
{
 UCHAR table[sizeof(G98HIDExpectedDsdt)];ULONG bytes=0;RTL_OSVERSIONINFOW version;NTSTATUS status;
 RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=G98HID_ABI;out->Magic=G98HID_MAGIC;
 out->Processors=KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);out->Irql=KeGetCurrentIrql();
 RtlZeroMemory(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);if(NT_SUCCESS(RtlGetVersion(&version)))out->KernelBuild=version.dwBuildNumber;
 status=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table),&bytes);out->FirmwareBytes=bytes;
 if(NT_SUCCESS(status)&&bytes==sizeof(table)&&RtlCompareMemory(table,G98HIDExpectedDsdt,sizeof(table))==sizeof(table))out->FirmwareMatch=1;
 out->D0=Counter(&c->D0);out->Started=Counter(&c->Started);out->CreateStatus=Counter(&c->CreateStatus);out->StartStatus=Counter(&c->StartStatus);out->Entries=Counter(&c->Entries);out->Exits=Counter(&c->Exits);out->Features=Counter(&c->Features);out->LiveAttempts=Counter(&c->LiveAttempts);out->LastSubmit=Counter(&c->LastSubmit);
 out->MaxContacts=G98HID_CONTACTS;out->MaxX=G98HID_RAW_X_MAX;out->MaxY=G98HID_RAW_Y_MAX;out->ReportBytes=G98HID_REPORT_BYTES;out->DescriptorBytes=G98HIDDescriptorBytes;
 /* The worker is the only writer of Live. Publish its frozen state only after
  * the interlocked DONE transition; do not race non-atomic input structures. */
 if(Counter(&c->State)==G98_OWNER_DONE){out->ReportsAccepted=c->Live.SubmitAccepted;out->LiveComplete=c->LiveComplete;out->LiveError=c->LastHardwareCode?c->LastHardwareCode:c->Live.Error;out->StopAttempts=c->Live.StopAttempts;out->StopAccepted=c->Live.StopAccepted;out->AcceptedMask=c->Live.Accepted.Mask;out->AcceptedGeneration=c->Live.Accepted.Generation;out->ReportsSubmitted=c->Live.SubmitAttempts;}
 if(Counter(&c->State)!=G98_OWNER_DONE){out->ReportsAccepted=(ULONG)TimeValue(&c->DiagAccepted);out->ReportsSubmitted=(ULONG)TimeValue(&c->DiagSubmitted);}
 out->Sequence=(ULONGLONG)InterlockedIncrement64(&c->Sequence);RtlCopyMemory(out->BuildId,"G98-stream1",sizeof("G98-stream1"));
}
/* 0 refuses, 1 is fully qualified, 2 is the observed early-boot hive gap.
 * Pending admits only an unpowered owner. The same complete gate must return
 * 1 in its worker before even the independent PMIC observer is called. */
static int Admission(G98HID_CONTEXT*c,G98HID_STATUS*proof)
{
 G98HID_STATUS identity;int os;Status(c,&identity);if(proof)*proof=identity;
 os=OsAdmission();
 if(!identity.FirmwareMatch||identity.Processors!=8||identity.Irql!=PASSIVE_LEVEL)return 0;
 if(os==1&&identity.KernelBuild==26300)return 1;
 /* The hive can appear between Status and OsAdmission. A known early
  * version remains pending until a fresh full gate returns1. */
 if((os==1||os==2)&&(identity.KernelBuild==26100||identity.KernelBuild==26300))return 2;
 return 0;
}
static int WaitAdmission(G98HID_CONTEXT*c)
{
 LARGE_INTEGER wait;unsigned i;int admission;wait.QuadPart=-1000000;
 for(i=0;i<600;i++){
  if(StopRequested(c)||!Available(c))return -1;
  admission=Admission(c,NULL);if(admission!=2)return admission;
  KeDelayExecutionThread(KernelMode,FALSE,&wait);
 }
 return 0;
}

static void RuntimeStatus(G98HID_CONTEXT*c,G98_RUNTIME*out)
{
 G98_SESSION session;SessionStatus(c,&session);RtlZeroMemory(out,sizeof(*out));out->Size=sizeof(*out);out->Version=1;out->Magic=G98HID_MAGIC;
 out->State=session.State;out->StopReason=session.StopReason;out->Starts=session.Starts;out->HardwareCalls=session.HardwareCalls;out->ResultReady=session.ResultReady;out->Outcome=session.Outcome;out->Inhibit=session.Inhibit;out->ThreadJoined=session.ThreadJoined;
 out->Cycles=TimeValue(&c->DiagCycles);out->Epochs=TimeValue(&c->DiagEpochs);out->ReportsSubmitted=TimeValue(&c->DiagSubmitted);out->ReportsAccepted=TimeValue(&c->DiagAccepted);out->Reads=TimeValue(&c->DiagReads);out->Writes=TimeValue(&c->DiagWrites);out->Wires=TimeValue(&c->DiagWires);out->BeginUs=session.BeginUs;out->LastCycleUs=TimeValue(&c->LastCycleUs);out->OwnerStarts=TimeValue(&c->OwnerStarts);out->Recoveries=TimeValue(&c->Recoveries);out->D0=Counter(&c->D0);out->Started=Counter(&c->Started);out->FaultReady=Counter(&c->FaultReady);
 if(Counter(&c->State)==G98_OWNER_DONE){out->HardwareCode=c->Result->Trial.Power.Code;out->PollCode=c->Result->Trial.Touch.Poll.Code;out->TouchCode=c->Result->Trial.Touch.Code;}
}
VOID G98HIDFeature(PVOID context,VHFOPERATIONHANDLE operation,PVOID operationContext,PHID_XFER_PACKET packet)
{
 G98HID_CONTEXT*c=context;uint32_t written=0;NTSTATUS status=STATUS_NOT_SUPPORTED;UNREFERENCED_PARAMETER(operationContext);
 InterlockedIncrement(&c->Features);
 if(packet&&G98HIDGetFeature(packet->reportId,packet->reportBuffer,packet->reportBufferLen,&written)){packet->reportBufferLen=written;status=STATUS_SUCCESS;}
 VhfAsyncOperationComplete(operation,status);
}
static int G98HIDSubmit(void*context,const uint8_t bytes[64])
{
 G98HID_CONTEXT*c=context;HID_XFER_PACKET packet;NTSTATUS status;
 if(!c->Handle||!Counter(&c->D0)||!Counter(&c->Started))return 0;
 RtlZeroMemory(&packet,sizeof(packet));packet.reportBuffer=(PUCHAR)bytes;packet.reportBufferLen=64;packet.reportId=1;
 InterlockedIncrement64(&c->DiagSubmitted);status=VhfReadReportSubmit(c->Handle,&packet);if(NT_SUCCESS(status))InterlockedIncrement64(&c->DiagAccepted);InterlockedExchange(&c->LastSubmit,status);return NT_SUCCESS(status);
}
static int G98HIDStage(void*context,const uint8_t*raw,uint32_t n,uint64_t at)
{
 G98HID_CONTEXT*c=context;if(!c->Handle||!Counter(&c->D0)||!Counter(&c->Started))return 0;
 return G98InputStage(&c->Live,raw,n,(uint16_t)(at/100));
}
static int G98HIDPublish(void*context,const uint8_t*raw,uint32_t n)
{
 G98HID_CONTEXT*c=context;G98_INPUT_IO io={c,G98HIDSubmit};
 if(!c->Handle||!Counter(&c->D0)||!Counter(&c->Started))return 0;
 return G98InputPublish(&c->Live,&io,raw,n);
}

static void RequestStop(G98HID_CONTEXT*c,ULONG reason)
{
 ULONG state=Counter(&c->State);ULONGLONG at;
 if(state!=G98_OWNER_QUEUED&&state!=G98_OWNER_RUNNING)return;
 InterlockedIncrement(&c->StopRequests);at=G98HardwareTimeUs();
 if(InterlockedCompareExchange(&c->StopReason,reason,0)==0)InterlockedExchange64(&c->StopUs,(LONG64)at);
}
/* Caller holds Control. The worker never acquires Control, and its kernel
 * handle is created/closed only under this mutex. A join waits for actual
 * thread termination, not merely a result-ready event. */
static NTSTATUS Join(G98HID_CONTEXT*c,ULONG reason)
{
 NTSTATUS s;RequestStop(c,reason);if(!c->Thread)return STATUS_SUCCESS;
 s=ZwWaitForSingleObject(c->Thread,FALSE,NULL);if(s!=STATUS_SUCCESS)return s;
 s=ZwClose(c->Thread);if(!NT_SUCCESS(s))return s;
 c->Thread=NULL;c->OwnerFile=NULL;InterlockedExchange(&c->ThreadJoined,1);return STATUS_SUCCESS;
}
static int Restored(G98HID_CONTEXT*c)
{
 G98_TRIAL*t=c->Result;
 return t->Attempt&&t->FixedRegistersUnchanged&&t->Trial.SafeRelease&&t->Trial.Power.Restored&&!t->Trial.Power.RestoreError&&t->Trial.Spi.Restored&&!t->Trial.Spi.RestoreError&&t->Trial.Spi.Engine.Restored&&!t->Trial.Spi.Engine.RestoreError&&t->Trial.Touch.Restored&&!t->Trial.Touch.RestoreError;
}
static void SaveFirstFault(G98HID_CONTEXT*c)
{
 G98_POLL_RESULT*p=&c->Result->Trial.Touch.Poll;G98_FAULT*f=&c->FirstFault;G98_POLL_RECORD*r;
 if(Counter(&c->FaultReady)||!p->Code||p->Code==G98_POLL_CANCELLED||!p->Cycles)return;r=&p->Records[(p->Cycles-1)%G98_POLL_RECORDS];
 RtlZeroMemory(f,sizeof(*f));f->Size=sizeof(*f);f->Version=1;f->Magic=G98HID_MAGIC;f->Present=1;f->PollCode=p->Code;f->FrameError=r->Frame.Error;f->ReadBytes=r->ReadBytes;f->AtUs=G98HardwareTimeUs();RtlCopyMemory(f->Bytes,r->Bytes,sizeof(f->Bytes));
 /* This snapshot is immutable after its release/acquire publication. */
 InterlockedExchange(&c->FaultReady,1);
}
static int Retryable(G98HID_CONTEXT*c)
{
 G98_POLL_RESULT*p=&c->Result->Trial.Touch.Poll;G98_POLL_RECORD*r;
 if(!c->Persistent||c->Live.Error||!Restored(c)||c->Live.Accepted.Mask||p->Code!=G98_POLL_DECODE||!p->Cycles||c->Result->Trial.Touch.Code!=18)return 0;
 r=&p->Records[(p->Cycles-1)%G98_POLL_RECORDS];return G98RetryablePrefix(r->Bytes,r->ReadBytes)!=0;
}
static int RecoveryWait(G98HID_CONTEXT*c)
{
 LARGE_INTEGER wait;unsigned i;wait.QuadPart=-1000000;
 for(i=0;i<5;i++){if(StopRequested(c)||!Available(c))return 0;KeDelayExecutionThread(KernelMode,FALSE,&wait);}return !StopRequested(c)&&Available(c);
}
static VOID Worker(PVOID context)
{
 G98HID_CONTEXT*c=context;G98_TRIAL*t=c->Result;G98_STREAM_IO stream={c,G98HIDStage,G98HIDPublish,StopRequested,Available,c->CycleLimit,c->Persistent,CycleComplete,EpochComplete};G98_INPUT_IO input={c,G98HIDSubmit};int released,restored,admission;ULONG outcome;
 InterlockedIncrement(&c->LiveAttempts);
 for(;;){InterlockedExchange(&c->State,G98_OWNER_QUEUED);admission=WaitAdmission(c);
 if(admission<0||Counter(&c->StopReason)||!Available(c)){
  RtlZeroMemory(t,sizeof(*t));G98HardwareStatus(&t->Status);t->Trial.Power.Code=1010;t->Trial.SafeRelease=1;
  InterlockedIncrement(&c->StopSeen);outcome=G98_OUTCOME_CANCELLED_BEFORE_HARDWARE;
 }else{
  outcome=G98_OUTCOME_FAILED;
  if(!admission){RtlZeroMemory(t,sizeof(*t));G98HardwareStatus(&t->Status);t->Trial.Power.Code=1012;t->Trial.SafeRelease=1;}
  else if(!G98HardwareAdmit(&stream)){RtlZeroMemory(t,sizeof(*t));G98HardwareStatus(&t->Status);t->Trial.Power.Code=1011;}
  else if(Counter(&c->StopReason)||!Available(c)){RtlZeroMemory(t,sizeof(*t));G98HardwareStatus(&t->Status);t->Trial.Power.Code=1010;t->Trial.SafeRelease=1;InterlockedIncrement(&c->StopSeen);outcome=G98_OUTCOME_CANCELLED_BEFORE_HARDWARE;}
  else{InterlockedExchange(&c->State,G98_OWNER_RUNNING);InterlockedIncrement(&c->HardwareCalls);G98HardwareTrial(t,&stream);}
 }
 released=G98InputStop(&c->Live,&input,(uint16_t)(G98HardwareTimeUs()/100));
 c->LastHardwareCode=t->Trial.Power.Code;
 restored=Restored(c);
 SaveFirstFault(c);
 if(released&&Retryable(c)&&!Counter(&c->StopReason)&&TimeValue(&c->Recoveries)<3){
  if(!RecoveryWait(c)){outcome=G98_OUTCOME_CANCELLED;break;}
  InterlockedIncrement64(&c->Recoveries);RtlZeroMemory(&c->Live,sizeof(c->Live));continue;
 }
 break;}
 c->LiveComplete=!c->Persistent&&released&&!c->Live.Error&&restored&&t->Trial.Power.Code==0&&t->Trial.Touch.Code==0&&t->Trial.Touch.Poll.Code==0&&t->Trial.Touch.Poll.Limit==c->CycleLimit&&t->Trial.Touch.Poll.Cycles==c->CycleLimit;
 if(c->LiveComplete)outcome=G98_OUTCOME_COMPLETE;
 else if(released&&!c->Live.Error&&restored&&Counter(&c->StopReason)&&(t->Trial.Touch.Code==G98_TOUCH_CANCELLED||c->Persistent))outcome=G98_OUTCOME_CANCELLED;
 InterlockedExchange(&c->Outcome,outcome);InterlockedExchange(&c->Phase,t->Trial.Touch.Stage);InterlockedExchange(&c->PollCycles,t->Trial.Touch.Poll.Cycles);InterlockedExchange64(&c->EndUs,(LONG64)G98HardwareTimeUs());
 InterlockedExchange(&c->ResultReady,1);InterlockedExchange(&c->State,G98_OWNER_DONE);
 PsTerminateSystemThread(STATUS_SUCCESS);
}
static NTSTATUS Start(G98HID_CONTEXT*c,WDFFILEOBJECT file,ULONG cycles)
{
 G98HID_STATUS identity;OBJECT_ATTRIBUTES attributes;NTSTATUS s;int admission;
 if(cycles!=G98_NATIVE_CYCLES&&cycles!=G98_PLAY_CYCLES&&cycles!=G98_EPOCH_CYCLES)return STATUS_INVALID_PARAMETER;
 admission=Admission(c,&identity);if(admission==0||(admission==2&&cycles!=G98_EPOCH_CYCLES))return STATUS_NOT_SUPPORTED;
 if(!identity.D0||!identity.Started||!c->Handle||!c->Result||(!file&&cycles!=G98_EPOCH_CYCLES)||Counter(&c->Inhibit)||!Available(c))return STATUS_DEVICE_NOT_READY;
 if(cycles==G98_EPOCH_CYCLES&&Counter(&c->State)==G98_OWNER_DONE){
  int noHardware=Counter(&c->Outcome)==G98_OUTCOME_CANCELLED_BEFORE_HARDWARE&&!Counter(&c->HardwareCalls)&&c->Result->Trial.SafeRelease;
  if(!Counter(&c->ResultReady)||(!Restored(c)&&!noHardware)||c->Live.Accepted.Mask||c->Live.Error)return STATUS_DEVICE_NOT_READY;
  s=Join(c,G98_STOP_NONE);if(!NT_SUCCESS(s))return s;
  RtlZeroMemory(&c->Live,sizeof(c->Live));c->LastHardwareCode=c->LiveComplete=0;
  InterlockedExchange(&c->State,G98_OWNER_IDLE);InterlockedExchange(&c->Starts,0);InterlockedExchange(&c->HardwareCalls,0);InterlockedExchange(&c->ResultReady,0);InterlockedExchange(&c->Outcome,0);InterlockedExchange(&c->StopReason,0);InterlockedExchange(&c->StopChecks,0);InterlockedExchange(&c->StopSeen,0);InterlockedExchange(&c->ThreadJoined,0);InterlockedExchange(&c->Phase,0);InterlockedExchange(&c->PollCycles,0);InterlockedExchange(&c->StopRequests,0);InterlockedExchange64(&c->EndUs,0);InterlockedExchange64(&c->StopUs,0);
 }
 if(Counter(&c->State)!=G98_OWNER_IDLE||InterlockedCompareExchange(&c->Starts,1,0)!=0)return STATUS_QUOTA_EXCEEDED;
 c->Persistent=cycles==G98_EPOCH_CYCLES;c->CycleLimit=cycles;c->OwnerFile=c->Persistent?NULL:file;InterlockedIncrement64(&c->OwnerStarts);InterlockedExchange64(&c->BeginUs,(LONG64)G98HardwareTimeUs());InterlockedExchange(&c->State,G98_OWNER_QUEUED);
 InitializeObjectAttributes(&attributes,NULL,OBJ_KERNEL_HANDLE,NULL,NULL);
 s=PsCreateSystemThread(&c->Thread,SYNCHRONIZE,&attributes,NULL,NULL,Worker,c);InterlockedExchange(&c->ThreadCreateStatus,s);
 if(!NT_SUCCESS(s)){c->Thread=NULL;c->OwnerFile=NULL;InterlockedExchange(&c->Outcome,G98_OUTCOME_FAILED);InterlockedExchange(&c->State,G98_OWNER_DONE);}
 return s;
}
VOID G98HIDControl(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code)
{
 G98HID_CONTEXT*c=G98HIDContext(WdfIoQueueGetDevice(queue));G98HID_REQUEST*in;PVOID out;NTSTATUS status;ULONG_PTR information=0;size_t needed;int hw;
 if(G100KeysTryControl(&c->Keys,request,outputBytes,inputBytes,code))return;
 hw=code==G98_IOCTL_STATUS||code==G98_IOCTL_SNAPSHOT||code==G98_IOCTL_PMIC||code==G98_IOCTL_POWER;
 if(!hw&&code!=G98HID_IOCTL_STATUS&&code!=G98HID_IOCTL_SESSION&&code!=G98HID_IOCTL_START&&code!=G98HID_IOCTL_STOP&&code!=G98HID_IOCTL_PLAY&&code!=G98HID_IOCTL_RUNTIME&&code!=G98HID_IOCTL_RUN&&code!=G98HID_IOCTL_FAULT){status=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inputBytes!=sizeof(*in)){status=STATUS_INVALID_PARAMETER;goto done;}
 status=WdfRequestRetrieveInputBuffer(request,sizeof(*in),(PVOID*)&in,NULL);if(!NT_SUCCESS(status))goto done;
 if(in->Size!=sizeof(*in)||in->Version!=1||in->Magic!=(hw?G98_MAGIC:G98HID_MAGIC)){status=STATUS_INVALID_PARAMETER;goto done;}
 needed=code==G98HID_IOCTL_FAULT?sizeof(G98_FAULT):code==G98HID_IOCTL_RUNTIME?sizeof(G98_RUNTIME):code==G98HID_IOCTL_STATUS?sizeof(G98HID_STATUS):!hw?sizeof(G98_SESSION):code==G98_IOCTL_STATUS?sizeof(G98_STATUS):code==G98_IOCTL_SNAPSHOT?sizeof(G98_SNAPSHOT):code==G98_IOCTL_PMIC?sizeof(G98_PMIC):sizeof(G98_TRIAL);
 if(outputBytes<needed){status=STATUS_BUFFER_TOO_SMALL;goto done;}
 status=WdfRequestRetrieveOutputBuffer(request,needed,&out,NULL);if(!NT_SUCCESS(status))goto done;
 OwnerLock(c);
 if(code==G98HID_IOCTL_STATUS){Status(c,out);status=STATUS_SUCCESS;}
 else if(code==G98HID_IOCTL_SESSION){SessionStatus(c,out);status=STATUS_SUCCESS;}
 else if(code==G98HID_IOCTL_RUNTIME){RuntimeStatus(c,out);status=STATUS_SUCCESS;}
 else if(code==G98HID_IOCTL_FAULT){if(Counter(&c->FaultReady))RtlCopyMemory(out,&c->FirstFault,sizeof(c->FirstFault));else{G98_FAULT*f=out;RtlZeroMemory(f,sizeof(*f));f->Size=sizeof(*f);f->Version=1;f->Magic=G98HID_MAGIC;}status=STATUS_SUCCESS;}
 else if(code==G98HID_IOCTL_RUN){status=Start(c,NULL,G98_EPOCH_CYCLES);if(NT_SUCCESS(status))SessionStatus(c,out);}
 else if(code==G98HID_IOCTL_START||code==G98HID_IOCTL_PLAY){status=Start(c,WdfRequestGetFileObject(request),code==G98HID_IOCTL_PLAY?G98_PLAY_CYCLES:G98_NATIVE_CYCLES);if(NT_SUCCESS(status))SessionStatus(c,out);}
 else if(code==G98HID_IOCTL_STOP){status=Join(c,G98_STOP_EXPLICIT);if(NT_SUCCESS(status))SessionStatus(c,out);}
 else if(code==G98_IOCTL_POWER){
  /* This old function number retrieves a frozen result. It never powers. */
  if(!Counter(&c->ResultReady)||Counter(&c->State)!=G98_OWNER_DONE)status=STATUS_DEVICE_NOT_READY;
  else{status=Join(c,G98_STOP_NONE);if(NT_SUCCESS(status))RtlCopyMemory(out,c->Result,sizeof(*c->Result));}
 }else if(code==G98_IOCTL_STATUS){G98HardwareStatus(out);status=STATUS_SUCCESS;}
 else if(Counter(&c->State)==G98_OWNER_QUEUED||Counter(&c->State)==G98_OWNER_RUNNING)status=STATUS_DEVICE_BUSY;
 else if(Counter(&c->Inhibit)||!Counter(&c->D0)||!Available(c))status=STATUS_DEVICE_NOT_READY;
 else{
  G98_STREAM_IO stream={c,G98HIDStage,G98HIDPublish,StopRequested,Available,c->CycleLimit,c->Persistent,CycleComplete,EpochComplete};
  if(code==G98_IOCTL_SNAPSHOT)status=G98HardwareSnapshot(out,&stream);
  else{G98HardwarePmic(out,&stream);status=STATUS_SUCCESS;}
 }
 OwnerUnlock(c);if(NT_SUCCESS(status))information=needed;
 done:WdfRequestCompleteWithInformation(request,status,information);
}
NTSTATUS G98HIDD0Entry(WDFDEVICE device,WDF_POWER_DEVICE_STATE previous)
{
 G98HID_CONTEXT*c=G98HIDContext(device);UNREFERENCED_PARAMETER(previous);OwnerLock(c);InterlockedIncrement(&c->Entries);InterlockedExchange(&c->D0,1);if(Available(c))InterlockedExchange(&c->Inhibit,0);OwnerUnlock(c);return STATUS_SUCCESS;
}
NTSTATUS G98HIDD0Exit(WDFDEVICE device,WDF_POWER_DEVICE_STATE target)
{
 G98HID_CONTEXT*c=G98HIDContext(device);NTSTATUS s;UNREFERENCED_PARAMETER(target);OwnerLock(c);InterlockedExchange(&c->Inhibit,1);s=Join(c,G98_STOP_D0_EXIT);if(NT_SUCCESS(s)){InterlockedExchange(&c->D0,0);InterlockedIncrement(&c->Exits);}OwnerUnlock(c);return s;
}
NTSTATUS G98HIDIoInit(WDFDEVICE device)
{
 G98HID_CONTEXT*c=G98HIDContext(device);NTSTATUS status=VhfStart(c->Handle);InterlockedExchange(&c->StartStatus,status);if(!NT_SUCCESS(status))return status;InterlockedExchange(&c->Started,1);OwnerLock(c);status=Start(c,NULL,G98_EPOCH_CYCLES);OwnerUnlock(c);return status;
}
NTSTATUS G98HIDSuspend(WDFDEVICE device)
{
 G98HID_CONTEXT*c=G98HIDContext(device);NTSTATUS s;OwnerLock(c);InterlockedExchange(&c->Inhibit,1);s=Join(c,G98_STOP_SUSPEND);OwnerUnlock(c);return s;
}
NTSTATUS G98HIDRestart(WDFDEVICE device)
{
 G98HID_CONTEXT*c=G98HIDContext(device);NTSTATUS status=STATUS_SUCCESS;ULONG reason;OwnerLock(c);if(Counter(&c->D0)&&Available(c)){InterlockedExchange(&c->Inhibit,0);reason=Counter(&c->StopReason);if(c->Persistent&&Counter(&c->State)==G98_OWNER_DONE&&(reason==G98_STOP_SUSPEND||reason==G98_STOP_D0_EXIT)&&(Counter(&c->Outcome)==G98_OUTCOME_CANCELLED||Counter(&c->Outcome)==G98_OUTCOME_CANCELLED_BEFORE_HARDWARE))status=Start(c,NULL,G98_EPOCH_CYCLES);}OwnerUnlock(c);return status;
}
VOID G98HIDSurprise(WDFDEVICE device)
{
 G98HID_CONTEXT*c=G98HIDContext(device);InterlockedExchange(&c->Removed,1);OwnerLock(c);InterlockedExchange(&c->Inhibit,1);Join(c,G98_STOP_SURPRISE);OwnerUnlock(c);
}
VOID G98HIDCleanup(WDFOBJECT object)
{
 G98HID_CONTEXT*c=G98HIDContext((WDFDEVICE)object);NTSTATUS status;if(!c->ControlInitialized)return;
 OwnerLock(c);InterlockedExchange(&c->Inhibit,1);status=Join(c,G98_STOP_CLEANUP);NT_ASSERT(NT_SUCCESS(status));
 if(NT_SUCCESS(status)){InterlockedExchange(&c->Started,0);if(c->Handle){VhfDelete(c->Handle,TRUE);c->Handle=NULL;}G100KeysFree(&c->Keys);if(c->Result){ExFreePoolWithTag(c->Result,'85GO');c->Result=NULL;}}
 OwnerUnlock(c);
}
VOID G98HIDFileCreate(WDFDEVICE device,WDFREQUEST request,WDFFILEOBJECT file)
{
 PUNICODE_STRING name=WdfFileObjectGetFileName(file);UNREFERENCED_PARAMETER(device);WdfRequestComplete(request,name&&name->Length?STATUS_OBJECT_NAME_INVALID:STATUS_SUCCESS);
}
VOID G98HIDFileCleanup(WDFFILEOBJECT file)
{
 G98HID_CONTEXT*c=G98HIDContext(WdfFileObjectGetDevice(file));OwnerLock(c);if(c->OwnerFile==file)Join(c,G98_STOP_CLOSE);OwnerUnlock(c);
}

/* Diagnostic metadata only: keep the first failed Add proof across reloads.
 * No device access, admission relaxation, retry, task or boot selection here. */
static void AdmissionRecord(WDFDEVICE device,const G98HID_STATUS*identity,int full)
{
 WDFKEY key;UNICODE_STRING name;ULONG proof[12],existing=0;NTSTATUS status;
 if(KeGetCurrentIrql()!=PASSIVE_LEVEL)return;
 status=WdfDeviceOpenRegistryKey(device,PLUGPLAY_REGKEY_DEVICE,KEY_QUERY_VALUE|KEY_SET_VALUE,WDF_NO_OBJECT_ATTRIBUTES,&key);
 if(!NT_SUCCESS(status))return;
 proof[0]=sizeof(proof);proof[1]=2;proof[2]=identity->FirmwareMatch;proof[3]=identity->FirmwareBytes;
 proof[4]=identity->KernelBuild;proof[5]=identity->Processors;proof[6]=identity->Irql;proof[7]=(ULONG)full;
 proof[8]=Counter(&G98FullStage);proof[9]=Counter(&G98FullStatus);proof[10]=Counter(&G98FullType);proof[11]=Counter(&G98FullBytes);
 if(full==0){
  RtlInitUnicodeString(&name,L"G98FirstAdmissionFailure");
  status=WdfRegistryQueryValue(key,&name,0,NULL,&existing,NULL);
  if(status==STATUS_OBJECT_NAME_NOT_FOUND)WdfRegistryAssignValue(key,&name,REG_BINARY,sizeof(proof),proof);
 }
 RtlInitUnicodeString(&name,L"G98LatestAdmission");WdfRegistryAssignValue(key,&name,REG_BINARY,sizeof(proof),proof);
 WdfRegistryClose(key);
}

NTSTATUS G98HIDAdd(WDFDRIVER driver,PWDFDEVICE_INIT init)
{
 WDF_OBJECT_ATTRIBUTES attributes;WDF_PNPPOWER_EVENT_CALLBACKS power;WDF_IO_QUEUE_CONFIG queue;WDF_FILEOBJECT_CONFIG files;
 WDFDEVICE device;G98HID_CONTEXT*c;G98HID_STATUS identity;VHF_CONFIG config;NTSTATUS status;UNREFERENCED_PARAMETER(driver);
 WdfDeviceInitSetDeviceType(init,FILE_DEVICE_UNKNOWN);WdfDeviceInitSetCharacteristics(init,FILE_DEVICE_SECURE_OPEN,TRUE);WdfDeviceInitSetExclusive(init,TRUE);WdfDeviceInitSetIoType(init,WdfDeviceIoBuffered);
 WDF_FILEOBJECT_CONFIG_INIT(&files,G98HIDFileCreate,WDF_NO_EVENT_CALLBACK,G98HIDFileCleanup);WdfDeviceInitSetFileObjectConfig(init,&files,WDF_NO_OBJECT_ATTRIBUTES);
 WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&power);power.EvtDeviceD0Entry=G98HIDD0Entry;power.EvtDeviceD0Exit=G98HIDD0Exit;power.EvtDeviceSelfManagedIoInit=G98HIDIoInit;power.EvtDeviceSelfManagedIoSuspend=G98HIDSuspend;power.EvtDeviceSelfManagedIoRestart=G98HIDRestart;power.EvtDeviceSurpriseRemoval=G98HIDSurprise;WdfDeviceInitSetPnpPowerEventCallbacks(init,&power);
 WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes,G98HID_CONTEXT);attributes.ExecutionLevel=WdfExecutionLevelPassive;attributes.SynchronizationScope=WdfSynchronizationScopeNone;attributes.EvtCleanupCallback=G98HIDCleanup;
 status=WdfDeviceCreate(&init,&attributes,&device);if(!NT_SUCCESS(status))return status;c=G98HIDContext(device);KeInitializeMutex(&c->Control,0);c->ControlInitialized=1;
 c->CreateStatus=c->StartStatus=c->LastSubmit=STATUS_DEVICE_NOT_READY;
 {int admission=Admission(c,&identity);AdmissionRecord(device,&identity,admission);if(!admission)return STATUS_NOT_SUPPORTED;}
 c->Result=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*c->Result),'85GO');if(!c->Result)return STATUS_INSUFFICIENT_RESOURCES;RtlZeroMemory(c->Result,sizeof(*c->Result));
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchSequential);queue.PowerManaged=WdfTrue;queue.EvtIoDeviceControl=G98HIDControl;
 status=WdfIoQueueCreate(device,&queue,WDF_NO_OBJECT_ATTRIBUTES,NULL);if(!NT_SUCCESS(status))return status;
 status=WdfDeviceCreateDeviceInterface(device,&G98HIDInterface,NULL);if(!NT_SUCCESS(status))return status;
 {DECLARE_CONST_UNICODE_STRING(keysName,L"\\DosDevices\\OpenG100Keys");status=WdfDeviceCreateSymbolicLink(device,&keysName);if(!NT_SUCCESS(status))return status;}
 status=G100KeysInitialize(&c->Keys,c,KeysAvailable);if(!NT_SUCCESS(status))return status;
 VHF_CONFIG_INIT(&config,WdfDeviceWdmGetDeviceObject(device),(USHORT)G98HIDDescriptorBytes,G98HIDDescriptor);config.VhfClientContext=c;config.EvtVhfAsyncOperationGetFeature=G98HIDFeature;
 {static WCHAR ids[]=L"OPENLAB\\ONEPLUSOPENTOUCHG98\0";config.HardwareIDs=ids;config.HardwareIDsLength=(USHORT)sizeof(ids);}
 status=VhfCreate(&config,&c->Handle);InterlockedExchange(&c->CreateStatus,status);return status;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING path)
{
 WDF_DRIVER_CONFIG config;NTSTATUS status=AuxKlibInitialize();if(!NT_SUCCESS(status))return status;
 G100BusInitialize();WDF_DRIVER_CONFIG_INIT(&config,G98HIDAdd);return WdfDriverCreate(object,path,WDF_NO_OBJECT_ATTRIBUTES,&config,WDF_NO_HANDLE);
}
