/* Actual WDM START/D0 request -> work item -> pinned system-thread bootstrap.
 * No user register IOCTL, render interface or automatic retry. */
#include "gpu_owner.h"
#include "open_parent_consumer.h"
typedef struct{OGO_CONTEXT*P;}EXT;
typedef struct{OGO_CONTEXT*P;PIRP Irp;PIO_WORKITEM Work;BOOLEAN Start,Bootstrap;DEVICE_POWER_STATE Requested;}JOB;
static volatile LONG Added;static volatile LONG64 Sequence;static BOOLEAN Enabled,CpEnabled,ApertureEnabled;static volatile LONG ApertureConsumed;static OGO_CONTEXT*volatile Retained;
static VOID Lock(OGO_CONTEXT*p){KeWaitForSingleObject(&p->Lock,Executive,KernelMode,FALSE,NULL);}static VOID OwnerUnlock(OGO_CONTEXT*p){KeReleaseMutex(&p->Lock,FALSE);}
static NTSTATUS Finish(OGO_CONTEXT*p,PIRP i,NTSTATUS st){i->IoStatus.Status=st;i->IoStatus.Information=0;IoReleaseRemoveLock(&p->Remove,i);IoCompleteRequest(i,IO_NO_INCREMENT);return st;}
static NTSTATUS Completed(PDEVICE_OBJECT d,PIRP i,PVOID c){UNREFERENCED_PARAMETER(d);if(i->PendingReturned)IoMarkIrpPending(i);IoReleaseRemoveLock(&((OGO_CONTEXT*)c)->Remove,i);return STATUS_CONTINUE_COMPLETION;}
static NTSTATUS ForwardHeld(OGO_CONTEXT*p,PIRP i,BOOLEAN power){IoCopyCurrentIrpStackLocationToNext(i);IoSetCompletionRoutine(i,Completed,p,TRUE,TRUE,TRUE);return power?PoCallDriver(p->Lower,i):IoCallDriver(p->Lower,i);}
static NTSTATUS Forward(PDEVICE_OBJECT d,PIRP i){OGO_CONTEXT*p=((EXT*)d->DeviceExtension)->P;NTSTATUS st=IoAcquireRemoveLock(&p->Remove,i);if(st!=STATUS_SUCCESS){i->IoStatus.Status=st;IoCompleteRequest(i,IO_NO_INCREMENT);return st;}return ForwardHeld(p,i,FALSE);}
static NTSTATUS Denied(PDEVICE_OBJECT d,PIRP i){UNREFERENCED_PARAMETER(d);i->IoStatus.Status=STATUS_INVALID_DEVICE_REQUEST;i->IoStatus.Information=0;IoCompleteRequest(i,IO_NO_INCREMENT);return STATUS_INVALID_DEVICE_REQUEST;}
static NTSTATUS Lower(OGO_CONTEXT*p,PIRP i){return IoForwardIrpSynchronously(p->Lower,i)?i->IoStatus.Status:STATUS_UNSUCCESSFUL;}
static NTSTATUS CheckResources(PCM_RESOURCE_LIST r){
 static const ULONGLONG pa[5]={0x3d00000,0x3d50000,0x3d68000,0x3d9a000,0xb280000};static const ULONG bytes[5]={0x40000,0x10000,0x28000,0x5000,0x10000};ULONG seen=0;
 if(!r||r->Count!=1||r->List[0].PartialResourceList.Count!=5)return STATUS_DEVICE_CONFIGURATION_ERROR;
 for(ULONG i=0;i<5;i++){PCM_PARTIAL_RESOURCE_DESCRIPTOR d=&r->List[0].PartialResourceList.PartialDescriptors[i];if(d->Type!=CmResourceTypeMemory||d->Flags!=CM_RESOURCE_MEMORY_READ_WRITE||(d->ShareDisposition!=CmResourceShareDeviceExclusive&&d->ShareDisposition!=CmResourceShareDriverExclusive))return STATUS_DEVICE_CONFIGURATION_ERROR;ULONG n;for(n=0;n<5;n++)if((ULONGLONG)d->u.Memory.Start.QuadPart==pa[n]&&d->u.Memory.Length==bytes[n])break;if(n==5||(seen&(1u<<n)))return STATUS_DEVICE_CONFIGURATION_ERROR;seen|=1u<<n;}
 return seen==31?STATUS_SUCCESS:STATUS_DEVICE_CONFIGURATION_ERROR;
}
static VOID Revoke(OGO_CONTEXT*p){Lock(p);InterlockedExchange(&p->Revoked,1);InterlockedExchange(&p->Life.Inhibit,1);p->Started=p->D0=FALSE;KeSetEvent(&p->Revoke,IO_NO_INCREMENT,FALSE);OwnerUnlock(p);}
static VOID Join(OGO_CONTEXT*p){KeWaitForSingleObject(&p->OperationDone,Executive,KernelMode,FALSE,NULL);}
static VOID Report(OGO_CONTEXT*p,PCSTR reason){LogPrint("%s run%llx gen%llx phase%u status%08x cleanup%08x input%08x once%ld active%u bank%llu faultToken%u scope%u retained%u GMU%08x nativeReady0 WDDM0\n",reason,p->RunId,p->Generation,p->Phase,p->Status,p->CleanupStatus,p->InputStatus,p->Once,p->Active&&p->Active->State==OAS_ACTIVE,p->Bank.Native.Id,p->Fault!=NULL||(p->Active&&p->Active->Fault!=NULL),p->Hold.ScopeHeld,p->Uncertain,p->GmuStatus);
 /* G731: CGH hold forensics for the phase-8 0x483 — state/error/deferred and the
  * cold() snapshot (reset/hfi/gx/fence) + halt handshake words (before/last/ack). */
 LogPrint("CGH st%u err%u def%u owns%u rst%x hfi%x gx%x fen%x haltB%x haltL%x ack%x tcs%x,%x,%x,%x clockGen%llx hstat%08x clockTok%llu\n",(unsigned)p->Hold.Hold.state,(unsigned)p->Hold.Hold.error,(unsigned)p->Hold.Hold.deferred,(unsigned)p->Hold.Hold.owned,p->Hold.Hold.reset,p->Hold.Hold.hfi,p->Hold.Hold.gx,p->Hold.Hold.fence,p->Hold.Hold.before_halt,p->Hold.Hold.last_halt,p->Hold.Hold.last_ack,p->Hold.Hold.tcs[0],p->Hold.Hold.tcs[1],p->Hold.Hold.tcs[2],p->Hold.Hold.tcs[3],p->Hold.ClockGeneration,p->Hold.Status,p->Hold.Clock.Token);
 LogPrint("G778 CGH reset-authority mode%u sampled%x coldFail%x reads%u writes%u polls%u attempted%u lastBank%u lastOff%x lastVal%x lastIo%d; TCS advisory, unset sampled bits mean NOT READ\n",p->Hold.Hold.reset_mode,p->Hold.Hold.sampled_mask,p->Hold.Hold.cold_fail_mask,p->Hold.Hold.reads,p->Hold.Hold.writes,p->Hold.Hold.polls,p->Hold.Hold.attempted,p->Hold.Hold.last_bank,p->Hold.Hold.last_offset,p->Hold.Hold.last_value,p->Hold.Hold.last_io);
 if(p->Active&&p->Active->Tables){OSMA_SESSION*s=&p->Active->Tables->Session;
  LogPrint("G810 OSMA phase%u status%u reads%u writes%u retain%u nsBefore%08x nsWanted%08x partialAfterNs%08x owner%d\n",(unsigned)s->Phase,(unsigned)s->Status,s->Reads,s->Writes,s->MustRetain,s->Before.Nscr0,s->DesiredNscr0,s->After.Nscr0,s->LastOwnerStatus);
  const ArmSmmu4KContextImage*i=&s->Image,*r=&s->Readback;
  ULONG diff=(i->cbar!=r->cbar?1u:0u)|(i->cba2r!=r->cba2r?2u:0u)|(i->tcr!=r->tcr?4u:0u)|(i->tcr2!=r->tcr2?8u:0u)|(i->mair0!=r->mair0?16u:0u)|(i->mair1!=r->mair1?32u:0u)|(i->ttbr0!=r->ttbr0?64u:0u)|(i->ttbr1!=r->ttbr1?128u:0u);
  LogPrint("G810 partialCB cfgDiffNoSctlr%x tcr2Want%08x tcr2Read%08x tcr2Xor%08x sctlrRaw%08x; diff CBAR,CBA2R,TCR,TCR2,MAIR0,MAIR1,TTBR0,TTBR1 bits0..7; zero fields may be unread on earlier failure\n",diff,i->tcr2,r->tcr2,i->tcr2^r->tcr2,r->sctlr);
 }}
static VOID ThreadMain(PVOID cookie){JOB*j=cookie;OGO_CONTEXT*p=j->P;NTSTATUS st=OgoBootstrap(p);
 Report(p,"bootstrap-result");
 if(st==STATUS_SUCCESS&&p->Active){PIRP irp=j->Irp;j->Irp=NULL;(void)Finish(p,irp,st);
  /* A real same-thread CGH mutex is still held. Keep its owner thread alive;
   * never return a pool worker or fabricate a released physical-stop token. */
  KeWaitForSingleObject(&p->Revoke,Executive,KernelMode,FALSE,NULL);
  (void)CghNativeRetainFailure(&p->Hold,STATUS_DELETE_PENDING);p->Uncertain=TRUE;p->Phase=OGO_RETAINED;
 }
 Lock(p);p->OperationThread=NULL;p->ThreadLive=FALSE;InterlockedExchange(&p->Once,2);KeSetEvent(&p->OperationDone,IO_NO_INCREMENT,FALSE);OwnerUnlock(p);
 if(j->Irp){PIRP irp=j->Irp;j->Irp=NULL;(void)Finish(p,irp,st);}IoReleaseRemoveLock(&p->Remove,j);ExFreePoolWithTag(j,OGO_TAG);PsTerminateSystemThread(STATUS_SUCCESS);
}
static VOID EndJob(JOB*j,NTSTATUS st){OGO_CONTEXT*p=j->P;Lock(p);if(j->Bootstrap){p->ThreadLive=FALSE;InterlockedExchange(&p->Once,2);KeSetEvent(&p->OperationDone,IO_NO_INCREMENT,FALSE);}else p->PowerBusy=FALSE;KeSetEvent(&p->OperationDone,IO_NO_INCREMENT,FALSE);OwnerUnlock(p);Finish(p,j->Irp,st);IoReleaseRemoveLock(&p->Remove,j);ExFreePoolWithTag(j,OGO_TAG);}
static VOID LaunchWorker(PDEVICE_OBJECT d,PVOID cookie){UNREFERENCED_PARAMETER(d);JOB*j=cookie;OGO_CONTEXT*p=j->P;
 if(!j->Start){NTSTATUS st=Lower(p,j->Irp);if(st==STATUS_SUCCESS){Lock(p);if(p->Started&&!p->Removing&&!p->StopPending&&!p->RemovePending&&!InterlockedCompareExchange(&p->Revoked,0,0))p->D0=j->Requested==PowerDeviceD0;else st=STATUS_DELETE_PENDING;OwnerUnlock(p);if(st==STATUS_SUCCESS){POWER_STATE power;power.DeviceState=j->Requested;PoSetPowerState(p->Fdo,DevicePowerState,power);}}
  if(st!=STATUS_SUCCESS||!j->Bootstrap){IoFreeWorkItem(j->Work);j->Work=NULL;EndJob(j,st);return;}}
 /* The new thread may finish and free j before PsCreateSystemThread returns.
  * Retire the work-item object first; success path never dereferences j again. */
 IoFreeWorkItem(j->Work);j->Work=NULL;HANDLE thread=NULL;NTSTATUS st=PsCreateSystemThread(&thread,THREAD_ALL_ACCESS,NULL,NULL,NULL,ThreadMain,j);
 if(st==STATUS_SUCCESS){ZwClose(thread);return;}p->Status=st;EndJob(j,st);
}
static NTSTATUS Queue(OGO_CONTEXT*p,PIRP i,BOOLEAN fromStart,BOOLEAN bootstrap,DEVICE_POWER_STATE requested){
 JOB*j=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*j),OGO_TAG);if(!j)return Finish(p,i,STATUS_INSUFFICIENT_RESOURCES);RtlZeroMemory(j,sizeof(*j));j->P=p;j->Irp=i;j->Start=fromStart;j->Bootstrap=bootstrap;j->Requested=requested;j->Work=IoAllocateWorkItem(p->Fdo);if(!j->Work){ExFreePoolWithTag(j,OGO_TAG);return Finish(p,i,STATUS_INSUFFICIENT_RESOURCES);}NTSTATUS st=IoAcquireRemoveLock(&p->Remove,j);if(st!=STATUS_SUCCESS){IoFreeWorkItem(j->Work);ExFreePoolWithTag(j,OGO_TAG);return Finish(p,i,st);}
 Lock(p);if(p->Removing||p->StopPending||p->RemovePending||p->ThreadLive||p->PowerBusy||InterlockedCompareExchange(&p->Revoked,0,0)||(bootstrap&&InterlockedCompareExchange(&p->Once,1,0)!=0)){OwnerUnlock(p);IoReleaseRemoveLock(&p->Remove,j);IoFreeWorkItem(j->Work);ExFreePoolWithTag(j,OGO_TAG);return Finish(p,i,STATUS_DEVICE_BUSY);}KeClearEvent(&p->OperationDone);if(bootstrap)p->ThreadLive=TRUE;else p->PowerBusy=TRUE;OwnerUnlock(p);
 IoMarkIrpPending(i);IoQueueWorkItem(j->Work,LaunchWorker,DelayedWorkQueue,j);return STATUS_PENDING;
}
static NTSTATUS Query(OGO_CONTEXT*p,PIRP i,BOOLEAN stop){Lock(p);NTSTATUS st=OgoSafe(p)&&(!stop||!p->Once)&&!p->Removing&&!p->StopPending&&!p->RemovePending?STATUS_SUCCESS:STATUS_DEVICE_BUSY;if(st==STATUS_SUCCESS){if(stop)p->StopPending=TRUE;else p->RemovePending=TRUE;}OwnerUnlock(p);if(st!=STATUS_SUCCESS)return Finish(p,i,st);st=Lower(p,i);if(st!=STATUS_SUCCESS){Lock(p);if(stop)p->StopPending=FALSE;else p->RemovePending=FALSE;OwnerUnlock(p);}return Finish(p,i,st);}
static NTSTATUS Pnp(PDEVICE_OBJECT d,PIRP i){OGO_CONTEXT*p=((EXT*)d->DeviceExtension)->P;PIO_STACK_LOCATION sp=IoGetCurrentIrpStackLocation(i);NTSTATUS st=IoAcquireRemoveLock(&p->Remove,i);if(st!=STATUS_SUCCESS){i->IoStatus.Status=st;IoCompleteRequest(i,IO_NO_INCREMENT);return st;}
 switch(sp->MinorFunction){
 case IRP_MN_START_DEVICE:
  Lock(p);BOOLEAN allow=!p->Started&&!p->Removing&&!p->StopPending&&!p->RemovePending&&!p->Resources&&!p->Once;OwnerUnlock(p);if(!allow)return Finish(p,i,STATUS_DEVICE_BUSY);
  st=Lower(p,i);if(st!=STATUS_SUCCESS)return Finish(p,i,st);st=CheckResources(sp->Parameters.StartDevice.AllocatedResources);if(st==STATUS_SUCCESS)st=CheckResources(sp->Parameters.StartDevice.AllocatedResourcesTranslated);if(st!=STATUS_SUCCESS)return Finish(p,i,st);
  p->ResourceBytes=FIELD_OFFSET(CM_RESOURCE_LIST,List[0].PartialResourceList.PartialDescriptors)+5*sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR);p->Resources=ExAllocatePool2(POOL_FLAG_NON_PAGED,p->ResourceBytes,OGO_TAG);if(!p->Resources)return Finish(p,i,STATUS_INSUFFICIENT_RESOURCES);RtlCopyMemory(p->Resources,sp->Parameters.StartDevice.AllocatedResourcesTranslated,p->ResourceBytes);
  Lock(p);p->Started=p->D0=TRUE;p->Generation=(ULONGLONG)InterlockedIncrement64(&Sequence);p->RunId=KeQueryInterruptTime();p->Phase=OGO_LOWER_STARTED;InterlockedExchange(&p->Revoked,0);KeClearEvent(&p->Revoke);OwnerUnlock(p);POWER_STATE power;power.DeviceState=PowerDeviceD0;PoSetPowerState(d,DevicePowerState,power);
  LogPrint("BEGIN run%llx OPEN0515 actual lowerSTART/resources; explicit BootstrapOnce%u; no render interface\n",p->RunId,p->Enabled);if(p->Enabled)return Queue(p,i,TRUE,TRUE,PowerDeviceD0);p->Status=STATUS_NOT_SUPPORTED;Report(p,"bootstrap-disabled");return Finish(p,i,STATUS_SUCCESS);
 case IRP_MN_QUERY_STOP_DEVICE:return Query(p,i,TRUE);
 case IRP_MN_QUERY_REMOVE_DEVICE:return Query(p,i,FALSE);
 case IRP_MN_CANCEL_STOP_DEVICE:Lock(p);p->StopPending=FALSE;OwnerUnlock(p);break;
 case IRP_MN_CANCEL_REMOVE_DEVICE:Lock(p);p->RemovePending=FALSE;OwnerUnlock(p);break;
 case IRP_MN_STOP_DEVICE:Revoke(p);Join(p);Lock(p);if(!p->Once&&OgoSafe(p)){if(p->Resources)ExFreePoolWithTag(p->Resources,OGO_TAG);p->Resources=NULL;p->ResourceBytes=0;p->StopPending=FALSE;}OwnerUnlock(p);i->IoStatus.Status=STATUS_SUCCESS;return ForwardHeld(p,i,FALSE);
 case IRP_MN_SURPRISE_REMOVAL:Revoke(p);Join(p);Lock(p);p->Removing=TRUE;OwnerUnlock(p);return ForwardHeld(p,i,FALSE);
 case IRP_MN_REMOVE_DEVICE:
  Revoke(p);IoReleaseRemoveLockAndWait(&p->Remove,i);Join(p);Lock(p);p->Removing=TRUE;BOOLEAN safe=OgoSafe(p);OwnerUnlock(p);Report(p,"REMOVE");IoSkipCurrentIrpStackLocation(i);st=IoCallDriver(p->Lower,i);IoDetachDevice(p->Lower);p->Lower=NULL;
  if(safe){if(p->Resources)ExFreePoolWithTag(p->Resources,OGO_TAG);ObDereferenceObject(p->Pdo);ExFreePoolWithTag(p,OGO_TAG);}else Retained=p;IoDeleteDevice(d);return st;
 default:break;
 }return ForwardHeld(p,i,FALSE);
}
static NTSTATUS Power(PDEVICE_OBJECT d,PIRP i){OGO_CONTEXT*p=((EXT*)d->DeviceExtension)->P;PIO_STACK_LOCATION sp=IoGetCurrentIrpStackLocation(i);NTSTATUS st=IoAcquireRemoveLock(&p->Remove,i);if(st!=STATUS_SUCCESS){i->IoStatus.Status=st;IoCompleteRequest(i,IO_NO_INCREMENT);return st;}
 if(KeGetCurrentIrql()!=PASSIVE_LEVEL)return Finish(p,i,STATUS_INVALID_DEVICE_STATE);
 if(sp->Parameters.Power.Type==SystemPowerState&&(sp->MinorFunction==IRP_MN_QUERY_POWER||sp->MinorFunction==IRP_MN_SET_POWER)&&sp->Parameters.Power.State.SystemState>PowerSystemWorking){if(sp->MinorFunction==IRP_MN_QUERY_POWER)return Finish(p,i,STATUS_NOT_SUPPORTED);else{Revoke(p);Join(p);}return ForwardHeld(p,i,TRUE);}
 if(sp->Parameters.Power.Type!=DevicePowerState||sp->MinorFunction!=IRP_MN_SET_POWER)return ForwardHeld(p,i,TRUE);
 DEVICE_POWER_STATE state=sp->Parameters.Power.State.DeviceState;Lock(p);BOOLEAN valid=p->Started&&!p->Removing&&!p->StopPending&&!p->RemovePending;BOOLEAN safe=OgoSafe(p);BOOLEAN d0=p->D0;OwnerUnlock(p);if(!valid)return Finish(p,i,STATUS_INVALID_DEVICE_STATE);
 if(state==PowerDeviceD0){if(d0)return ForwardHeld(p,i,TRUE);return Queue(p,i,FALSE,p->Enabled&&!p->Once,PowerDeviceD0);}
 if(state!=PowerDeviceD3||!safe)return Finish(p,i,STATUS_DEVICE_BUSY);
 return Queue(p,i,FALSE,FALSE,PowerDeviceD3);
}
static NTSTATUS Add(PDRIVER_OBJECT driver,PDEVICE_OBJECT pdo){if(!OpenExactHardwareId(pdo,L"ACPI\\OPEN0515")||InterlockedCompareExchange(&Added,1,0))return STATUS_DEVICE_CONFIGURATION_ERROR;PDEVICE_OBJECT fdo;NTSTATUS st=IoCreateDevice(driver,sizeof(EXT),NULL,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,FALSE,&fdo);if(st!=STATUS_SUCCESS)return st;OGO_CONTEXT*p=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*p),OGO_TAG);if(!p){IoDeleteDevice(fdo);return STATUS_INSUFFICIENT_RESOURCES;}RtlZeroMemory(p,sizeof(*p));p->Pdo=pdo;p->Fdo=fdo;ObReferenceObject(pdo);p->Enabled=Enabled;p->CpInit=CpEnabled;p->CpDdrType=0;p->InputStatus=p->Status=p->CleanupStatus=STATUS_DEVICE_NOT_READY;p->GmuStatus=STATUS_NOT_SUPPORTED;KeInitializeMutex(&p->Lock,0);KeInitializeMutex(&p->RamLock,0);KeInitializeEvent(&p->Revoke,NotificationEvent,FALSE);KeInitializeEvent(&p->OperationDone,NotificationEvent,TRUE);IoInitializeRemoveLock(&p->Remove,OGO_TAG,0,0);((EXT*)fdo->DeviceExtension)->P=p;p->Lower=IoAttachDeviceToDeviceStack(fdo,pdo);if(!p->Lower){ObDereferenceObject(pdo);ExFreePoolWithTag(p,OGO_TAG);IoDeleteDevice(fdo);return STATUS_NO_SUCH_DEVICE;}fdo->Flags|=DO_POWER_PAGABLE;fdo->Flags&=~DO_DEVICE_INITIALIZING;return STATUS_SUCCESS;}
static NTSTATUS ReadOption(HANDLE key,PCWSTR option,PULONG out){UNICODE_STRING name;RtlInitUnicodeString(&name,option);UCHAR buffer[FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION,Data)+sizeof(ULONG)];ULONG bytes=0;NTSTATUS st=ZwQueryValueKey(key,&name,KeyValuePartialInformation,buffer,sizeof(buffer),&bytes);if(st==STATUS_OBJECT_NAME_NOT_FOUND){*out=0;return STATUS_SUCCESS;}if(st!=STATUS_SUCCESS)return st;PKEY_VALUE_PARTIAL_INFORMATION v=(PKEY_VALUE_PARTIAL_INFORMATION)buffer;if(v->Type!=REG_DWORD||v->DataLength!=sizeof(ULONG)||bytes!=sizeof(buffer))return STATUS_DEVICE_CONFIGURATION_ERROR;RtlCopyMemory(out,v->Data,sizeof(*out));return STATUS_SUCCESS;}
BOOLEAN OgoCpRequested(VOID){return CpEnabled;}
BOOLEAN OgoApertureRequested(VOID){return ApertureEnabled;}
BOOLEAN OgoConsumeAperture(VOID){return ApertureEnabled&&InterlockedCompareExchange(&ApertureConsumed,1,0)==0;}
static NTSTATUS ReadEnable(PUNICODE_STRING path){OBJECT_ATTRIBUTES oa;HANDLE key=NULL;InitializeObjectAttributes(&oa,path,OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,NULL,NULL);NTSTATUS st=ZwOpenKey(&key,KEY_QUERY_VALUE,&oa);if(st!=STATUS_SUCCESS)return st;ULONG boot=0,cp=0,aperture=0;st=ReadOption(key,L"BootstrapOnce",&boot);if(st==STATUS_SUCCESS)st=ReadOption(key,L"CpInitFenceOnce",&cp);if(st==STATUS_SUCCESS)st=ReadOption(key,L"ScmApertureOnce",&aperture);ZwClose(key);if(st!=STATUS_SUCCESS)return st;if(boot>1||cp>1||aperture>1||(cp&&!boot)||(aperture&&(!boot||!cp)))return STATUS_DEVICE_CONFIGURATION_ERROR;Enabled=(BOOLEAN)boot;CpEnabled=(BOOLEAN)cp;ApertureEnabled=(BOOLEAN)aperture;return STATUS_SUCCESS;}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver,PUNICODE_STRING path){NTSTATUS st=ReadEnable(path);if(st!=STATUS_SUCCESS)return st;LogOpen();LogPrint("OpenGpuStart explicit once bootstrap enabled%u; no graphics/READY claims\n",Enabled);for(ULONG n=0;n<=IRP_MJ_MAXIMUM_FUNCTION;n++)driver->MajorFunction[n]=Forward;driver->MajorFunction[IRP_MJ_PNP]=Pnp;driver->MajorFunction[IRP_MJ_POWER]=Power;driver->MajorFunction[IRP_MJ_DEVICE_CONTROL]=Denied;driver->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL]=Denied;driver->DriverExtension->AddDevice=Add;driver->DriverUnload=NULL;return STATUS_SUCCESS;}
