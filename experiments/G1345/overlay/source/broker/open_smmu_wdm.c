/* SPDX-License-Identifier: MIT -- genuine ACPI OPEN0D01 power-only FDO.
 * Source-only initial S0 profile. No translation DDI/interface, IOCTL, interrupt,
 * DMA, domain/stream/CB/TLB programming, rail/reset or firmware execution.
 */
#include <ntifs.h>
#include "open_smmu_d0.h"
#include "open_parent_consumer.h"
#include "open_clock_interface.h"
#include "../gmu_clock.h"
#include "../gmu_clock_interface.h"
#include "../local_bank_interface.h"
#include "../gpu_user_bank.h"
#include "../fault_owner.h"
#include "../open_smmu_activate_wdm.h"
typedef struct {ULONGLONG Id;OPEN_CLOCK_CLIENT Client;} OSM_CLIENT_SLOT;
#define TAG 'DmSO'
#if OPEN_QTB_WITNESS
#define QTB_EXTRA 1u
#else
#define QTB_EXTRA 0u
#endif
typedef struct OSM_CONTEXT {
 PDEVICE_OBJECT Pdo,Lower,Fdo;IO_REMOVE_LOCK Remove;KMUTEX Lock;
 PKTHREAD LockThread;BOOLEAN Started,Removing,D0Ref,Faulted,StopPending,RemovePending;
 ULONG64 Generation;ULONG Clients;struct osm_lease Lease;
 BOOLEAN Granted[OSM_MAPS];PVOID Map[OSM_MAPS];
#if OPEN_QTB_WITNESS
 BOOLEAN QtbGranted;PVOID QtbMap,Qtb;CM_PARTIAL_RESOURCE_DESCRIPTOR QtbGrant;
#endif
 OSMA_NATIVE_IO*RunNative;OLB_NATIVE*RunBank;PVOID RunTag;
 OLB_OWNER Banks;ULONG BankClaims;OF_OWNER Fault;
 OGU_BANK GpuUser;OGU_TOKEN*GpuUserTag;OLB_NATIVE*GpuUserGmu;BOOLEAN GpuCandidateRead;OSMI_TABLES*GpuTables;
 KMUTEX NsMutex;PETHREAD NsThread;PVOID NsTag,NsFault;OLB_NATIVE*NsBank;ULONGLONG NsToken,NsSequence,NsGeneration;volatile LONG NsRevoked;CM_PARTIAL_RESOURCE_DESCRIPTOR NsGrant;
 GMC_LEASE Gmu;OSM_CLIENT_SLOT GmuSlots[8];ULONG GmuClients;
 ULONG Reads,WritesAttempted;ULONGLONG LastWritePa;ULONG LastWriteBefore,LastWriteValue;
 NTSTATUS LastStatus;ULONGLONG LastReadPa;ULONG LastReadWord;
 UNICODE_STRING Link;NTSTATUS LinkStatus;
 OPEN_PARENT_BINDING Parent;volatile LONG InterfaceRefs,OpenFiles;ULONGLONG TokenSequence;OSM_CLIENT_SLOT Slots[8];
} OSM_CONTEXT;
typedef struct{OSM_CONTEXT*P;}OSM_EXTENSION;
typedef struct{PIO_WORKITEM Work;OSM_CONTEXT*P;PIRP Irp;}OSM_POWER_WORK;
static volatile LONG Added;
static volatile LONG64 Sequence;
static OSM_CONTEXT * volatile Retained;
static const BOOLEAN GrantWritable[OSM_MAPS]={TRUE,TRUE,TRUE,TRUE,FALSE,FALSE};
static VOID BrokerLock(OSM_CONTEXT*p){KeWaitForSingleObject(&p->Lock,Executive,KernelMode,FALSE,NULL);p->LockThread=KeGetCurrentThread();}
static VOID BrokerUnlock(OSM_CONTEXT*p){p->LockThread=NULL;KeReleaseMutex(&p->Lock,FALSE);}
static int Frame(OSM_CONTEXT*p,uint64_t g){return KeGetCurrentIrql()==PASSIVE_LEVEL&&p->LockThread==KeGetCurrentThread()&&p->Started&&!p->Removing&&!p->Faulted&&p->Generation==g?0:-1;}
static int Own(void*c,uint64_t g){return Frame(c,g);}
static int Grant(void*c,uint64_t g,const struct osm_range*r){OSM_CONTEXT*p=c;if(Frame(p,g))return -1;for(unsigned i=0;i<OSM_MAPS;i++)if(r->pa==osm_required_ranges[i].pa&&r->bytes==osm_required_ranges[i].bytes&&r->writable==osm_required_ranges[i].writable)return p->Granted[i]?0:-1;return -1;}
static int Map(void*c,const struct osm_range*r,uintptr_t*out){OSM_CONTEXT*p=c;PHYSICAL_ADDRESS pa;*out=0;if(Frame(p,p->Generation))return -1;
 for(unsigned i=0;i<OSM_MAPS;i++)if(r==&osm_required_ranges[i]){if(!p->Granted[i]||p->Map[i])return -1;pa.QuadPart=(LONGLONG)r->pa;p->Map[i]=MmMapIoSpaceEx(pa,r->bytes,PAGE_NOCACHE|(r->writable?PAGE_READWRITE:PAGE_READONLY));if(!p->Map[i])return -1;*out=(uintptr_t)p->Map[i];return 0;}return -1;}
static VOID Unmap(void*c,uintptr_t t,uint32_t bytes){OSM_CONTEXT*p=c;
 for(unsigned i=0;i<OSM_MAPS;i++)if(p->Map[i]==(PVOID)t&&bytes==osm_required_ranges[i].bytes){MmUnmapIoSpace(p->Map[i],bytes);p->Map[i]=NULL;return;}
 p->Faulted=TRUE; /* Never treat an unknown/unreleased VA as cleaned up. */
}
static int Locate(OSM_CONTEXT*p,uintptr_t token,uint32_t off,unsigned*index,ULONGLONG*pa){
 if(Frame(p,p->Generation)||off&3)return -1;
 for(unsigned i=0;i<OSM_MAPS;i++)if(p->Map[i]==(PVOID)token&&p->Map[i]&&off<=osm_required_ranges[i].bytes-4){*index=i;*pa=osm_required_ranges[i].pa+off;return 0;}return -1;
}
static BOOLEAN ReadAllowed(ULONGLONG a){
 static const ULONGLONG Allowed[]={0x03da0020,0x03d97000,0x03d99108,0x03d9953c,0x03d99104,0x03d993ec,0x03d993f0,0x03d9911c,0x00171004,0x00171000,0x00171010,0x00171018,0x00100000,0x00100004,0x00100010,0x00100014,0x00100018};
 for(unsigned i=0;i<RTL_NUMBER_OF(Allowed);i++)if(a==Allowed[i])return TRUE;return FALSE;
}
static int Read(void*c,uintptr_t t,uint32_t off,uint32_t*v){OSM_CONTEXT*p=c;unsigned i;ULONGLONG a;if(!v||Locate(p,t,off,&i,&a)||!ReadAllowed(a))return -1;
 if(a==0x03da0020&&(p->Lease.state!=OSM_ACTIVE||p->Lease.refs!=1))return -1;
 *v=READ_REGISTER_ULONG((PULONG)((PUCHAR)p->Map[i]+off));p->LastReadPa=a;p->LastReadWord=*v;p->Reads++;return *v==MAXULONG?-1:0;
}
static int Write(void*c,uintptr_t t,uint32_t off,uint32_t value){OSM_CONTEXT*p=c;unsigned i;ULONGLONG a;ULONG current,desired;
 if(Locate(p,t,off,&i,&a)||!osm_required_ranges[i].writable||
    (a!=0x03d97000&&a!=0x00171010&&a!=0x00171018&&a!=0x03d9911c))return -1;
 /* The driver owns/serializes these control words. Recheck immediately at
  * the native boundary; preserve every current bit except owned enable0. */
 current=READ_REGISTER_ULONG((PULONG)((PUCHAR)p->Map[i]+off));
 if(current==MAXULONG||((current^value)&0x0ffffffeu)||((current^value)&1u)==0){DbgPrintEx(DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL,"OpenSmmuD0 native-write-rejected PA%llx current%08x requested%08x; no-store\n",a,current,value);return -1;}
 desired=(current&~1u)|(value&1u);p->LastWritePa=a;p->LastWriteBefore=current;p->LastWriteValue=desired;p->WritesAttempted++;
 WRITE_REGISTER_ULONG((PULONG)((PUCHAR)p->Map[i]+off),desired);return 0;
}
static VOID Barrier(void*c){UNREFERENCED_PARAMETER(c);KeMemoryBarrier();}
static VOID Delay(void*c,uint32_t us){OSM_CONTEXT*p=c;if(us>10){p->Faulted=TRUE;return;}KeStallExecutionProcessor(us);}
static int Drained(void*c,uint64_t g){OSM_CONTEXT*p=c;
 /* This initial adapter exposes NO translation or DMA path. Clients is never
  * handed out/incremented by any interface. Later integration must replace
  * this with actual GPU/GMU stop and bounded translation-drain ownership. */
 return Frame(p,g)||p->Clients? -1:0;
}
static int ParentVotes(void*c,uint32_t*external,uint32_t*ap){OSM_CONTEXT*p=c;ULONG e,a;if(Frame(p,p->Generation)||OpenParentRead(&p->Parent,&e,&a)!=STATUS_SUCCESS)return -1;*external=e;*ap=a;return 0;}
static struct osm_ops Ops(OSM_CONTEXT*p){struct osm_ops o={p,Own,Grant,Map,Unmap,Read,Write,Barrier,Delay,Drained,ParentVotes};return o;}
static NTSTATUS CoreStatus(int e){switch(e){case OSM_OK:return STATUS_SUCCESS;case OSM_BUSY:return STATUS_DEVICE_BUSY;case OSM_OWNER:return STATUS_INVALID_DEVICE_STATE;case OSM_POWER_OFF:return STATUS_DEVICE_POWER_FAILURE;case OSM_TIMEOUT:return STATUS_IO_TIMEOUT;default:return STATUS_DEVICE_HARDWARE_ERROR;}}
static VOID Report(OSM_CONTEXT*p,PCSTR where){DbgPrintEx(DPFLTR_IHVDRIVER_ID,(p->LastStatus==STATUS_SUCCESS?DPFLTR_INFO_LEVEL:DPFLTR_ERROR_LEVEL),"OpenSmmuD0 %s generation%llx started%u D0%u state%u core%d refs%u ownmask%x mapped%u nativewrites%u last%llx %08x->%08x CX%08x HW%08x root%08x cfg%08x status%08x rawAHB%08x delayRequest%x bit0Confirmed%x rejectReason%u lastRead%llx=%08x; request-only/no physical-stop/no translation\n",where,p->Generation,p->Started,p->D0Ref,p->Lease.state,p->Lease.error,p->Lease.refs,p->Lease.owned_mask,p->Lease.mapped,p->WritesAttempted,p->LastWritePa,p->LastWriteBefore,p->LastWriteValue,p->Lease.last_cx,p->Lease.last_hw,p->Lease.last_root,p->Lease.last_cfg,p->LastStatus,p->Lease.last_branch[3],p->Lease.delay_request_mask,p->Lease.bit0_confirmed_mask,p->Lease.reject_reason,p->LastReadPa,p->LastReadWord);}
static BOOLEAN HardwareSafe(OSM_CONTEXT*p){
#if OPEN_QTB_WITNESS
 if(p->QtbMap||p->Qtb)return FALSE;
#endif
if(p->NsThread||p->NsToken||p->GpuUser.Id||p->GpuUserTag)return FALSE;if(p->Fault.Map[0]||p->Fault.Map[1]||p->Fault.Map[2]||p->Fault.Interrupt[0]||p->Fault.Interrupt[1]||p->Fault.Interrupt[2]||p->Fault.Retain)return FALSE;if(p->BankClaims)return FALSE;if(p->Gmu.state==GMC_HELD||p->Gmu.state==GMC_MUTATING||p->Gmu.refs||p->Gmu.owned_mask||p->Gmu.root_owned||p->Gmu.state==GMC_POISONED||p->GmuClients)return FALSE;if(p->Lease.state==OSM_POISONED||p->Lease.refs||p->Lease.owned_mask||p->Lease.mapped||p->Faulted||(p->Parent.File&&!p->Parent.Bound))return FALSE;for(unsigned i=0;i<OSM_MAPS;i++)if(p->Map[i])return FALSE;return TRUE;}
static BOOLEAN Safe(OSM_CONTEXT*p){return HardwareSafe(p)&&!p->InterfaceRefs&&!p->OpenFiles;}
static NTSTATUS EnterD0(OSM_CONTEXT*p){int e;struct osm_ops o=Ops(p);
 if(!p->Parent.Bound){NTSTATUS ps=OpenParentBind(&p->Parent);if(ps!=STATUS_SUCCESS)return p->LastStatus=ps;}
 if(p->D0Ref)e=osm_witness(&p->Lease,p->Generation);
 else if(p->Lease.state==OSM_NEW)e=osm_acquire(&p->Lease,&o,p->Generation);
 else if(p->Lease.state==OSM_RELEASED&&HardwareSafe(p)&&!p->Clients){
  /* A fully verified old generation may begin a new requested D0 lease.
   * Poisoned/failed/partial generations are NEVER reset or retried. */
  RtlZeroMemory(&p->Lease,sizeof(p->Lease));p->Generation=(ULONG64)InterlockedIncrement64(&Sequence);
  e=osm_acquire(&p->Lease,&o,p->Generation);
 }
 else return p->LastStatus=STATUS_DEVICE_NOT_READY; /* No failed/poison reset. */
 p->LastStatus=CoreStatus(e);if(!e){p->D0Ref=TRUE;p->LinkStatus=IoSetDeviceInterfaceState(&p->Link,TRUE);if(p->LinkStatus!=STATUS_SUCCESS)p->LastStatus=p->LinkStatus;}Report(p,"D0entry");return p->LastStatus;
}
static NTSTATUS ExitD0(OSM_CONTEXT*p){int e;
 if(p->Clients)return p->LastStatus=STATUS_DEVICE_BUSY;
 if(!p->D0Ref){p->LastStatus=HardwareSafe(p)?STATUS_SUCCESS:STATUS_DEVICE_BUSY;if(p->LastStatus==STATUS_SUCCESS)OpenParentUnbind(&p->Parent);return p->LastStatus;}
 e=osm_release(&p->Lease,p->Generation);p->LastStatus=CoreStatus(e);
 if(!e&&!p->Faulted){p->D0Ref=FALSE;OpenParentUnbind(&p->Parent);p->LinkStatus=IoSetDeviceInterfaceState(&p->Link,FALSE);}else if(p->Faulted)p->LastStatus=STATUS_DEVICE_HARDWARE_ERROR;
 Report(p,"D0exit");return p->LastStatus;
}
static NTSTATUS ValidateResources(OSM_CONTEXT*p,PCM_RESOURCE_LIST r){ULONG seen=0;
 if(!r||r->Count!=1||r->List[0].PartialResourceList.Count!=OSM_MAPS+3+QTB_EXTRA)return STATUS_DEVICE_CONFIGURATION_ERROR;
 for(ULONG j=0;j<OSM_MAPS;j++){
  PCM_PARTIAL_RESOURCE_DESCRIPTOR d=&r->List[0].PartialResourceList.PartialDescriptors[j];unsigned found=OSM_MAPS;
  if(d->Type!=CmResourceTypeMemory)return STATUS_DEVICE_CONFIGURATION_ERROR;
  for(unsigned i=0;i<OSM_MAPS;i++)if((ULONGLONG)d->u.Memory.Start.QuadPart==osm_required_ranges[i].pa&&d->u.Memory.Length==osm_required_ranges[i].bytes)found=i;
  if(found==OSM_MAPS||(seen&(1u<<found)))return STATUS_DEVICE_CONFIGURATION_ERROR;
  USHORT expected=GrantWritable[found]?CM_RESOURCE_MEMORY_READ_WRITE:CM_RESOURCE_MEMORY_READ_ONLY;
  if(d->Flags!=expected)return STATUS_DEVICE_CONFIGURATION_ERROR;
  if(GrantWritable[found]&&d->ShareDisposition!=CmResourceShareDeviceExclusive&&d->ShareDisposition!=CmResourceShareDriverExclusive)return STATUS_DEVICE_CONFIGURATION_ERROR;
  if(found==0)p->NsGrant=*d;seen|=1u<<found;
 }
#if OPEN_QTB_WITNESS
 PCM_PARTIAL_RESOURCE_DESCRIPTOR q=&r->List[0].PartialResourceList.PartialDescriptors[OSM_MAPS];
 if(q->Type!=CmResourceTypeMemory||q->u.Memory.Start.QuadPart!=0x03de8000||q->u.Memory.Length!=0x1000||q->Flags!=CM_RESOURCE_MEMORY_READ_WRITE||(q->ShareDisposition!=CmResourceShareDeviceExclusive&&q->ShareDisposition!=CmResourceShareDriverExclusive))return STATUS_DEVICE_CONFIGURATION_ERROR;
 p->QtbGrant=*q;p->QtbGranted=TRUE;
#endif
 if(seen!=(1u<<OSM_MAPS)-1u)return STATUS_DEVICE_CONFIGURATION_ERROR;
 for(unsigned i=0;i<OSM_MAPS;i++)p->Granted[i]=TRUE;return STATUS_SUCCESS;
}
static NTSTATUS Finish(OSM_CONTEXT*p,PIRP irp,NTSTATUS st){irp->IoStatus.Status=st;irp->IoStatus.Information=0;IoReleaseRemoveLock(&p->Remove,irp);IoCompleteRequest(irp,IO_NO_INCREMENT);return st;}
static NTSTATUS Completion(PDEVICE_OBJECT d,PIRP irp,PVOID cookie){OSM_CONTEXT*p=cookie;UNREFERENCED_PARAMETER(d);if(irp->PendingReturned)IoMarkIrpPending(irp);IoReleaseRemoveLock(&p->Remove,irp);return STATUS_CONTINUE_COMPLETION;}
static NTSTATUS ForwardHeld(OSM_CONTEXT*p,PIRP irp,BOOLEAN power){IoCopyCurrentIrpStackLocationToNext(irp);IoSetCompletionRoutine(irp,Completion,p,TRUE,TRUE,TRUE);return power?PoCallDriver(p->Lower,irp):IoCallDriver(p->Lower,irp);}
static NTSTATUS Forward(PDEVICE_OBJECT d,PIRP irp){OSM_CONTEXT*p=((OSM_EXTENSION*)d->DeviceExtension)->P;NTSTATUS st=IoAcquireRemoveLock(&p->Remove,irp);if(st!=STATUS_SUCCESS){irp->IoStatus.Status=st;IoCompleteRequest(irp,IO_NO_INCREMENT);return st;}return ForwardHeld(p,irp,FALSE);}
static NTSTATUS FileIrp(PDEVICE_OBJECT d,PIRP irp){
 OSM_CONTEXT*p=((OSM_EXTENSION*)d->DeviceExtension)->P;PIO_STACK_LOCATION sp=IoGetCurrentIrpStackLocation(irp);
 NTSTATUS st;
 if(sp->MajorFunction==IRP_MJ_CLOSE){
  if(!sp->FileObject||sp->FileObject->FsContext!=p){irp->IoStatus.Status=STATUS_SUCCESS;IoCompleteRequest(irp,IO_NO_INCREMENT);return STATUS_SUCCESS;}
  st=IoAcquireRemoveLock(&p->Remove,irp);sp->FileObject->FsContext=NULL;
  irp->IoStatus.Status=STATUS_SUCCESS;irp->IoStatus.Information=0;
  /* An open file retains this context through REMOVE. Once decremented do
   * not access p unless the remove lock was acquired. */
  (void)InterlockedDecrement(&p->OpenFiles);
  if(st==STATUS_SUCCESS)IoReleaseRemoveLock(&p->Remove,irp);IoCompleteRequest(irp,IO_NO_INCREMENT);return STATUS_SUCCESS;
 }
 st=IoAcquireRemoveLock(&p->Remove,irp);
 if(st!=STATUS_SUCCESS){irp->IoStatus.Status=st;IoCompleteRequest(irp,IO_NO_INCREMENT);return st;}
 if(sp->MajorFunction==IRP_MJ_CREATE){
  if(KeGetCurrentIrql()!=PASSIVE_LEVEL)return Finish(p,irp,STATUS_INVALID_DEVICE_STATE);
  BrokerLock(p);st=(!p->Removing&&p->Started&&p->D0Ref&&!p->StopPending&&!p->RemovePending)?STATUS_SUCCESS:STATUS_DEVICE_NOT_READY;
  if(!sp->FileObject||sp->FileObject->FileName.Length||sp->FileObject->FsContext)st=STATUS_OBJECT_NAME_INVALID;
  if(st==STATUS_SUCCESS){if(p->OpenFiles==MAXLONG)st=STATUS_INSUFFICIENT_RESOURCES;else{sp->FileObject->FsContext=p;InterlockedIncrement(&p->OpenFiles);}}BrokerUnlock(p);
 }else st=STATUS_SUCCESS;
 return Finish(p,irp,st);
}
static NTSTATUS LowerSync(OSM_CONTEXT*p,PIRP irp){return IoForwardIrpSynchronously(p->Lower,irp)?irp->IoStatus.Status:STATUS_UNSUCCESSFUL;}
static VOID PowerWorker(PDEVICE_OBJECT device,PVOID context){OSM_POWER_WORK*w=context;OSM_CONTEXT*p=w->P;PIRP irp=w->Irp;PIO_STACK_LOCATION sp=IoGetCurrentIrpStackLocation(irp);NTSTATUS st=STATUS_INVALID_DEVICE_STATE;DEVICE_POWER_STATE requested=sp->Parameters.Power.State.DeviceState;UNREFERENCED_PARAMETER(device);
 BrokerLock(p);
 if(p->Started&&!p->Removing&&!p->StopPending&&!p->RemovePending&&(requested==PowerDeviceD0||requested==PowerDeviceD3)){
  if(requested==PowerDeviceD0){st=LowerSync(p,irp);if(st==STATUS_SUCCESS)st=EnterD0(p);}
  else{st=ExitD0(p);if(st==STATUS_SUCCESS)st=LowerSync(p,irp);}
  if(st==STATUS_SUCCESS){POWER_STATE state;state.DeviceState=requested;PoSetPowerState(p->Fdo,DevicePowerState,state);}
 }
 p->LastStatus=st;BrokerUnlock(p);IoFreeWorkItem(w->Work);ExFreePoolWithTag(w,TAG);(void)Finish(p,irp,st);
}
static NTSTATUS Power(PDEVICE_OBJECT d,PIRP irp){OSM_CONTEXT*p=((OSM_EXTENSION*)d->DeviceExtension)->P;PIO_STACK_LOCATION sp=IoGetCurrentIrpStackLocation(irp);NTSTATUS st=IoAcquireRemoveLock(&p->Remove,irp);
 if(st!=STATUS_SUCCESS){irp->IoStatus.Status=st;IoCompleteRequest(irp,IO_NO_INCREMENT);return st;}
 if(sp->MinorFunction==IRP_MN_QUERY_POWER){if(sp->Parameters.Power.Type==DevicePowerState&&sp->Parameters.Power.State.DeviceState!=PowerDeviceD0&&(p->Lease.state==OSM_POISONED||p->Clients))return Finish(p,irp,STATUS_DEVICE_BUSY);return ForwardHeld(p,irp,TRUE);}
 if(sp->MinorFunction!=IRP_MN_SET_POWER||sp->Parameters.Power.Type!=DevicePowerState)return ForwardHeld(p,irp,TRUE);
 OSM_POWER_WORK*w=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*w),TAG);if(!w)return Finish(p,irp,STATUS_INSUFFICIENT_RESOURCES);w->P=p;w->Irp=irp;w->Work=IoAllocateWorkItem(d);if(!w->Work){ExFreePoolWithTag(w,TAG);return Finish(p,irp,STATUS_INSUFFICIENT_RESOURCES);}IoMarkIrpPending(irp);IoQueueWorkItem(w->Work,PowerWorker,DelayedWorkQueue,w);return STATUS_PENDING;
}
static VOID BrokerReference(PVOID context){OSM_CONTEXT*p=context;LONG n=InterlockedIncrement(&p->InterfaceRefs);if(n<=0)p->Faulted=TRUE;ObReferenceObject(p->Fdo);}
static VOID BrokerDereference(PVOID context){OSM_CONTEXT*p=context;LONG n=InterlockedDecrement(&p->InterfaceRefs);if(n<0)p->Faulted=TRUE;ObDereferenceObject(p->Fdo);}
static BOOLEAN ClientCurrent(const OPEN_CLOCK_CLIENT*c){return c->Current(c->Context,c->Pdo,c->Generation)==STATUS_SUCCESS;}
static NTSTATUS BrokerAcquire(PVOID context,const OPEN_CLOCK_CLIENT*c,ULONGLONG*out){
 OSM_CONTEXT*p=context;if(!out||!c||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;*out=0;
 if(c->Size!=sizeof(*c)||c->Version!=OPEN_CLOCK_VERSION||c->Reserved||!c->Pdo||!c->Context||!c->Generation||!c->Current||!c->Drained)return STATUS_INVALID_PARAMETER;
 if((c->Role==OPEN_CLOCK_GPU_CLIENT&&!OpenExactHardwareId(c->Pdo,L"ACPI\\OPEN0549")&&!OpenExactHardwareId(c->Pdo,L"ACPI\\OPEN0515"))||(c->Role==OPEN_CLOCK_SMMU_CLIENT&&c->Pdo!=p->Pdo)||(c->Role!=OPEN_CLOCK_GPU_CLIENT&&c->Role!=OPEN_CLOCK_SMMU_CLIENT))return STATUS_ACCESS_DENIED;
 BrokerLock(p);NTSTATUS st=STATUS_DEVICE_NOT_READY;unsigned freeSlot=RTL_NUMBER_OF(p->Slots);
 if(!Frame(p,p->Generation)&&p->D0Ref&&!p->StopPending&&!p->RemovePending&&p->Lease.state==OSM_ACTIVE&&p->Lease.refs==p->Clients+1&&p->TokenSequence!=MAXULONGLONG&&ClientCurrent(c)){
  for(unsigned i=0;i<RTL_NUMBER_OF(p->Slots);i++)if(!p->Slots[i].Id){freeSlot=i;break;}
  if(freeSlot==RTL_NUMBER_OF(p->Slots))st=STATUS_INSUFFICIENT_RESOURCES;
  else{struct osm_ops o=Ops(p);st=CoreStatus(osm_acquire(&p->Lease,&o,p->Generation));if(st==STATUS_SUCCESS){OSM_CLIENT_SLOT*slot=&p->Slots[freeSlot];slot->Client=*c;ObReferenceObject(c->Pdo);slot->Id=++p->TokenSequence;p->Clients++;*out=slot->Id;}}
 }BrokerUnlock(p);return st;
}
static NTSTATUS BrokerRelease(PVOID context,ULONGLONG token){
 OSM_CONTEXT*p=context;if(!token||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;
 BrokerLock(p);NTSTATUS st=STATUS_INVALID_DEVICE_STATE;
 if(!Frame(p,p->Generation)&&p->D0Ref&&p->Lease.state==OSM_ACTIVE){for(unsigned i=0;i<RTL_NUMBER_OF(p->Slots);i++){OSM_CLIENT_SLOT*slot=&p->Slots[i];if(slot->Id!=token)continue;
  if(!p->Clients||p->Lease.refs!=p->Clients+1||!ClientCurrent(&slot->Client)||slot->Client.Drained(slot->Client.Context,slot->Client.Pdo,slot->Client.Generation)!=STATUS_SUCCESS){st=STATUS_DEVICE_BUSY;break;}
  st=CoreStatus(osm_release(&p->Lease,p->Generation));if(st==STATUS_SUCCESS){ObDereferenceObject(slot->Client.Pdo);RtlZeroMemory(slot,sizeof(*slot));p->Clients--;}break;
 }}BrokerUnlock(p);return st;
}
static NTSTATUS BrokerSnapshot(PVOID context,OPEN_CLOCK_SNAPSHOT*out){
 OSM_CONTEXT*p=context;if(!out||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;
 RtlZeroMemory(out,sizeof(*out));BrokerLock(p);NTSTATUS st=STATUS_DEVICE_NOT_READY;
 if(!Frame(p,p->Generation)&&p->D0Ref&&p->Lease.state==OSM_ACTIVE){st=CoreStatus(osm_witness(&p->Lease,p->Generation));if(st==STATUS_SUCCESS){
  static const unsigned bank[4]={1,3,3,2};static const ULONG off[4]={0,0x10,0x18,0x11c};
  for(unsigned i=0;i<4;i++){uint32_t v;if(Read(p,(uintptr_t)p->Map[bank[i]],off[i],&v)){p->Faulted=TRUE;st=STATUS_DEVICE_HARDWARE_ERROR;break;}out->Branches[i]=v;}
  if(st==STATUS_SUCCESS){out->DelayRequestMask=p->Lease.delay_request_mask;out->Bit0ConfirmedMask=0;for(unsigned j=0;j<4;j++)if(out->Branches[j]&1u)out->Bit0ConfirmedMask|=1u<<j;out->Size=sizeof(*out);out->Version=OPEN_CLOCK_VERSION;out->Cx=p->Lease.last_cx;out->Hw=p->Lease.last_hw;out->Root=p->Lease.last_root;out->Cfg=p->Lease.last_cfg;out->Generation=p->Generation;out->At100ns=KeQueryInterruptTime();}
 }}BrokerUnlock(p);return st;
}
#include "../gmu_clock_broker.inc"
static NTSTATUS Pnp(PDEVICE_OBJECT d,PIRP irp);
static BOOLEAN BuffersOverlap(PVOID a,SIZE_T an,PVOID b,SIZE_T bn){ULONG_PTR x=(ULONG_PTR)a,y=(ULONG_PTR)b;return x>MAXULONG_PTR-an||y>MAXULONG_PTR-bn||(x<y+bn&&y<x+an);}
static NTSTATUS CaptureGlobals(OSM_CONTEXT*p,OSH_SNAPSHOT*s){
 PUCHAR b=(PUCHAR)p->Map[0];RtlZeroMemory(s,sizeof(*s));
 s->Id0=READ_REGISTER_ULONG((PULONG)(b+0x20));
 s->Id1=READ_REGISTER_ULONG((PULONG)(b+0x24));
 s->Id2=READ_REGISTER_ULONG((PULONG)(b+0x28));
 if(s->Id0!=0x4c017e18u||s->Id1!=0x40000016u||s->Id2!=0x5511u)return STATUS_DEVICE_CONFIGURATION_ERROR;
 s->Nscr0=READ_REGISTER_ULONG((PULONG)b);s->Nsacr=READ_REGISTER_ULONG((PULONG)(b+0x10));
 for(ULONG i=0;i<OSH_SMRS;i++){s->Smr[i]=READ_REGISTER_ULONG((PULONG)(b+0x800+i*4));s->S2cr[i]=READ_REGISTER_ULONG((PULONG)(b+0xc00+i*4));}
 return STATUS_SUCCESS;
}
/* Actual owner-internal entry, not a generic caller boolean/token. The source
 * D0 broker's mutex/remove lock, START grants and current clock witness apply.
 * Caller holds a genuine referenced FDO/driver context; no public dispatch is
 * published. Outputs must remain owned through this synchronous PASSIVE call.
 */
#include "../local_bank_native.inc"
#include "../fault_owner_native.inc"
#include "../ns_scope_native.inc"
#include "../gpu_user_native.inc"
static NTSTATUS InspectGlobalsFdo(PDEVICE_OBJECT fdo,OSH_SNAPSHOT*first,OSH_SNAPSHOT*second,OSH_REPORT*out){
 if(!fdo||!first||!second||!out||BuffersOverlap(first,sizeof(*first),second,sizeof(*second))||BuffersOverlap(first,sizeof(*first),out,sizeof(*out))||BuffersOverlap(second,sizeof(*second),out,sizeof(*out))||KeGetCurrentIrql()!=PASSIVE_LEVEL||fdo->DriverObject->MajorFunction[IRP_MJ_PNP]!=Pnp)return STATUS_INVALID_PARAMETER;
 OSM_CONTEXT*p=((OSM_EXTENSION*)fdo->DeviceExtension)->P;if(!p||p->Fdo!=fdo)return STATUS_INVALID_DEVICE_STATE;
 NTSTATUS st=IoAcquireRemoveLock(&p->Remove,out);if(st!=STATUS_SUCCESS)return st;
 RtlZeroMemory(first,sizeof(*first));RtlZeroMemory(second,sizeof(*second));RtlZeroMemory(out,sizeof(*out));out->Status=OSH_NOT_CAPTURED;out->ProtectedBank=MAXULONG;
 BrokerLock(p);st=STATUS_DEVICE_NOT_READY;
 if(!Frame(p,p->Generation)&&p->D0Ref&&!p->StopPending&&!p->RemovePending&&!p->Clients&&
    p->Lease.state==OSM_ACTIVE&&p->Lease.refs==1&&p->Granted[0]&&p->Map[0]&&
    osm_required_ranges[0].pa==0x03da0000&&osm_required_ranges[0].bytes==0x40000&&!osm_required_ranges[0].writable){
  st=CoreStatus(osm_witness(&p->Lease,p->Generation));
  if(st==STATUS_SUCCESS){
   st=CaptureGlobals(p,first);KeMemoryBarrier();if(st==STATUS_SUCCESS)st=CaptureGlobals(p,second);
   if(st==STATUS_SUCCESS)st=CoreStatus(osm_witness(&p->Lease,p->Generation));
   if(st==STATUS_SUCCESS)st=OshAnalyze(first,second,out)==OSH_OK?STATUS_SUCCESS:STATUS_DEVICE_CONFIGURATION_ERROR;
  }
 }
 BrokerUnlock(p);IoReleaseRemoveLock(&p->Remove,out);return st;
}

#if OPEN_QTB_WITNESS
#include "../qtb_once.c"
#include "../qtb_native.inc"
#endif
static NTSTATUS InspectGlobalsApi(PVOID context,OSH_SNAPSHOT*a,OSH_SNAPSHOT*b,OSH_REPORT*r){OSM_CONTEXT*p=context;return InspectGlobalsFdo(p->Fdo,a,b,r);}
static NTSTATUS Pnp(PDEVICE_OBJECT d,PIRP irp){OSM_CONTEXT*p=((OSM_EXTENSION*)d->DeviceExtension)->P;PIO_STACK_LOCATION sp=IoGetCurrentIrpStackLocation(irp);NTSTATUS st=IoAcquireRemoveLock(&p->Remove,irp);
 if(st!=STATUS_SUCCESS){irp->IoStatus.Status=st;IoCompleteRequest(irp,IO_NO_INCREMENT);return st;}
 switch(sp->MinorFunction){
 case IRP_MN_QUERY_INTERFACE:
  if(sp->Parameters.QueryInterface.InterfaceType&&RtlCompareMemory(sp->Parameters.QueryInterface.InterfaceType,&OpenLocalBankQueryGuid,sizeof(GUID))==sizeof(GUID)){
   if(irp->RequestorMode!=KernelMode||sp->Parameters.QueryInterface.Size!=sizeof(OPEN_LOCAL_BANK_INTERFACE)||sp->Parameters.QueryInterface.Version!=OPEN_QTB_ABI||!sp->Parameters.QueryInterface.Interface||sp->Parameters.QueryInterface.InterfaceSpecificData)return Finish(p,irp,STATUS_INVALID_PARAMETER);
   BrokerLock(p);st=STATUS_DEVICE_NOT_READY;if(!Frame(p,p->Generation)&&p->D0Ref&&!p->StopPending&&!p->RemovePending&&p->InterfaceRefs<MAXLONG){OPEN_LOCAL_BANK_INTERFACE a;RtlZeroMemory(&a,sizeof(a));a.Interface.Size=sizeof(a);a.Interface.Version=OPEN_QTB_ABI;a.Interface.Context=p;a.Interface.InterfaceReference=BrokerReference;a.Interface.InterfaceDereference=BrokerDereference;a.ProviderPdo=p->Pdo;a.Reserve=LocalApiReserve;a.Qualify=LocalApiQualify;a.BindRequest=LocalApiBind;a.CheckBank=LocalApiCheck;a.PinProgramming=LocalApiPin;a.ReleaseUnpublished=LocalApiRelease;a.ConnectFault=FaultConnectApi;a.CheckFault=FaultCheckApi;a.DisconnectFaultUnpublished=FaultDisconnectApi;a.EnterNs=NsEnterApi;a.CheckNs=NsCheckApi;a.LeaveNs=NsLeaveApi;a.PromoteRuntime=NsPromoteRuntimeApi;a.CheckNsFast=NsCheckFastApi;a.ReserveGpuUser=GpuUserReserveApi;a.CheckGpuUser=GpuUserCheckApi;a.ReleaseGpuUserUnpublished=GpuUserReleaseApi;a.PinGpuProgramming=GpuUserPinApi;a.CommitGpuProgramming=GpuUserCommitApi;
#if OPEN_QTB_WITNESS
 a.QtbOnce=QtbOnceApi;
#endif
BrokerReference(p);RtlCopyMemory(sp->Parameters.QueryInterface.Interface,&a,sizeof(a));st=STATUS_SUCCESS;}BrokerUnlock(p);return Finish(p,irp,st);
  }
  if(sp->Parameters.QueryInterface.InterfaceType&&RtlCompareMemory(sp->Parameters.QueryInterface.InterfaceType,&OpenGmuClockQueryGuid,sizeof(GUID))==sizeof(GUID)){
   if(irp->RequestorMode!=KernelMode||sp->Parameters.QueryInterface.Size!=sizeof(OPEN_GMU_CLOCK_INTERFACE)||sp->Parameters.QueryInterface.Version!=1||!sp->Parameters.QueryInterface.Interface)return Finish(p,irp,STATUS_INVALID_PARAMETER);
   BrokerLock(p);st=STATUS_DEVICE_NOT_READY;if(!Frame(p,p->Generation)&&p->D0Ref&&!p->StopPending&&!p->RemovePending&&p->InterfaceRefs<MAXLONG){OPEN_GMU_CLOCK_INTERFACE a;RtlZeroMemory(&a,sizeof(a));a.Interface.Size=sizeof(a);a.Interface.Version=1;a.Interface.Context=p;a.Interface.InterfaceReference=BrokerReference;a.Interface.InterfaceDereference=BrokerDereference;a.ProviderPdo=p->Pdo;a.Acquire=GmuAcquireApi;a.ReleaseCold=GmuReleaseApi;a.Witness=GmuWitnessApi;BrokerReference(p);RtlCopyMemory(sp->Parameters.QueryInterface.Interface,&a,sizeof(a));st=STATUS_SUCCESS;}BrokerUnlock(p);return Finish(p,irp,st);
  }
  if(sp->Parameters.QueryInterface.InterfaceType&&RtlCompareMemory(sp->Parameters.QueryInterface.InterfaceType,&OpenClockQueryGuid,sizeof(GUID))==sizeof(GUID)){
   if(irp->RequestorMode!=KernelMode||sp->Parameters.QueryInterface.Size!=sizeof(OPEN_CLOCK_INTERFACE)||sp->Parameters.QueryInterface.Version!=OPEN_CLOCK_VERSION||!sp->Parameters.QueryInterface.Interface||sp->Parameters.QueryInterface.InterfaceSpecificData)return Finish(p,irp,STATUS_INVALID_PARAMETER);
   BrokerLock(p);st=STATUS_DEVICE_NOT_READY;
   if(!Frame(p,p->Generation)&&p->D0Ref&&!p->StopPending&&!p->RemovePending&&p->InterfaceRefs<MAXLONG){OPEN_CLOCK_INTERFACE api;RtlZeroMemory(&api,sizeof(api));api.Interface.Size=sizeof(api);api.Interface.Version=OPEN_CLOCK_VERSION;api.Interface.Context=p;api.Interface.InterfaceReference=BrokerReference;api.Interface.InterfaceDereference=BrokerDereference;api.ProviderPdo=p->Pdo;api.Acquire=BrokerAcquire;api.Release=BrokerRelease;api.Snapshot=BrokerSnapshot;api.InspectGlobals=InspectGlobalsApi;BrokerReference(p);RtlCopyMemory(sp->Parameters.QueryInterface.Interface,&api,sizeof(api));st=STATUS_SUCCESS;}
   BrokerUnlock(p);return Finish(p,irp,st);
  }break;
 case IRP_MN_START_DEVICE:
  BrokerLock(p);st=(!p->Started&&!p->Removing&&(p->Lease.state==OSM_NEW||(p->Lease.state==OSM_RELEASED&&Safe(p))))?STATUS_SUCCESS:STATUS_INVALID_DEVICE_STATE;BrokerUnlock(p);
  if(st!=STATUS_SUCCESS)return Finish(p,irp,st);
  st=LowerSync(p,irp);if(st==STATUS_SUCCESS){BrokerLock(p);if(p->Started||(p->Lease.state!=OSM_NEW&&!(p->Lease.state==OSM_RELEASED&&Safe(p))))st=STATUS_INVALID_DEVICE_STATE;else{if(p->Lease.state==OSM_RELEASED)RtlZeroMemory(&p->Lease,sizeof(p->Lease));st=ValidateResources(p,sp->Parameters.StartDevice.AllocatedResources);if(st==STATUS_SUCCESS)st=ValidateResources(p,sp->Parameters.StartDevice.AllocatedResourcesTranslated);if(st==STATUS_SUCCESS)st=CaptureFaultGrants(p,sp->Parameters.StartDevice.AllocatedResources,sp->Parameters.StartDevice.AllocatedResourcesTranslated);if(st==STATUS_SUCCESS)st=FaultCurrentIort();
#if OPEN_QTB_WITNESS
 if(st==STATUS_SUCCESS){PHYSICAL_ADDRESS qpa;qpa.QuadPart=p->QtbGrant.u.Memory.Start.QuadPart;p->QtbMap=MmMapIoSpaceEx(qpa,0x1000,PAGE_NOCACHE|PAGE_READWRITE);if(!p->QtbMap)st=STATUS_INSUFFICIENT_RESOURCES;}
#endif
 if(st==STATUS_SUCCESS){p->Generation=(ULONG64)InterlockedIncrement64(&Sequence);p->StopPending=FALSE;p->RemovePending=FALSE;p->Started=TRUE;InterlockedExchange(&p->NsRevoked,0);st=EnterD0(p);if(st==STATUS_SUCCESS){POWER_STATE state;state.DeviceState=PowerDeviceD0;PoSetPowerState(d,DevicePowerState,state);}}}p->LastStatus=st;BrokerUnlock(p);}return Finish(p,irp,st);
 case IRP_MN_QUERY_STOP_DEVICE:case IRP_MN_QUERY_REMOVE_DEVICE:
  BrokerLock(p);st=(!p->Clients&&Safe(p))?STATUS_SUCCESS:STATUS_DEVICE_BUSY;
  if(st==STATUS_SUCCESS){if(sp->MinorFunction==IRP_MN_QUERY_STOP_DEVICE)p->StopPending=TRUE;else p->RemovePending=TRUE;}BrokerUnlock(p);
  if(st!=STATUS_SUCCESS)return Finish(p,irp,st);
  st=LowerSync(p,irp);if(st!=STATUS_SUCCESS){BrokerLock(p);if(sp->MinorFunction==IRP_MN_QUERY_STOP_DEVICE)p->StopPending=FALSE;else p->RemovePending=FALSE;BrokerUnlock(p);}return Finish(p,irp,st);
 case IRP_MN_CANCEL_STOP_DEVICE:
  BrokerLock(p);p->StopPending=FALSE;BrokerUnlock(p);break;
 case IRP_MN_CANCEL_REMOVE_DEVICE:
  BrokerLock(p);p->RemovePending=FALSE;BrokerUnlock(p);break;
 case IRP_MN_STOP_DEVICE:
  FaultInvalidate(p);
  /* STOP cannot be failed. QUERY_STOP vetoes an active lease; an unexpected
   * STOP invalidates ownership and retains it without trying uncertain MMIO. */
  BrokerLock(p);p->Started=FALSE;if(!Safe(p))p->Faulted=TRUE;p->LastStatus=STATUS_SUCCESS;BrokerUnlock(p);p->LinkStatus=IoSetDeviceInterfaceState(&p->Link,FALSE);
  irp->IoStatus.Status=STATUS_SUCCESS;return ForwardHeld(p,irp,FALSE);
 case IRP_MN_SURPRISE_REMOVAL:
  FaultInvalidate(p);
  /* The grant is gone: no MMIO cleanup after surprise removal. Retain any
   * active/uncertain generation until reset, never infer a successful release. */
  BrokerLock(p);p->Removing=TRUE;p->Started=FALSE;if(!Safe(p))p->Faulted=TRUE;BrokerUnlock(p);p->LinkStatus=IoSetDeviceInterfaceState(&p->Link,FALSE);return ForwardHeld(p,irp,FALSE);
 case IRP_MN_REMOVE_DEVICE:
  IoReleaseRemoveLockAndWait(&p->Remove,irp);FaultInvalidate(p);BrokerLock(p);
  /* REMOVE never initiates hardware cleanup. Only an admitted D3
   * transition may release while the grant is known current. */
  p->Removing=TRUE;p->Started=FALSE;BOOLEAN safe=Safe(p);if(!safe)p->Faulted=TRUE;BrokerUnlock(p);p->LinkStatus=IoSetDeviceInterfaceState(&p->Link,FALSE);
  IoSkipCurrentIrpStackLocation(irp);st=IoCallDriver(p->Lower,irp);IoDetachDevice(p->Lower);p->Lower=NULL;
  if(safe){OpenParentUnbind(&p->Parent);RtlFreeUnicodeString(&p->Link);ObDereferenceObject(p->Pdo);ExFreePoolWithTag(p,TAG);}else{Retained=p;DbgPrintEx(DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL,"OpenSmmuD0 unresolved lease/mapping retained until reset\n");}
  IoDeleteDevice(d);return st;
 default:break;
 }
 return ForwardHeld(p,irp,FALSE);
}
static NTSTATUS Add(PDRIVER_OBJECT driver,PDEVICE_OBJECT pdo){PDEVICE_OBJECT fdo=NULL;NTSTATUS st;
 if(InterlockedCompareExchange(&Added,1,0))return STATUS_DEVICE_BUSY;
 st=IoCreateDevice(driver,sizeof(OSM_EXTENSION),NULL,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,FALSE,&fdo);if(st!=STATUS_SUCCESS)return st;
 OSM_CONTEXT*p=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*p),TAG);if(!p){IoDeleteDevice(fdo);return STATUS_INSUFFICIENT_RESOURCES;}RtlZeroMemory(p,sizeof(*p));p->Pdo=pdo;p->Fdo=fdo;ObReferenceObject(pdo);KeInitializeMutex(&p->Lock,0);KeInitializeMutex(&p->NsMutex,0);p->NsRevoked=1;IoInitializeRemoveLock(&p->Remove,TAG,0,0);((OSM_EXTENSION*)fdo->DeviceExtension)->P=p;
 p->Lower=IoAttachDeviceToDeviceStack(fdo,pdo);if(!p->Lower){ObDereferenceObject(pdo);ExFreePoolWithTag(p,TAG);IoDeleteDevice(fdo);return STATUS_NO_SUCH_DEVICE;}st=IoRegisterDeviceInterface(pdo,&OpenClockDeviceGuid,NULL,&p->Link);if(st!=STATUS_SUCCESS){IoDetachDevice(p->Lower);ObDereferenceObject(pdo);ExFreePoolWithTag(p,TAG);IoDeleteDevice(fdo);return st;}fdo->Flags|=DO_POWER_PAGABLE;fdo->Flags&=~DO_DEVICE_INITIALIZING;return STATUS_SUCCESS;
}
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT driver,PUNICODE_STRING path){NTSTATUS aux=AuxKlibInitialize();if(aux!=STATUS_SUCCESS)return aux;UNREFERENCED_PARAMETER(path);for(unsigned i=0;i<=IRP_MJ_MAXIMUM_FUNCTION;i++)driver->MajorFunction[i]=Forward;driver->MajorFunction[IRP_MJ_CREATE]=FileIrp;driver->MajorFunction[IRP_MJ_CLOSE]=FileIrp;driver->MajorFunction[IRP_MJ_CLEANUP]=FileIrp;driver->MajorFunction[IRP_MJ_PNP]=Pnp;driver->MajorFunction[IRP_MJ_POWER]=Power;driver->DriverExtension->AddDevice=Add;driver->DriverUnload=NULL;return STATUS_SUCCESS;}
