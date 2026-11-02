#include <aux_klib.h>
#include "fault_iort.h"
static NTSTATUS FaultCurrentOgbt(void){UCHAR data[124];ULONG n=sizeof(data);NTSTATUS s=AuxKlibGetSystemFirmwareTable(0x41435049u,0x5442474fu,data,sizeof(data),&n);return s==STATUS_SUCCESS&&(n!=sizeof(data)||OfOgbtContract(data,n))?STATUS_DEVICE_CONFIGURATION_ERROR:s;}
static NTSTATUS FaultCurrentIort(void){NTSTATUS st;ULONG bytes=0;st=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54524f49u,NULL,0,&bytes);if(st!=STATUS_BUFFER_TOO_SMALL&&st!=STATUS_SUCCESS)return st;if(bytes<48||bytes>65536)return STATUS_DEVICE_CONFIGURATION_ERROR;PVOID b=ExAllocatePool2(POOL_FLAG_NON_PAGED,bytes,'tIfO');if(!b)return STATUS_INSUFFICIENT_RESOURCES;ULONG got=0;st=AuxKlibGetSystemFirmwareTable(0x41435049u,0x54524f49u,b,bytes,&got);if(st==STATUS_SUCCESS&&(got!=bytes||OfIortContract(b,got)))st=STATUS_DEVICE_CONFIGURATION_ERROR;ExFreePoolWithTag(b,'tIfO');return st==STATUS_SUCCESS?FaultCurrentOgbt():st;}
/* Private actual MMU1 owner, fixed two ordinary level interrupt resources. */
static BOOLEAN FaultIsr(PKINTERRUPT irq,PVOID context){UNREFERENCED_PARAMETER(irq);OF_ISR_CONTEXT*c=context;OF_OWNER*f=c->Owner;if(!InterlockedCompareExchange(&f->Armed,0,0))return FALSE;
 ULONG off=c->Index?0x58:0x48;ULONG v=READ_REGISTER_ULONG((PULONG)((PUCHAR)f->Map[c->Index]+off));ULONG ack=OfAckPolicy(&f->Journal,c->Index,v);
 if(ack){WRITE_REGISTER_ULONG((PULONG)((PUCHAR)f->Map[c->Index]+off),ack);KeMemoryBarrier();}return (c->Index?(v&~0x400u):v)?TRUE:FALSE;
}
static NTSTATUS CaptureFaultGrants(OSM_CONTEXT*p,PCM_RESOURCE_LIST raw,PCM_RESOURCE_LIST translated){
 if(!raw||!translated||raw->Count!=1||translated->Count!=1||raw->List[0].PartialResourceList.Count!=9||translated->List[0].PartialResourceList.Count!=9)return STATUS_DEVICE_CONFIGURATION_ERROR;
 const ULONG gsiv[3]={705,711,709};OF_IRQ_GRANT out[3];
 for(unsigned i=0;i<3;i++){PCM_PARTIAL_RESOURCE_DESCRIPTOR a=&raw->List[0].PartialResourceList.PartialDescriptors[6+i],b=&translated->List[0].PartialResourceList.PartialDescriptors[6+i];
  if(a->Type!=CmResourceTypeInterrupt||b->Type!=CmResourceTypeInterrupt||a->Flags!=CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE||b->Flags!=CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE||a->ShareDisposition!=CmResourceShareDeviceExclusive||b->ShareDisposition!=CmResourceShareDeviceExclusive||a->u.Interrupt.Vector!=gsiv[i]||!b->u.Interrupt.Vector||b->u.Interrupt.Vector==MAXULONG||b->u.Interrupt.Level<=DISPATCH_LEVEL||b->u.Interrupt.Level>HIGH_LEVEL||!b->u.Interrupt.Affinity)return STATUS_DEVICE_CONFIGURATION_ERROR;
#if defined(NT_PROCESSOR_GROUPS)
  if(b->u.Interrupt.Group)return STATUS_NOT_SUPPORTED; /* exact8-core Group0 source profile */
#endif
  out[i].Vector=b->u.Interrupt.Vector;out[i].Irql=(KIRQL)b->u.Interrupt.Level;out[i].Affinity=b->u.Interrupt.Affinity;
 }
 RtlCopyMemory(p->Fault.Grant,out,sizeof(out));p->Fault.GrantsValid=TRUE;return STATUS_SUCCESS;
}
static VOID FaultDisconnectObjects(OF_OWNER*f){
 /* Serialize callback invalidation at the validated common interrupt DIRQL,
  * even if a failed connect returned an uncertain object that cannot be used. */
 if(f->SyncIrql>DISPATCH_LEVEL){KIRQL old;KeRaiseIrql(f->SyncIrql,&old);KeAcquireSpinLockAtDpcLevel(&f->Lock);InterlockedExchange(&f->Armed,0);KeReleaseSpinLockFromDpcLevel(&f->Lock);KeLowerIrql(old);}else InterlockedExchange(&f->Armed,0);
 for(unsigned i=0;i<3;i++)if(f->KnownMask&(1u<<i)){IoDisconnectInterrupt(f->Interrupt[i]);f->Interrupt[i]=NULL;f->KnownMask&=~(1u<<i);} /* unknown failed tokens stay retained */
}
/* Caller holds BrokerLock. Never tear down coverage across a writer's
 * check→store interval. A fatal caller revokes/retains now; NsLeave joins and
 * disconnects after that actual writer has stopped using the fixed mapper. */
static VOID FaultRetainAndDisconnect(OSM_CONTEXT*p){
 p->Fault.Retain=1;InterlockedExchange(&p->NsRevoked,1);
 if(!p->NsToken)FaultDisconnectObjects(&p->Fault);
}
/* STOP/surprise/remove: official interrupt disconnect joins ISR; no MMIO or
 * mapping cleanup after grants disappear. Retain state/code/maps until reset. */
static VOID FaultInvalidate(OSM_CONTEXT*p){
 /* Revoke first, then join the actual PASSIVE writer interval before tearing
  * down IRQ coverage. No BrokerLock is held while waiting: writer proof checks
  * and LeaveNs must be able to finish. This is a software lifetime join, not a
  * hardware completion poll or an assertion that surprise grants persist. */
 InterlockedExchange(&p->NsRevoked,1);
 (void)KeWaitForSingleObject(&p->NsMutex,Executive,KernelMode,FALSE,NULL);
 BrokerLock(p);p->Started=FALSE;OF_OWNER*f=&p->Fault;if(f->Map[0]||f->Map[1]||f->Map[2]||f->Interrupt[0]||f->Interrupt[1]||f->Interrupt[2]){f->Retain=1;FaultDisconnectObjects(f);}BrokerUnlock(p);
 KeReleaseMutex(&p->NsMutex,FALSE);
}
static NTSTATUS FaultEnter(OSM_CONTEXT*p,PVOID tag){NTSTATUS st=IoAcquireRemoveLock(&p->Remove,tag);if(st!=STATUS_SUCCESS)return st;BrokerLock(p);return STATUS_SUCCESS;}
static VOID FaultLeave(OSM_CONTEXT*p,PVOID tag){BrokerUnlock(p);IoReleaseRemoveLock(&p->Remove,tag);}
static int FaultBinding(OSM_CONTEXT*p,OLB_NATIVE*b){return b&&b->Referenced&&b->Fdo==p->Fdo&&b->Hold&&b->Id&&p->BankClaims==1;}
static NTSTATUS FaultConnectApi(PVOID x,OLB_NATIVE*b,PVOID*out){
 OSM_CONTEXT*p=x;if(!out||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;*out=NULL;NTSTATUS entry=FaultEnter(p,out);if(entry!=STATUS_SUCCESS)return entry;OF_OWNER*f=&p->Fault;NTSTATUS st=STATUS_INVALID_DEVICE_STATE;unsigned maps=p->GpuUser.Qualified?3:2;
 if((p->GpuUser.Id&&(!p->GpuUser.Qualified||p->GpuUser.Retained||p->GpuUserGmu!=b))||p->NsToken||!FaultBinding(p,b)||!f->GrantsValid||f->Map[0]||f->Map[1]||f->Map[2]||f->Retain||f->Connecting){FaultLeave(p,out);return st;}
 OLB_NATIVE_IO n={p,b->Hold};OLB_IO io=LocalOps(&n);OLB_CLAIM c;st=LocalStatus(OlbCheck(&p->Banks,&io,b->Id,&c));if(st!=STATUS_SUCCESS||c.Bank!=2){FaultLeave(p,out);return st==STATUS_SUCCESS?STATUS_NOT_SUPPORTED:st;}
 if(maps==3){p->GpuCandidateRead=TRUE;st=LocalStatus(OguCheckCold(&p->GpuUser,&io));p->GpuCandidateRead=FALSE;if(st!=STATUS_SUCCESS){FaultLeave(p,out);return st;}}
 st=FaultCurrentIort();if(st!=STATUS_SUCCESS){FaultLeave(p,out);return st;}
 f->Bank=b;f->Generation=p->Generation;f->Connecting=1;KeInitializeSpinLock(&f->Lock);
 PHYSICAL_ADDRESS pa;pa.QuadPart=0x03da0000;f->Map[0]=MmMapIoSpaceEx(pa,0x1000,PAGE_READWRITE|PAGE_NOCACHE);pa.QuadPart=0x03dc2000;f->Map[1]=MmMapIoSpaceEx(pa,0x1000,PAGE_READWRITE|PAGE_NOCACHE);if(maps==3){pa.QuadPart=0x03dc0000;f->Map[2]=MmMapIoSpaceEx(pa,0x1000,PAGE_READWRITE|PAGE_NOCACHE);}
 if(!f->Map[0]||!f->Map[1]||(maps==3&&!f->Map[2])){st=STATUS_INSUFFICIENT_RESOURCES;goto clean;}
 /* Do not clear or consume inherited faults. No stores before actual IRQs. */
 if(READ_REGISTER_ULONG((PULONG)((PUCHAR)f->Map[0]+0x48))||READ_REGISTER_ULONG((PULONG)((PUCHAR)f->Map[1]+0x58))||(maps==3&&READ_REGISTER_ULONG((PULONG)((PUCHAR)f->Map[2]+0x58)))){st=STATUS_DEVICE_BUSY;goto clean;}
 for(unsigned i=0;i<maps;i++){f->Isr[i].Owner=f;f->Isr[i].Index=i;}
 *out=f;InterlockedExchange(&f->Armed,1);KIRQL sync=f->Grant[0].Irql>f->Grant[1].Irql?f->Grant[0].Irql:f->Grant[1].Irql;if(maps==3&&f->Grant[2].Irql>sync)sync=f->Grant[2].Irql;f->SyncIrql=sync;
 for(unsigned i=0;i<maps;i++){
  st=IoConnectInterrupt(&f->Interrupt[i],FaultIsr,&f->Isr[i],&f->Lock,f->Grant[i].Vector,f->Grant[i].Irql,sync,LevelSensitive,FALSE,f->Grant[i].Affinity,FALSE);
  if(st!=STATUS_SUCCESS){if(f->Interrupt[i]){f->UncertainMask|=1u<<i;f->Retain=1;f->Connecting=0;FaultDisconnectObjects(f);FaultLeave(p,out);return CghNativeRetainFailure(b->Hold,st);}goto clean;}
  if(!f->Interrupt[i]){f->UncertainMask|=1u<<i;f->Retain=1;f->Connecting=0;FaultDisconnectObjects(f);FaultLeave(p,out);return CghNativeRetainFailure(b->Hold,STATUS_DEVICE_DATA_ERROR);}f->KnownMask|=1u<<i;
 }
 f->Connecting=0;if(InterlockedCompareExchange(&f->Journal.Fatal,0,0)){FaultRetainAndDisconnect(p);FaultLeave(p,out);return CghNativeRetainFailure(b->Hold,STATUS_DEVICE_HARDWARE_ERROR);}FaultLeave(p,out);return STATUS_SUCCESS;
clean:
 FaultDisconnectObjects(f);f->Connecting=0;
 if(InterlockedCompareExchange(&f->Journal.Fatal,0,0)){f->Retain=1;*out=f;FaultLeave(p,out);return CghNativeRetainFailure(b->Hold,st);}
 for(unsigned i=0;i<3;i++)if(f->Map[i]){MmUnmapIoSpace(f->Map[i],0x1000);f->Map[i]=NULL;}f->Bank=NULL;*out=NULL;FaultLeave(p,out);return st;
}
static NTSTATUS FaultCheckApi(PVOID x,OLB_NATIVE*b,PVOID token,const OSMA_REQUEST*q){
 OSM_CONTEXT*p=x;if(!q||!b||q->Proof.StopSerial!=b->StopSerial||token!=&p->Fault||q->Proof.Fault!=token||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;NTSTATUS entry=FaultEnter(p,(PVOID)q);if(entry!=STATUS_SUCCESS)return entry;OF_OWNER*f=&p->Fault;NTSTATUS st=STATUS_DEVICE_NOT_READY;
 if(FaultBinding(p,b)&&f->Bank==b&&f->Generation==p->Generation&&f->Map[0]&&f->Map[1]&&f->Interrupt[0]&&f->Interrupt[1]&&(!p->GpuUser.Qualified||(f->Map[2]&&f->Interrupt[2]))&&InterlockedCompareExchange(&f->Armed,0,0)&&!f->Retain&&!f->Connecting&&!InterlockedCompareExchange(&f->Journal.Fatal,0,0)){
  OLB_NATIVE_IO n={p,b->Hold};OLB_IO io=LocalOps(&n);OLB_CLAIM c;st=LocalStatus(b->ProgramPinned?OlbCheckPinned(&p->Banks,&io,b->Id,&c):OlbCheck(&p->Banks,&io,b->Id,&c));if(st==STATUS_SUCCESS&&(c.Bank!=q->Bank||c.Asid!=q->Asid||c.Slot!=q->Slot))st=STATUS_INVALID_PARAMETER;
 }if(st!=STATUS_SUCCESS&&InterlockedCompareExchange(&f->Journal.Fatal,0,0)){FaultRetainAndDisconnect(p);FaultLeave(p,(PVOID)q);return CghNativeRetainFailure(b->Hold,st);}FaultLeave(p,(PVOID)q);if(st!=STATUS_SUCCESS)return CghNativeRetainFailure(b->Hold,st);return st;
}
static NTSTATUS FaultDisconnectApi(PVOID x,OLB_NATIVE*b,PVOID*token){
 OSM_CONTEXT*p=x;if(!token||*token!=&p->Fault||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;NTSTATUS entry=FaultEnter(p,token);if(entry!=STATUS_SUCCESS)return entry;OF_OWNER*f=&p->Fault;NTSTATUS st=STATUS_DEVICE_BUSY;
 if(FaultBinding(p,b)&&f->Bank==b&&InterlockedCompareExchange(&f->Journal.Fatal,0,0)){FaultRetainAndDisconnect(p);FaultLeave(p,token);return CghNativeRetainFailure(b->Hold,STATUS_DEVICE_HARDWARE_ERROR);}
 if(FaultBinding(p,b)&&f->Bank==b&&!b->ProgramPinned&&!p->NsToken&&!f->Retain&&!InterlockedCompareExchange(&f->Journal.Fatal,0,0)){
  OLB_NATIVE_IO n={p,b->Hold};OLB_IO io=LocalOps(&n);OLB_CLAIM c;st=LocalStatus(OlbCheck(&p->Banks,&io,b->Id,&c));if(st!=STATUS_SUCCESS){FaultRetainAndDisconnect(p);FaultLeave(p,token);return CghNativeRetainFailure(b->Hold,st);}if(st==STATUS_SUCCESS){FaultDisconnectObjects(f);if(InterlockedCompareExchange(&f->Journal.Fatal,0,0)){f->Retain=1;FaultLeave(p,token);return CghNativeRetainFailure(b->Hold,STATUS_DEVICE_HARDWARE_ERROR);}for(unsigned i=0;i<3;i++)if(f->Map[i]){MmUnmapIoSpace(f->Map[i],0x1000);f->Map[i]=NULL;}f->Bank=NULL;*token=NULL;}
 }FaultLeave(p,token);return st;
}
