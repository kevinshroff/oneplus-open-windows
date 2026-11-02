/* SPDX-License-Identifier: MIT. No entry point/dispatch/native execution. */
#include "open_smmu_activate_wdm.h"
#include <intrin.h>
#define TAG 'AmSO'
#define NEED (OSMA_CURRENT|OSMA_PHYSICAL_STOP|OSMA_BANK_STREAM|OSMA_SECURE_ACCESS|OSMA_TABLES_VISIBLE|OSMA_FAULT_HANDLER)
static int Current(OSMA_NATIVE_IO*n,unsigned extra){return !n||!n->Base||n->Proof.check(n->Proof.Context,&n->Proof,NEED|extra,5,n->Bank,n->Bank,n->Slot);}
static int Read32(void*cookie,size_t at,uint32_t*out){OSMA_NATIVE_IO*n=cookie;size_t cb=0x20000+n->Bank*0x1000;
 if(!out||Current(n,at==0x74?OSMA_NS_BLOCK:0)||(at&3))return -1;
 BOOLEAN ok=at==0||at==0x10||at==0x20||at==0x24||at==0x28||at==0x74||
 (at>=0x800&&at<0x800+OSH_SMRS*4)||(at>=0xc00&&at<0xc00+OSH_SMRS*4)||
 at==0x1000+n->Bank*4||at==0x1800+n->Bank*4||at==cb||at==cb+4||at==cb+0x10||
 at==cb+0x30||at==cb+0x38||at==cb+0x3c||at==cb+0x58||at==cb+0x7f4;
 if(!ok)return -1;*out=READ_REGISTER_ULONG((PULONG)(n->Base+at));return *out==MAXULONG?-1:0;
}
static int Read64(void*cookie,size_t at,uint64_t*out){OSMA_NATIVE_IO*n=cookie;size_t cb=0x20000+n->Bank*0x1000;
 if(!out||Current(n,0)||(at!=cb+0x20&&at!=cb+0x28))return -1;
 *out=READ_REGISTER_ULONG64((PULONGLONG)(n->Base+at));return *out==MAXULONGLONG?-1:0;
}
static int Write32(void*cookie,size_t at,uint32_t v){OSMA_NATIVE_IO*n=cookie;size_t cb=0x20000+n->Bank*0x1000;
 unsigned global=at==0||at==0x10||at==0x70;
 if(Current(n,global?OSMA_NS_BLOCK:0))return -1;
 BOOLEAN ok=(at==0x800+n->Slot*4&&v==0x80000005u)||
 (at==0xc00+n->Slot*4&&!(v&~0x030303ffu)&&(((v>>16)&3)==2||v==(0x300u|n->Bank)))||
 (at==0x1000+n->Bank*4&&v==0x1f300)||(at==0x1800+n->Bank*4&&v==1)||
 (at==cb&&(v==0||v==0x00c01067))||(at==cb+4&&v==0x32b)||
 (at==cb+0x10&&v==0x38011)||(at==cb+0x30&&v==0x00803519)||
 (at==cb+0x38&&v==0xf404ff44)||(at==cb+0x3c&&v==0xefe4)||
 (at==cb+0x58&&v==0) /* a new fault belongs to the actual ISR; never hide it before Journal.Fatal */||(at==cb+0x610&&v==n->Bank)||
 ((at==cb+0x7f0||at==0x70)&&v==MAXULONG);
 if(at==0){ULONG now=READ_REGISTER_ULONG((PULONG)n->Base);ok=now!=MAXULONG&&
   !((now^v)&~0x00c0fc37u)&&(v&0x00c0fc37u)==0x00c01c36u;}
 if(at==0x10){ULONG now=READ_REGISTER_ULONG((PULONG)(n->Base+0x10));ok=now!=MAXULONG&&v==(now&~(1u<<26));}
 if(!ok)return -1;WRITE_REGISTER_ULONG((PULONG)(n->Base+at),v);return 0;
}
static int Write64(void*cookie,size_t at,uint64_t v){OSMA_NATIVE_IO*n=cookie;size_t cb=0x20000+n->Bank*0x1000;
 uint64_t tag=(uint64_t)n->Bank<<48;
 if(Current(n,0)||!((at==cb+0x20&&v==(n->Tables->Tables.Tables.root_physical|tag))||(at==cb+0x28&&v==tag)))return -1;
 WRITE_REGISTER_ULONG64((PULONGLONG)(n->Base+at),v);return 0;
}
static int Barrier(void*cookie){OSMA_NATIVE_IO*n=cookie;if(Current(n,0))return -1;__dsb(_ARM64_BARRIER_OSH);return 0;}
static int Wait(void*cookie){if(Current(cookie,0))return -1;KeStallExecutionProcessor(1);return 0;}
NTSTATUS OsmaTakeInactiveTables(G321_INACTIVE_RUNTIME*r,PDEVICE_OBJECT pdo,OSMA_TABLE_BINDING**out){
 if(!r||!pdo||!out||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;*out=NULL;
 LARGE_INTEGER timeout;timeout.QuadPart=-500000;NTSTATUS st=KeWaitForSingleObject(&r->Lock,Executive,KernelMode,FALSE,&timeout);if(st!=STATUS_SUCCESS)return st;
 BOOLEAN entered=FALSE;OSMA_TABLE_BINDING*b=NULL;
 if(!r->Initialized||!r->Attempted||!r->TablesPrepared||r->Poisoned||r->Closed||r->Tables.State!=OSMI_BUILT||r->Tables.ActivationQualified||r->Tables.PoolOrigin!=0x4e435047u||r->Tables.PoolCache!=MmNonCached){st=STATUS_INVALID_DEVICE_STATE;goto done;}
 st=r->Owner.Enter(r->Owner.Cookie,r->Generation);if(st!=STATUS_SUCCESS)goto done;entered=TRUE;
 st=r->Owner.Lease(r->Owner.Cookie,r->Generation);if(st!=STATUS_SUCCESS)goto done;
 st=r->Owner.Stopped(r->Owner.Cookie,r->StopSerial,r->Generation);if(st!=STATUS_SUCCESS)goto done;
 st=OsmiAuditInactive(&r->Tables);if(st!=STATUS_SUCCESS){r->Poisoned=TRUE;goto done;}
 /* The original allocator generated normal NC pages and index0 NC outer-
  * shareable privileged RW/execute descriptors. Check that real ledger again. */
 for(ULONG i=0;i<r->Plan.count;i++){
  G321_BUFFER*m=&r->Buffer[i];if(!(r->AllocatedNcMask&(1u<<i))||!(r->MappedNcMask&(1u<<i))||r->AllocationCache[i]!=MmNonCached||r->MappingCache[i]!=MmNonCached||!m->Mdl||!m->Cpu||m->Mapped||m->MapAttempted||!(m->Mdl->MdlFlags&MDL_PAGES_LOCKED)){st=STATUS_INVALID_DEVICE_STATE;goto done;}
  for(SIZE_T j=0;j<r->Plan.extent[i].bytes/4096;j++){
   UINT64 va=r->Plan.extent[i].iova+j*4096,pa=(UINT64)MmGetMdlPfnArray(m->Mdl)[j]*4096;BOOLEAN found=FALSE;
   for(SIZE_T k=0;k<r->Tables.RangeCount;k++){ArmSmmu4KRange*x=&r->Tables.Ranges[k];if(x->iova==va){found=x->physical==pa&&x->bytes==4096&&x->permissions==15&&!x->writeback&&x->shareability==2;break;}}
   if(!found){st=STATUS_DATA_ERROR;goto done;}
  }
 }
 b=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*b),TAG);if(!b){st=STATUS_INSUFFICIENT_RESOURCES;goto done;}RtlZeroMemory(b,sizeof(*b));
 b->AllocatedNcMask=r->AllocatedNcMask;b->MappedNcMask=r->MappedNcMask;RtlCopyMemory(b->AllocationCache,r->AllocationCache,sizeof(b->AllocationCache));RtlCopyMemory(b->MappingCache,r->MappingCache,sizeof(b->MappingCache));
 b->Tables=r->Tables;RtlCopyMemory(b->Buffer,r->Buffer,sizeof(b->Buffer));b->Plan=r->Plan;b->Inputs=r->Inputs;b->ImageCopy=r->ImageCopy;b->Generation=r->Generation;b->StopSerial=r->StopSerial;b->References=1;
 b->ConsumerPdo=pdo;ObReferenceObject(pdo);
 /* Ownership transfer, not a second referenceable-MDL fiction. Old RAM-only
  * ledger becomes closed/empty and cannot later free these active candidates. */
 r->AllocatedNcMask=r->MappedNcMask=0;RtlZeroMemory(r->AllocationCache,sizeof(r->AllocationCache));RtlZeroMemory(r->MappingCache,sizeof(r->MappingCache));RtlZeroMemory(&r->Tables,sizeof(r->Tables));r->Tables.State=OSMI_CLOSED;RtlZeroMemory(r->Buffer,sizeof(r->Buffer));RtlZeroMemory(&r->Inputs,sizeof(r->Inputs));RtlZeroMemory(&r->Plan,sizeof(r->Plan));r->ImageCopy=NULL;r->TablesPrepared=FALSE;r->Closed=TRUE;
 __dsb(_ARM64_BARRIER_OSHST);*out=b;st=STATUS_SUCCESS;
done:
 if(entered)r->Owner.Leave(r->Owner.Cookie);KeReleaseMutex(&r->Lock,FALSE);return st;
}
NTSTATUS OsmaOpenNativeIo(OSMA_NATIVE_IO*n,PDEVICE_OBJECT pdo,PCM_RESOURCE_LIST resources,OSMA_TABLE_BINDING*b,const OSMA_PROOFS*proof,ULONG bank,ULONG slot){
 if(!n||n->Base||!pdo||!resources||!b||!proof||proof->Tables!=b||!proof->check||bank>=OSH_BANKS||slot>=OSH_SMRS||KeGetCurrentIrql()!=PASSIVE_LEVEL||b->Poisoned||b->ActivationAttempted)return STATUS_INVALID_PARAMETER;
 if(proof->check(proof->Context,proof,NEED,5,bank,bank,slot))return STATUS_ACCESS_DENIED;
 if(resources->Count!=1||resources->List[0].PartialResourceList.Count>64)return STATUS_DEVICE_CONFIGURATION_ERROR;
 ULONG matches=0;for(ULONG i=0;i<resources->List[0].PartialResourceList.Count;i++){
  PCM_PARTIAL_RESOURCE_DESCRIPTOR d=&resources->List[0].PartialResourceList.PartialDescriptors[i];
  if(d->Type!=CmResourceTypeMemory||d->u.Memory.Start.QuadPart!=0x03da0000||d->u.Memory.Length!=0x40000)continue;
  if(d->Flags!=CM_RESOURCE_MEMORY_READ_WRITE||(d->ShareDisposition!=CmResourceShareDeviceExclusive&&d->ShareDisposition!=CmResourceShareDriverExclusive))return STATUS_DEVICE_CONFIGURATION_ERROR;matches++;
 }if(matches!=1)return STATUS_DEVICE_CONFIGURATION_ERROR;
 LONG refs=b->References;for(;;){if(refs<=0||refs==MAXLONG)return STATUS_DEVICE_BUSY;LONG old=InterlockedCompareExchange(&b->References,refs+1,refs);if(old==refs)break;refs=old;}
 PHYSICAL_ADDRESS pa;pa.QuadPart=0x03da0000;PUCHAR base=MmMapIoSpaceEx(pa,0x40000,PAGE_NOCACHE|PAGE_READWRITE);if(!base){InterlockedDecrement(&b->References);return STATUS_INSUFFICIENT_RESOURCES;}
 RtlZeroMemory(n,sizeof(*n));n->Base=base;n->Pdo=pdo;ObReferenceObject(pdo);n->Proof=*proof;n->Tables=b;n->Bank=bank;n->Slot=slot;n->Io=(ArmSmmu4KIo){n,0x40000,Read32,Read64,Write32,Write64,Barrier};return STATUS_SUCCESS;
}
static OSMA_REQUEST Request(OSMA_NATIVE_IO*n){OSMA_REQUEST q={n->Io,n->Proof,&n->Tables->Tables.Config,&n->Tables->Tables.Tables,n->Bank,n->Bank,n->Slot,1000,Wait};return q;}
NTSTATUS OsmaActivateOwnedBinding(OSMA_NATIVE_IO*n){
 if(!n||!n->Base||!n->Tables||n->Tables->ActivationAttempted||n->Tables->Poisoned)return STATUS_INVALID_DEVICE_STATE;
 if(OsmiAuditInactive(&n->Tables->Tables)!=STATUS_SUCCESS)return STATUS_DATA_ERROR;
 /* NC allocator-backed table stores are ordered here; this is not a claim
  * that a random cached buffer was cleaned. Full platform scope is checked
  * by the real mandatory active producer before any MMIO access. */
 __dsb(_ARM64_BARRIER_OSHST);n->Tables->ActivationAttempted=TRUE;
 for(ULONG i=0;i<n->Tables->Plan.count;i++)n->Tables->Buffer[i].MapAttempted=TRUE;
 OSMA_REQUEST q=Request(n);enum osma_status s=OsmaActivate(&n->Tables->Session,&q);
 if(s==OSMA_OK){for(ULONG i=0;i<n->Tables->Plan.count;i++)n->Tables->Buffer[i].Mapped=TRUE;return STATUS_SUCCESS;}
 if(n->Tables->Session.Writes)n->Tables->Poisoned=TRUE;else{n->Tables->ActivationAttempted=FALSE;for(ULONG i=0;i<n->Tables->Plan.count;i++)n->Tables->Buffer[i].MapAttempted=FALSE;}
 return s==OSMA_TIMEOUT?STATUS_IO_TIMEOUT:STATUS_DEVICE_NOT_READY;
}
NTSTATUS OsmaDisableOwnedBindingStopped(OSMA_NATIVE_IO*n,ULONGLONG fresh){
 if(!n||!n->Base||!n->Tables||n->Tables->Poisoned)return STATUS_INVALID_DEVICE_STATE;
 if(fresh<=n->Tables->Session.ActivationStopSerial)return STATUS_INVALID_DEVICE_STATE;
 n->Proof.StopSerial=fresh;OSMA_REQUEST q=Request(n);enum osma_status s=OsmaDisableStopped(&n->Tables->Session,&q);
 if(s!=OSMA_OK){n->Tables->Poisoned=TRUE;return s==OSMA_TIMEOUT?STATUS_IO_TIMEOUT:STATUS_DEVICE_BUSY;}
 n->Tables->Disabled=TRUE;for(ULONG i=0;i<n->Tables->Plan.count;i++)n->Tables->Buffer[i].Mapped=FALSE;return STATUS_SUCCESS;
}
NTSTATUS OsmaCloseNativeIo(OSMA_NATIVE_IO*n){
 if(!n||!n->Base||!n->Tables)return STATUS_INVALID_DEVICE_STATE;
 if(n->Tables->Poisoned||n->Tables->Session.MustRetain||
    (n->Tables->ActivationAttempted&&!n->Tables->Disabled))return STATUS_DEVICE_BUSY;
 MmUnmapIoSpace(n->Base,0x40000);ObDereferenceObject(n->Pdo);InterlockedDecrement(&n->Tables->References);RtlZeroMemory(n,sizeof(*n));return STATUS_SUCCESS;
}
NTSTATUS OsmaFreeRetiredBinding(OSMA_TABLE_BINDING*b){
 if(!b||KeGetCurrentIrql()!=PASSIVE_LEVEL||b->Poisoned||b->Session.MustRetain||(b->ActivationAttempted&&!b->Disabled))return STATUS_DEVICE_BUSY;
 if(InterlockedCompareExchange(&b->References,0,1)!=1)return STATUS_DEVICE_BUSY;
 NTSTATUS st=OsmiDestroyInactive(&b->Tables);if(st!=STATUS_SUCCESS){b->Poisoned=TRUE;InterlockedExchange(&b->References,1);return st;}
 for(ULONG i=0;i<b->Plan.count;i++){G321_BUFFER*m=&b->Buffer[i];if(m->Cpu)MmUnmapLockedPages(m->Cpu,m->Mdl);if(m->Mdl){MmFreePagesFromMdl(m->Mdl);ExFreePool(m->Mdl);}}
 if(b->ImageCopy)ExFreePoolWithTag(b->ImageCopy,'In3G');ObDereferenceObject(b->ConsumerPdo);ExFreePoolWithTag(b,TAG);return STATUS_SUCCESS;
}
NTSTATUS OsmaWitnessOwnedBindingHeld(OSMA_NATIVE_IO*n){if(!n||!n->Base||!n->Tables||n->Tables->Poisoned)return STATUS_INVALID_DEVICE_STATE;OSMA_REQUEST q=Request(n);return OsmaWitnessActiveHeld(&n->Tables->Session,&q)==OSMA_OK?STATUS_SUCCESS:STATUS_DEVICE_HARDWARE_ERROR;}
