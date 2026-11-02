/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include "g321_inactive.h"
#define TAG 'In3G'
static NTSTATUS Lock(G321_INACTIVE_RUNTIME*r){LARGE_INTEGER timeout;timeout.QuadPart=-500000;
 if(!r||!r->Initialized||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_DEVICE_STATE;
 return KeWaitForSingleObject(&r->Lock,Executive,KernelMode,FALSE,&timeout);
}
static NTSTATUS Enter(G321_INACTIVE_RUNTIME*r){NTSTATUS st=r->Owner.Enter(r->Owner.Cookie,r->Generation);
 if(st!=STATUS_SUCCESS)return st;st=r->Owner.Lease(r->Owner.Cookie,r->Generation);
 if(st!=STATUS_SUCCESS)r->Owner.Leave(r->Owner.Cookie);return st;
}
VOID G321InactiveInitialize(G321_INACTIVE_RUNTIME*r){
 if(!r)return;RtlZeroMemory(r,sizeof(*r));KeInitializeMutex(&r->Lock,0);
 r->Initialized=TRUE;r->LastStatus=STATUS_DEVICE_NOT_READY;OsmiInitialize(&r->Tables);
}
NTSTATUS G321PrepareInactive(G321_INACTIVE_RUNTIME*r,const G321_OWNER*owner,
 const g196_inputs*inputs,ULONGLONG generation,ULONGLONG serial){
 NTSTATUS st=Lock(r);BOOLEAN entered=FALSE;OSMI_INPUT maps[G321_MAX_EXTENTS];
 if(st!=STATUS_SUCCESS)return st;
 if(r->Attempted||r->Closed||!owner||!owner->Enter||!owner->Leave||!owner->Lease||
    !owner->Stopped||!inputs||!generation||!serial){st=STATUS_INVALID_PARAMETER;goto done;}
 if(g196_prepare(inputs,&r->Inputs)!=G196_INPUTS_MATCH){st=STATUS_INVALID_IMAGE_HASH;goto done;}
 r->Owner=*owner;r->Generation=generation;r->StopSerial=serial;
 st=Enter(r);if(st!=STATUS_SUCCESS)goto done;entered=TRUE;
 st=r->Owner.Stopped(r->Owner.Cookie,serial,generation);if(st!=STATUS_SUCCESS)goto done;
 r->Attempted=TRUE; /* From here every allocation is retained in this ledger. */
 r->ImageCopy=ExAllocatePool2(POOL_FLAG_NON_PAGED,r->Inputs.image.size,TAG);
 if(!r->ImageCopy){st=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 RtlCopyMemory(r->ImageCopy,r->Inputs.image.bytes,r->Inputs.image.size);
 r->Inputs.image.bytes=r->ImageCopy;
 if(g321_plan_image(&r->Inputs.image,&r->Plan)!=G190_OK){st=STATUS_INVALID_IMAGE_HASH;goto done;}
 if(!r->Plan.count||r->Plan.count>OSMI_MAX_INPUTS||!r->Plan.total_bytes||
    r->Plan.total_bytes>(SIZE_T)OSMI_MAX_LEAVES*4096){st=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 for(ULONG i=0;i<r->Plan.count;i++){
  G321_BUFFER*b=&r->Buffer[i];const g321_extent*e=&r->Plan.extent[i];
  PHYSICAL_ADDRESS low={0},high,skip={0};high.QuadPart=(LONGLONG)(OSMI_PA_LIMIT-1);
  st=r->Owner.Lease(r->Owner.Cookie,generation);if(st!=STATUS_SUCCESS){r->Poisoned=TRUE;goto done;}
  b->Mdl=MmAllocatePagesForMdlEx(low,high,skip,e->bytes,MmNonCached,MM_ALLOCATE_FULLY_REQUIRED);
  if(!b->Mdl){st=STATUS_INSUFFICIENT_RESOURCES;goto done;}
  r->AllocatedNcMask|=1u<<i;r->AllocationCache[i]=MmNonCached;
  if(!(b->Mdl->MdlFlags&MDL_PAGES_LOCKED)||MmGetMdlByteOffset(b->Mdl)||MmGetMdlByteCount(b->Mdl)!=e->bytes){st=STATUS_DEVICE_CONFIGURATION_ERROR;goto done;}
  b->Cpu=MmMapLockedPagesSpecifyCache(b->Mdl,KernelMode,MmNonCached,NULL,FALSE,NormalPagePriority|MdlMappingNoExecute);
  if(!b->Cpu){st=STATUS_INSUFFICIENT_RESOURCES;goto done;}
  r->MappedNcMask|=1u<<i;r->MappingCache[i]=MmNonCached;
  RtlZeroMemory(b->Cpu,e->bytes);
  /* This path owns the actual NC allocator result. OsmiBuildInactive checks
   * its locked MDL/PFNs/PA bounds directly. The old ValidateBacking domain
   * callback is not called: no native domain/cache-walk policy is claimed. */
  maps[i]=(OSMI_INPUT){b->Mdl,e->iova,e->bytes};
  /* MapAttempted/Mapped remain FALSE: no active address space exists. */
 }
 st=OsmiBuildInactive(&r->Tables,maps,r->Plan.count);
 if(st!=STATUS_SUCCESS){if(r->Tables.State==OSMI_POISONED)r->Poisoned=TRUE;goto done;}
 /* Revalidate source ownership before returning the retained inactive image.
  * No G482 board MMIO, g190 initialization, HAL role, attach or GMU start. */
 st=r->Owner.Lease(r->Owner.Cookie,generation);
 if(st!=STATUS_SUCCESS){r->Poisoned=TRUE;goto done;}
 st=r->Owner.Stopped(r->Owner.Cookie,serial,generation);
 if(st!=STATUS_SUCCESS){r->Poisoned=TRUE;goto done;}
 r->TablesPrepared=TRUE;st=STATUS_SUCCESS;
done:
 if(entered)r->Owner.Leave(r->Owner.Cookie);r->LastStatus=st;KeReleaseMutex(&r->Lock,FALSE);return st;
}
NTSTATUS G321ReleaseInactiveStopped(G321_INACTIVE_RUNTIME*r,ULONGLONG serial){
 NTSTATUS st=Lock(r);BOOLEAN entered=FALSE;if(st!=STATUS_SUCCESS)return st;
 if(!r->Attempted||r->Closed||r->Poisoned||serial<=r->StopSerial){st=STATUS_DEVICE_BUSY;goto done;}
 st=Enter(r);if(st!=STATUS_SUCCESS)goto done;entered=TRUE;
 st=r->Owner.Stopped(r->Owner.Cookie,serial,r->Generation);if(st!=STATUS_SUCCESS)goto done;
 st=OsmiDestroyInactive(&r->Tables);if(st!=STATUS_SUCCESS){r->Poisoned=TRUE;goto done;}
 /* Tables retired first. Each original allocator-owned MDL is freed exactly
  * once afterward; borrowed mappings/refcount guesses are never substituted. */
 for(ULONG i=0;i<r->Plan.count;i++){
  G321_BUFFER*b=&r->Buffer[i];if(b->Cpu)MmUnmapLockedPages(b->Cpu,b->Mdl);
  if(b->Mdl){MmFreePagesFromMdl(b->Mdl);ExFreePool(b->Mdl);}RtlZeroMemory(b,sizeof(*b));
 }
 if(r->ImageCopy)ExFreePoolWithTag(r->ImageCopy,TAG);r->ImageCopy=NULL;
 r->StopSerial=serial;r->TablesPrepared=FALSE;r->Closed=TRUE;st=STATUS_SUCCESS;
done:
 if(entered)r->Owner.Leave(r->Owner.Cookie);r->LastStatus=st;KeReleaseMutex(&r->Lock,FALSE);return st;
}
NTSTATUS G321InactiveActivationStatus(const G321_INACTIVE_RUNTIME*r){
 UNREFERENCED_PARAMETER(r);return STATUS_NOT_SUPPORTED;
}
