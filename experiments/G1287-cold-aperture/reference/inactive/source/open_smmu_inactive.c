/* SPDX-License-Identifier: MIT */
#include "open_smmu_inactive.h"
#define TAG 'ImSO'
static VOID FreeKnown(OSMI_TABLES*t){
 if(t->Pool)MmFreeContiguousMemory(t->Pool);
 if(t->Visited)ExFreePoolWithTag(t->Visited,TAG);
 if(t->Ranges)ExFreePoolWithTag(t->Ranges,TAG);
 t->Pool=NULL;t->Visited=NULL;t->Ranges=NULL;t->PoolBytes=0;t->RangeCount=0;
 t->PoolPhysical.QuadPart=0;t->PoolOrigin=0;RtlZeroMemory(&t->Config,sizeof(t->Config));
 RtlZeroMemory(&t->Tables,sizeof(t->Tables));RtlZeroMemory(&t->Audit,sizeof(t->Audit));
}
VOID OsmiInitialize(OSMI_TABLES*t){if(t)RtlZeroMemory(t,sizeof(*t));}
static int ReadDescriptor(void*cookie,uint64_t pa,uint64_t*out){
 OSMI_TABLES*t=cookie;UINT64 start=(UINT64)t->PoolPhysical.QuadPart;
 if(!out||!t->Pool||pa<start||(pa&7)||pa-start>t->PoolBytes-8)return -1;
 /* This VA->PA relation was checked for every allocator-returned pool page.
  * No physical-address cast, identity mapping, MMIO or generated shadow read. */
 *out=*(volatile UINT64*)((PUCHAR)t->Pool+(SIZE_T)(pa-start));return 0;
}
NTSTATUS OsmiAuditInactive(OSMI_TABLES*t){
 if(!t||KeGetCurrentIrql()!=PASSIVE_LEVEL||
    (t->State!=OSMI_BUILDING&&t->State!=OSMI_BUILT)||!t->Pool||!t->Ranges||!t->Visited)
  return STATUS_INVALID_DEVICE_STATE;
 ArmSmmu4KTableIo io={t,ReadDescriptor};
 ArmSmmu4KAuditRegion region={t->Ranges,t->RangeCount,t->PoolBytes/4096,
   (t->PoolBytes/4096)*512,t->Visited,t->PoolBytes/4096};
 if(ArmSmmu4KAuditTables(&io,&t->Config,&t->Tables,&region,
      (UINT64)t->PoolPhysical.QuadPart,&t->Audit)!=ArmSmmu4KSuccess){
  t->State=OSMI_POISONED;return t->Status=STATUS_DATA_ERROR;
 }
 return t->Status=STATUS_SUCCESS;
}
NTSTATUS OsmiBuildInactive(OSMI_TABLES*t,const OSMI_INPUT*in,ULONG count){
 ULONG order[OSMI_MAX_INPUTS];SIZE_T leaves=0,pages=1,k=0;
 UINT64 last1=MAXULONGLONG,last2=MAXULONGLONG;NTSTATUS st=STATUS_INVALID_PARAMETER;
 if(!t||!in||!count||count>OSMI_MAX_INPUTS||KeGetCurrentIrql()!=PASSIVE_LEVEL||
    PAGE_SIZE!=4096||t->State!=OSMI_NEW)return STATUS_INVALID_PARAMETER;
 /* Validate borrowed MDL objects before allocating any table storage. Only
  * genuine caller-owned locked MDLs are supported, never arbitrary PFN lists. */
 for(ULONG i=0;i<count;i++){
  if(!in[i].Mdl||!(in[i].Mdl->MdlFlags&MDL_PAGES_LOCKED)||
     MmGetMdlByteOffset(in[i].Mdl)||!in[i].Bytes||(in[i].Bytes&4095)||
     MmGetMdlByteCount(in[i].Mdl)!=in[i].Bytes||(in[i].Iova&4095)||
     in[i].Iova>=(UINT64_C(1)<<39)||in[i].Bytes>(UINT64_C(1)<<39)-in[i].Iova||
     in[i].Bytes/4096>OSMI_MAX_LEAVES-leaves)return STATUS_INVALID_PARAMETER;
  for(ULONG j=0;j<i;j++)if(in[i].Mdl==in[j].Mdl)return STATUS_INVALID_PARAMETER;
  leaves+=in[i].Bytes/4096;order[i]=i;
 }
 for(ULONG i=1;i<count;i++){ULONG n=order[i],j=i;while(j&&in[order[j-1]].Iova>in[n].Iova){order[j]=order[j-1];--j;}order[j]=n;}
 for(ULONG j=0;j<count;j++){
  ULONG i=order[j];if(j&&in[order[j-1]].Iova+in[order[j-1]].Bytes>in[i].Iova)return STATUS_CONFLICTING_ADDRESSES;
  PPFN_NUMBER pfns=MmGetMdlPfnArray(in[i].Mdl);
  for(SIZE_T n=0;n<in[i].Bytes/4096;n++)if((UINT64)pfns[n]>=OSMI_PA_LIMIT/4096)return STATUS_CONFLICTING_ADDRESSES;
 }
 t->State=OSMI_BUILDING;
 t->Ranges=ExAllocatePool2(POOL_FLAG_NON_PAGED,leaves*sizeof(*t->Ranges),TAG);
 if(!t->Ranges){st=STATUS_INSUFFICIENT_RESOURCES;goto known_failure;}
 for(ULONG j=0;j<count;j++){
  ULONG i=order[j];PPFN_NUMBER pfns=MmGetMdlPfnArray(in[i].Mdl);
  for(SIZE_T n=0;n<in[i].Bytes/4096;n++){
   UINT64 va=in[i].Iova+n*4096;
   /* Explicit INACTIVE candidate: Open gen7 kernel-block READ|WRITE|PRIV,
    * normal-NC data matches our NC MDL backing; no active TCR/MAIR claim.
    * Execute allowed here reflects absence of IOMMU_NOEXEC in that source.
    * No raw vendor permission flags are consumed anywhere. */
   t->Ranges[k++]=(ArmSmmu4KRange){va,(UINT64)pfns[n]*4096,4096,
      ArmSmmu4KRead|ArmSmmu4KWrite|ArmSmmu4KExecute|ArmSmmu4KPrivileged,0,2};
   if((va>>30)!=last1){++pages;last1=va>>30;}
   if((va>>21)!=last2){++pages;last2=va>>21;}
  }
 }
 t->RangeCount=leaves;t->PoolBytes=pages*4096;
 PHYSICAL_ADDRESS low={0},high,boundary={0};high.QuadPart=(LONGLONG)(OSMI_PA_LIMIT-1);
 t->Pool=MmAllocateContiguousMemorySpecifyCache(t->PoolBytes,low,high,boundary,MmNonCached);
 if(!t->Pool){st=STATUS_INSUFFICIENT_RESOURCES;goto known_failure;}
 t->PoolCache=MmNonCached;t->PoolOrigin=0x4e435047u;
 t->PoolPhysical=MmGetPhysicalAddress(t->Pool);
 if(((ULONG_PTR)t->Pool&4095)||(t->PoolPhysical.QuadPart&4095)||
    (UINT64)t->PoolPhysical.QuadPart>=OSMI_PA_LIMIT||
    t->PoolBytes>OSMI_PA_LIMIT-(UINT64)t->PoolPhysical.QuadPart){st=STATUS_CONFLICTING_ADDRESSES;goto known_failure;}
 for(SIZE_T n=0;n<pages;n++){
  PHYSICAL_ADDRESS actual=MmGetPhysicalAddress((PUCHAR)t->Pool+n*4096);
  if(actual.QuadPart!=t->PoolPhysical.QuadPart+(LONGLONG)(n*4096)){st=STATUS_CONFLICTING_ADDRESSES;goto known_failure;}
 }
 t->Visited=ExAllocatePool2(POOL_FLAG_NON_PAGED,pages,TAG);
 if(!t->Visited){st=STATUS_INSUFFICIENT_RESOURCES;goto known_failure;}
 t->Config=(ArmSmmu4KConfig){39,36,(UINT64)t->PoolPhysical.QuadPart,OSMI_MAX_LEAVES};
 if(ArmSmmu4KBuild(&t->Config,t->Ranges,leaves,t->Pool,pages,&t->Tables)!=ArmSmmu4KSuccess){st=STATUS_DATA_ERROR;goto known_failure;}
 st=OsmiAuditInactive(t);if(st!=STATUS_SUCCESS)return st; /* Retain corrupt/uncertain pool. */
 t->State=OSMI_BUILT;t->ActivationQualified=FALSE;return t->Status=STATUS_SUCCESS;
known_failure:
 /* No root has been published and allocator ownership is known. This is
  * pre-activation cleanup, never an inferred DMA/TLB rollback. */
 FreeKnown(t);t->State=OSMI_CLOSED;return t->Status=st;
}
NTSTATUS OsmiDestroyInactive(OSMI_TABLES*t){
 if(!t||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_DEVICE_STATE;
 if(t->State==OSMI_POISONED||t->ActivationQualified)return STATUS_DEVICE_BUSY;
 if(t->State!=OSMI_BUILT&&t->State!=OSMI_NEW&&t->State!=OSMI_CLOSED)return STATUS_INVALID_DEVICE_STATE;
 if(t->State==OSMI_BUILT&&OsmiAuditInactive(t)!=STATUS_SUCCESS)return t->Status;
 FreeKnown(t);t->State=OSMI_CLOSED;return t->Status=STATUS_SUCCESS;
}
