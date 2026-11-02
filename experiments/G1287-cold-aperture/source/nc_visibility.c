#include "nc_visibility.h"
#include <intrin.h>
NTSTATUS OasMakeNcVisible(OSMA_TABLE_BINDING*b){
 if(!b||KeGetCurrentIrql()!=PASSIVE_LEVEL||b->Poisoned||b->References<=0||!b->Plan.count||b->Plan.count>G321_MAX_EXTENTS||b->Plan.count>16)return STATUS_INVALID_DEVICE_STATE;
 OSMI_TABLES*t=&b->Tables;ULONG mask=(1u<<b->Plan.count)-1;
 if(b->AllocatedNcMask!=mask||b->MappedNcMask!=mask||t->PoolOrigin!=0x4e435047u||t->PoolCache!=MmNonCached||!t->Pool||!t->PoolBytes||(t->PoolBytes&4095)||t->PoolBytes/4096>OSMI_MAX_LEAVES||t->State!=OSMI_BUILT||t->Config.input_bits!=39||t->Config.output_bits!=36||t->Config.table_physical!=(UINT64)t->PoolPhysical.QuadPart||t->Tables.root_physical!=t->Config.table_physical||t->Tables.mair!=0xff44)return STATUS_DEVICE_CONFIGURATION_ERROR;
 UINT64 base=(UINT64)t->PoolPhysical.QuadPart;if((base&4095)||base>=OSMI_PA_LIMIT||t->PoolBytes>OSMI_PA_LIMIT-base)return STATUS_CONFLICTING_ADDRESSES;
 for(SIZE_T i=0;i<t->PoolBytes/4096;i++)if((UINT64)MmGetPhysicalAddress((PUCHAR)t->Pool+i*4096).QuadPart!=base+i*4096)return STATUS_DATA_ERROR;
 ULONG order[16];for(ULONG i=0;i<b->Plan.count;i++)order[i]=i;
 for(ULONG i=1;i<b->Plan.count;i++){ULONG n=order[i],j=i;while(j&&b->Plan.extent[order[j-1]].iova>b->Plan.extent[n].iova){order[j]=order[j-1];j--;}order[j]=n;}
 SIZE_T expected=0;
 for(ULONG oi=0;oi<b->Plan.count;oi++){ULONG i=order[oi];
  G321_BUFFER*m=&b->Buffer[i];SIZE_T bytes=b->Plan.extent[i].bytes;
  if(b->AllocationCache[i]!=MmNonCached||b->MappingCache[i]!=MmNonCached||!m->Mdl||!m->Cpu||!(m->Mdl->MdlFlags&MDL_PAGES_LOCKED)||MmGetMdlByteOffset(m->Mdl)||!bytes||(bytes&4095)||MmGetMdlByteCount(m->Mdl)!=bytes||((ULONG_PTR)m->Cpu&4095)||bytes/4096>OSMI_MAX_LEAVES-expected)return STATUS_DEVICE_CONFIGURATION_ERROR;
  if(m->Mapped&&!b->ActivationAttempted)return STATUS_DATA_ERROR;
  PPFN_NUMBER pfns=MmGetMdlPfnArray(m->Mdl);
  for(SIZE_T j=0;j<bytes/4096;j++){
   UINT64 pa=(UINT64)pfns[j]*4096,va=b->Plan.extent[i].iova+j*4096;if((UINT64)pfns[j]>=OSMI_PA_LIMIT/4096||(pa>=base&&pa-base<t->PoolBytes)||(UINT64)MmGetPhysicalAddress((PUCHAR)m->Cpu+j*4096).QuadPart!=pa)return STATUS_CONFLICTING_ADDRESSES;
   if(expected+j>=t->RangeCount)return STATUS_DATA_ERROR;ArmSmmu4KRange*r=&t->Ranges[expected+j];if(r->iova!=va||r->physical!=pa||r->bytes!=4096||r->permissions!=15||r->writeback||r->shareability!=2)return STATUS_DATA_ERROR;
  }expected+=bytes/4096;
 }
 if(t->RangeCount!=expected)return STATUS_DATA_ERROR;
 for(ULONG i=b->Plan.count;i<G321_MAX_EXTENTS;i++)if(b->Buffer[i].Mdl||b->Buffer[i].Cpu||b->Buffer[i].MapAttempted||b->Buffer[i].Mapped)return STATUS_DATA_ERROR;
 NTSTATUS st=OsmiAuditInactive(t);if(st!=STATUS_SUCCESS){b->Poisoned=TRUE;return st;}
 /* These exact pages came from NC allocation + NC mapping. No random cached
  * buffer is presumed flushed. The source fixed walker/image contract is
  * separately checked by the activation core; pages remain immutable/pinned. */
 __dsb(_ARM64_BARRIER_OSHST);KeMemoryBarrier();return STATUS_SUCCESS;
}
