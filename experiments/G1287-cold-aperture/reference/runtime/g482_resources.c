/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Actual Windows mapping/IO for exact nonoverlapping source device grants. */
#include "g482_resources.h"
#include "g290_power_report.h"
#include "g323_clock_policy.h"
#include "g482_mmio_policy.h"
#include <intrin.h>
static const ULONGLONG Base[G482_BANKS]={0x03d00000,0x03d50000,0x03d68000,0x03d9a000,0x0b280000};
static const ULONG Bytes[G482_BANKS]={0x40000,0x10000,0x28000,0x5000,0x10000};
VOID G482Initialize(G482_BINDING*b){RtlZeroMemory(b,sizeof(*b));b->Initialized=TRUE;b->MissingMask=31;b->Status=STATUS_RESOURCE_TYPE_NOT_FOUND;}
NTSTATUS G482Bind(G482_BINDING*b,PDEVICE_OBJECT pdo,PCM_RESOURCE_LIST resources){
 NTSTATUS s=STATUS_RESOURCE_TYPE_NOT_FOUND;ULONG seen=0,extra=0;
 if(!b||!b->Initialized||b->Bound||b->MappedMask||!pdo||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_DEVICE_STATE;
 b->SeenMask=0;b->MissingMask=31;b->ObservedDescriptors=0;
 if(!resources||resources->Count!=1)goto done;
 PCM_PARTIAL_RESOURCE_LIST list=&resources->List[0].PartialResourceList;b->ObservedDescriptors=list->Count;
 if(list->Count>16){s=STATUS_DEVICE_CONFIGURATION_ERROR;goto done;}
 for(ULONG i=0;i<list->Count;i++){
  PCM_PARTIAL_RESOURCE_DESCRIPTOR d=&list->PartialDescriptors[i];ULONG bank=G482_BANKS;
  if(d->Type!=CmResourceTypeMemory){s=STATUS_DEVICE_CONFIGURATION_ERROR;goto done;}
  for(ULONG j=0;j<G482_BANKS;j++)if((ULONGLONG)d->u.Memory.Start.QuadPart==Base[j]&&d->u.Memory.Length==Bytes[j])bank=j;
  if(bank==G482_BANKS){extra++;continue;} /* Complete validation below refuses extras. */
  if(seen&(1u<<bank)){s=STATUS_DEVICE_CONFIGURATION_ERROR;goto done;}
  if(d->Flags!=CM_RESOURCE_MEMORY_READ_WRITE||
   (d->ShareDisposition!=CmResourceShareDeviceExclusive&&d->ShareDisposition!=CmResourceShareDriverExclusive)){s=STATUS_DEVICE_CONFIGURATION_ERROR;goto done;}
  seen|=1u<<bank;
 }
 b->SeenMask=seen;b->MissingMask=31u&~seen;
 if(seen!=31)goto done;
 if(extra||list->Count!=G482_BANKS){s=STATUS_DEVICE_CONFIGURATION_ERROR;goto done;}
 /* Nothing above performs target IO. Only actual complete OS assignments
  * can reach mapping; no PA supplied separately by a caller is admitted. */
 for(ULONG i=0;i<G482_BANKS;i++){
  PHYSICAL_ADDRESS pa;pa.QuadPart=(LONGLONG)Base[i];
  b->Cpu[i]=MmMapIoSpaceEx(pa,Bytes[i],G482_MAP_PROTECTION(i));
  if(!b->Cpu[i]){s=STATUS_INSUFFICIENT_RESOURCES;goto rollback;}
  b->MappedMask|=1u<<i;
 }
#if OGO_GPU_MMIO_WRITECOMBINE
 /* All five CPU views exist, but no target IO or DMA starts here. This early
  * marker supports a short, image-qualified PTE observation before use. */
 DbgPrintEx(DPFLTR_IHVVIDEO_ID,DPFLTR_INFO_LEVEL,
  "G1322 GPU_MAP bank0 va%p bytes%lx requested%lx beforeTargetIo1\n",
  b->Cpu[G482_GPU],Bytes[G482_GPU],(ULONG)G482_MAP_PROTECTION(G482_GPU));
#endif
 b->Pdo=pdo;ObReferenceObject(pdo);b->Bound=TRUE;s=STATUS_SUCCESS;goto done;
rollback:
 /* No IO/owner can use a partially constructed binding. Unmap only the
  * CPU views; no device store, allocator backing or DMA state is unwound. */
 for(ULONG i=0;i<G482_BANKS;i++)if(b->Cpu[i]){MmUnmapIoSpace(b->Cpu[i],Bytes[i]);b->Cpu[i]=NULL;}b->MappedMask=0;
done:b->Status=s;return s;
}
NTSTATUS G482Release(G482_BINDING*b){
 if(!b||!b->Initialized||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_DEVICE_STATE;
 for(ULONG i=0;i<G482_BANKS;i++)if(b->Cpu[i]){MmUnmapIoSpace(b->Cpu[i],Bytes[i]);b->Cpu[i]=NULL;}
 if(b->Pdo)ObDereferenceObject(b->Pdo);b->Pdo=NULL;b->Bound=FALSE;b->MappedMask=0;return b->Status=STATUS_SUCCESS;
}
static NTSTATUS Access(G482_BINDING*b,ULONG bank,ULONG off,PULONG v,BOOLEAN write){
 if(!b||!b->Bound||b->MappedMask!=31||!v||KeGetCurrentIrql()!=PASSIVE_LEVEL||bank>=G482_BANKS||!b->Cpu[bank]||(off&3)||off>Bytes[bank]-4)return STATUS_RESOURCE_TYPE_NOT_FOUND;
 PULONG at=(PULONG)((PUCHAR)b->Cpu[bank]+off);
 if(write){WRITE_REGISTER_ULONG(at,*v);__dsb(_ARM64_BARRIER_OSH);}else *v=READ_REGISTER_ULONG(at);
 return STATUS_SUCCESS;
}
NTSTATUS G482GpuRead(G482_BINDING*b,ULONG o,PULONG v){return Access(b,G482_GPU,o,v,FALSE);}
NTSTATUS G482GpuWrite(G482_BINDING*b,ULONG o,ULONG v){return Access(b,G482_GPU,o,&v,TRUE);}
static NTSTATUS Core(G482_BINDING*b,ULONG o,PULONG v,BOOLEAN write){
 if(o>0x34ffc)return STATUS_ACCESS_DENIED;
 ULONG relative=o+0x2000;
 if(relative<0x28000)return Access(b,G482_GMU_LOW,relative,v,write);
 if(relative>=0x32000)return Access(b,G482_GMU_HIGH,relative-0x32000,v,write);
 /* No read or write view exists for the GPUCC03d90000/a000 hole. */
 return STATUS_ACCESS_DENIED;
}
NTSTATUS G482CoreRead(G482_BINDING*b,ULONG o,PULONG v){return Core(b,o,v,FALSE);}
NTSTATUS G482CoreWrite(G482_BINDING*b,ULONG o,ULONG v){return Core(b,o,&v,TRUE);}
NTSTATUS G482TcmRead(G482_BINDING*b,ULONG region,ULONG o,PULONG v){if((region!=1&&region!=3)||o>0x3ffc)return STATUS_ACCESS_DENIED;return G482CoreRead(b,(region==1?0x3000:0x7000)+o,v);}
NTSTATUS G482TcmWrite(G482_BINDING*b,ULONG region,ULONG o,ULONG v){if((region!=1&&region!=3)||o>0x3ffc)return STATUS_ACCESS_DENIED;return G482CoreWrite(b,(region==1?0x3000:0x7000)+o,v);}
NTSTATUS G482RscRead(G482_BINDING*b,ULONG o,PULONG v){return Access(b,G482_RSCC,o,v,FALSE);}
NTSTATUS G482RscWrite(G482_BINDING*b,ULONG o,ULONG v){return Access(b,G482_RSCC,o,&v,TRUE);}
NTSTATUS G482PdcRead(G482_BINDING*b,ULONG o,PULONG v){return Access(b,G482_PDC,o,v,FALSE);}
NTSTATUS G482PdcWrite(G482_BINDING*b,ULONG o,ULONG v){return Access(b,G482_PDC,o,&v,TRUE);}
NTSTATUS G482CxRead(G482_BINDING*b,ULONG o,PULONG v){if(o>0xffc)return STATUS_ACCESS_DENIED;return Access(b,G482_GMU_HIGH,0x4000+o,v,FALSE);}
NTSTATUS G482CxWrite(G482_BINDING*b,ULONG o,ULONG v){if(o>0xffc)return STATUS_ACCESS_DENIED;return Access(b,G482_GMU_HIGH,0x4000+o,&v,TRUE);}
NTSTATUS G482ReadClock(G482_BINDING*b,ULONGLONG pa,PULONG v){
 UNREFERENCED_PARAMETER(b);UNREFERENCED_PARAMETER(v);
 static const ULONGLONG known[]={0x171004,0x03d99108,0x03d9953c,0x171010,0x171018,0x03d9911c,0x03d97000};
 for(ULONG i=0;i<RTL_NUMBER_OF(known);i++)if(pa==known[i])return STATUS_NOT_SUPPORTED;
 return STATUS_ACCESS_DENIED;
}
NTSTATUS G482RequirePoweredHandoff(G482_BINDING*b){
 UNREFERENCED_PARAMETER(b);
 /* Firmware reports do not establish a current Windows clock lease. The
  * new split grants intentionally cannot serve legacy direct clock readers.
  * Real MMU1 + all-six-GMU power/clock ownership must replace that callsite
  * before any GMU register access; no synthesized success fallback exists. */
 return STATUS_NOT_SUPPORTED;
}
