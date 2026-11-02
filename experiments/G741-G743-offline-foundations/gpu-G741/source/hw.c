/* SPDX-License-Identifier: MIT
 * Original Open/A740 experimental backend. Replaces (does not modify) donor
 * A610 hw.c. No PAS, SMMU register, reset, GPU ring or synthesized completion.
 */
#include "tgpu.h"
#include "a740_backend.h"
#include <intrin.h>
static struct {
    KMUTEX Lock; A740_HAL Hal; A740_HAL_ROLE Gpu,Gmu;
    PDEVICE_OBJECT Pdo; PCM_RESOURCE_LIST Resources;
    NTSTATUS Status; BOOLEAN Bound, RolesOpened, MastersStarted, CpReady;
    ULONGLONG ChipId, NextVa;
} g_A740;
VOID HwInit(VOID)
{
    RtlZeroMemory(&g_A740,sizeof(g_A740));KeInitializeMutex(&g_A740.Lock,0);
    g_A740.Status=STATUS_DEVICE_NOT_READY;g_A740.NextVa=TGPU_VA_USER_START;
}
NTSTATUS A740LastStatus(VOID) { return g_A740.Status; }
ULONGLONG A740ChipId(VOID) { return g_A740.ChipId; }
NTSTATUS A740GpuId(PULONGLONG Value)
{
    if(!Value||!g_A740.ChipId) return STATUS_DEVICE_NOT_READY;
    *Value=740;return STATUS_SUCCESS;
}
NTSTATUS A740BindDevice(PDEVICE_OBJECT Pdo,PCM_RESOURCE_LIST Resources)
{
    NTSTATUS st;SIZE_T bytes=0;
    if(!Pdo||KeGetCurrentIrql()!=PASSIVE_LEVEL||g_A740.Bound)
        return STATUS_INVALID_PARAMETER;
    if(Resources&&Resources->Count>16) return STATUS_DEVICE_CONFIGURATION_ERROR;
    /* Retain the actual variable-sized translated list, not PnP stack storage.
     * DeviceSpecific payloads are not part of this GPU composition. */
    for(ULONG i=0;Resources&&i<Resources->Count;++i) {
        PCM_PARTIAL_RESOURCE_LIST p=&Resources->List[i].PartialResourceList;
        if(p->Count>256) return STATUS_DEVICE_CONFIGURATION_ERROR;
        for(ULONG j=0;j<p->Count;++j)
            if(p->PartialDescriptors[j].Type==CmResourceTypeDeviceSpecific)
                return STATUS_DEVICE_CONFIGURATION_ERROR;
        bytes+=FIELD_OFFSET(CM_FULL_RESOURCE_DESCRIPTOR,PartialResourceList.PartialDescriptors)+
               (SIZE_T)p->Count*sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR);
        /* CM_RESOURCE_LIST is variable-sized; this initial path requires one
         * full descriptor, rather than indexing an arbitrary packed list. */
        if(Resources->Count!=1) return STATUS_DEVICE_CONFIGURATION_ERROR;
    }
    if(bytes) {
    bytes+=FIELD_OFFSET(CM_RESOURCE_LIST,List);
    g_A740.Resources=ExAllocatePool2(POOL_FLAG_NON_PAGED,bytes,TGPU_POOL_TAG);
    if(!g_A740.Resources) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(g_A740.Resources,Resources,bytes);
    }
    g_A740.Pdo=Pdo;ObReferenceObject(Pdo);g_A740.Bound=TRUE;
    st=A740RequirePoweredHandoff(Resources);
    if(NT_SUCCESS(st)) st=A740HalDiscover(&g_A740.Hal,Pdo);
    g_A740.Status=st;
    LogPrint("A740 HAL discover phase %u status %08x inputs %u\n",
        g_A740.Hal.Report.Phase,st,g_A740.Hal.Report.Count);
    for(ULONG i=0;i<g_A740.Hal.Report.Count;++i) {
        const A740_HAL_INPUT *r=&g_A740.Hal.Report.Input[i];
        LogPrint("A740 input %08x attempted %u types %08x create %08x delete %08x\n",
            r->InputId,r->Attempted,r->AvailableDomainTypes,r->CreateStatus,r->DeleteStatus);
    }
    /* No SMMU attach and no GPUCC read occurs at this callpoint. */
    return st;
}
NTSTATUS A740ReleaseProbe(VOID)
{
    if(KeGetCurrentIrql()!=PASSIVE_LEVEL||g_A740.Hal.ProbeRetained||
       g_A740.Gpu.Hal||g_A740.Gmu.Hal||g_A740.MastersStarted)
        return STATUS_DEVICE_BUSY;
    if(g_A740.Resources) ExFreePoolWithTag(g_A740.Resources,TGPU_POOL_TAG);
    if(g_A740.Pdo) ObDereferenceObject(g_A740.Pdo);
    g_A740.Resources=NULL;g_A740.Pdo=NULL;g_A740.Bound=FALSE;
    RtlZeroMemory(&g_A740.Hal,sizeof(g_A740.Hal));return STATUS_SUCCESS;
}
static NTSTATUS ResourceRead(ULONGLONG Pa,PULONG Value)
{
    PCM_PARTIAL_RESOURCE_LIST p;PHYSICAL_ADDRESS at;PULONG mapped;
    if(!g_A740.Resources||!Value) return STATUS_DEVICE_NOT_READY;
    p=&g_A740.Resources->List[0].PartialResourceList;
    for(ULONG i=0;i<p->Count;++i) {
        PCM_PARTIAL_RESOURCE_DESCRIPTOR r=&p->PartialDescriptors[i];
        ULONGLONG start;
        if(r->Type!=CmResourceTypeMemory) continue;
        start=(ULONGLONG)r->u.Memory.Start.QuadPart;
        if(start>Pa||r->u.Memory.Length<4||Pa-start>r->u.Memory.Length-4) continue;
        at.QuadPart=(LONGLONG)Pa;mapped=MmMapIoSpaceEx(at,4,PAGE_READWRITE|PAGE_NOCACHE);
        if(!mapped) return STATUS_INSUFFICIENT_RESOURCES;
        *Value=READ_REGISTER_ULONG(mapped);MmUnmapIoSpace(mapped,4);return STATUS_SUCCESS;
    }
    return STATUS_RESOURCE_TYPE_NOT_FOUND;
}
NTSTATUS A740ReadPoweredClockResources(VOID)
{
    static const ULONGLONG gates[]={0x03d9911c,0x03d97000,0x00171010,0x00171018};
    ULONG value;NTSTATUS st;
    if(!g_A740.Bound||KeGetCurrentIrql()!=PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
    st=ResourceRead(0x00171004,&value);
    if(!NT_SUCCESS(st)) return st;
    LogPrint("A740 cfg-AHB %08x\n",value);
    if(!(value&1)) return STATUS_DEVICE_NOT_READY;
    /* Entry to this function additionally requires the real upstream rail
     * owner. cfg-AHB alone does not establish that condition. */
    st=ResourceRead(0x03d9953c,&value);
    if(!NT_SUCCESS(st)) return st;
    LogPrint("A740 CX status %08x\n",value);
    if(!(value&0x80000000u)) return STATUS_DEVICE_POWER_FAILURE;
    for(ULONG i=0;i<RTL_NUMBER_OF(gates);++i) {
        st=ResourceRead(gates[i],&value);if(!NT_SUCCESS(st)) return st;
        LogPrint("A740 clock %llx %08x\n",gates[i],value);
        if(!(value&1)||(value&0x80000000u)) return STATUS_DEVICE_NOT_READY;
    }
    return STATUS_SUCCESS;
}
NTSTATUS A740OpenMappedRoles(const ULONG *Gpu,ULONG Ng,const ULONG *Gmu,ULONG Nm,
                            IOMMU_DMA_DOMAIN_TYPE Type)
{
    NTSTATUS st;
    if(!Gpu||!Gmu||!Ng||!Nm||Ng>A740_HAL_MAX_ROLE_INPUTS||Nm>A740_HAL_MAX_ROLE_INPUTS||
       !g_A740.Bound||g_A740.RolesOpened||g_A740.MastersStarted)
        return STATUS_INVALID_DEVICE_STATE;
    /* Callpoint is deliberately not invoked by StartDevice: current IORT
     * role IDs and boot-time stopped-master handoff are not implemented yet. */
    for(ULONG i=0;i<Ng;++i) for(ULONG j=0;j<Nm;++j)
        if(Gpu[i]==Gmu[j]) return STATUS_INVALID_PARAMETER;
    st=A740HalOpenRole(&g_A740.Gpu,&g_A740.Hal,Gpu,Ng,Type);
    if(!NT_SUCCESS(st)) return g_A740.Status=st;
    st=A740HalOpenRole(&g_A740.Gmu,&g_A740.Hal,Gmu,Nm,Type);
    if(!NT_SUCCESS(st)) return g_A740.Status=st;
    g_A740.RolesOpened=TRUE;return g_A740.Status=STATUS_SUCCESS;
}
BOOLEAN HwStart(VOID)
{
    /* HAL discover/map support is not GMU/CP startup. No current code sets
     * CpReady: rendering remains disabled until the real startup composition. */
    return g_A740.CpReady;
}
VOID HwStop(VOID) {g_A740.CpReady=FALSE;}
BOOLEAN HwReady(VOID) {return g_A740.CpReady;}
BOOLEAN HwRecover(VOID) {return FALSE;}
BOOLEAN HwWedged(VOID) {return g_A740.MastersStarted&&!g_A740.CpReady;}
ULONG HwGmemSize(VOID) {return 0;}
ULONGLONG HwTimestamp(VOID) {return 0;}
NTSTATUS HwSubmit(const ULONGLONG *Ib,const ULONG *Words,ULONG Count,PULONG Fence)
{
    UNREFERENCED_PARAMETER(Ib);UNREFERENCED_PARAMETER(Words);
    UNREFERENCED_PARAMETER(Count);UNREFERENCED_PARAMETER(Fence);
    return STATUS_DEVICE_NOT_READY;
}
ULONG HwCompletedFence(VOID) {return 0;}
BOOLEAN HwWaitFence(ULONG Fence,ULONG Timeout)
{UNREFERENCED_PARAMETER(Timeout);return Fence==0&&!g_A740.MastersStarted;}
ULONGLONG VaAlloc(SIZE_T Bytes)
{
    ULONGLONG va;
    if(!Bytes||(Bytes&(PAGE_SIZE-1))||Bytes>TGPU_VA_KERNEL-TGPU_VA_USER_START) return 0;
    va=g_A740.NextVa;
    if(va>TGPU_VA_KERNEL-Bytes-PAGE_SIZE) return 0;
    g_A740.NextVa+=Bytes+PAGE_SIZE;return va;
}
VOID VaFree(ULONGLONG Va,SIZE_T Bytes)
{UNREFERENCED_PARAMETER(Va);UNREFERENCED_PARAMETER(Bytes); /* no unsafe reuse across outstanding work */}
NTSTATUS MmuMap(ULONGLONG Va,PMDL Mdl,SIZE_T Bytes)
{return A740HalMap(&g_A740.Gpu,Mdl,Va,Bytes,3);}
VOID MmuUnmap(ULONGLONG Va,SIZE_T Bytes)
{(void)A740HalUnmap(&g_A740.Gpu,Va,Bytes);}
PMDL TgAllocPages(SIZE_T Bytes,PULONGLONG Iova,PVOID *KernelVa)
{
    PHYSICAL_ADDRESS low={0},high,skip={0};PMDL mdl;PVOID va;ULONGLONG gpu;
    if(!Iova||!KernelVa||!g_A740.RolesOpened||!Bytes||Bytes>0x40000000u||
       (Bytes&(PAGE_SIZE-1))) return NULL;
    high.QuadPart=MAXLONGLONG;
    mdl=MmAllocatePagesForMdlEx(low,high,skip,Bytes,MmWriteCombined,MM_ALLOCATE_FULLY_REQUIRED);
    if(!mdl) return NULL;
    va=MmMapLockedPagesSpecifyCache(mdl,KernelMode,MmWriteCombined,NULL,FALSE,
                                   NormalPagePriority|MdlMappingNoExecute);
    if(!va) {MmFreePagesFromMdl(mdl);ExFreePool(mdl);return NULL;}
    RtlZeroMemory(va,Bytes);gpu=VaAlloc(Bytes);
    if(!gpu||!NT_SUCCESS(MmuMap(gpu,mdl,Bytes))) {
        if(g_A740.Gpu.Poisoned) {
            LogPrint("A740 retain uncertain HAL mapping mdl %p cpu %p\n",mdl,va);return NULL;
        }
        MmUnmapLockedPages(va,mdl);MmFreePagesFromMdl(mdl);ExFreePool(mdl);return NULL;
    }
    *Iova=gpu;*KernelVa=va;return mdl;
}
VOID TgFreePages(PMDL Mdl,PVOID Va,SIZE_T Bytes,ULONGLONG Iova)
{
    /* A pending/faulted master never frees backing merely on a timeout. */
    if(g_A740.MastersStarted||!NT_SUCCESS(A740HalUnmap(&g_A740.Gpu,Iova,Bytes))) return;
    if(Va) MmUnmapLockedPages(Va,Mdl);MmFreePagesFromMdl(Mdl);ExFreePool(Mdl);
}
