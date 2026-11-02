/* SPDX-License-Identifier: MIT
 * Original Open/A740 experimental backend. Replaces (does not modify) donor
 * A610 hw.c. Real owned GMU/CP stages; no raw SMMU/SMC or synthesized completion.
 */
#include "tgpu.h"
#include "a740_backend.h"
#include "g323_clock_policy.h"
#include <intrin.h>
static struct {
    KMUTEX Lock; G321_RUNTIME GmuRuntime; G433_RUNTIME CpRuntime; G482_BINDING NativeIo; A740_HAL Hal; A740_HAL_ROLE Gpu,Gmu;
    PDEVICE_OBJECT Pdo; PCM_RESOURCE_LIST Resources;
    NTSTATUS Status; BOOLEAN Bound, RolesOpened, MastersStarted, CpReady;
    ULONGLONG ChipId, NextVa; G433_SUBMIT_AUTH SubmitAuth;
} g_A740;
VOID HwInit(VOID)
{
    RtlZeroMemory(&g_A740,sizeof(g_A740));KeInitializeMutex(&g_A740.Lock,0);G321Initialize(&g_A740.GmuRuntime);G433Initialize(&g_A740.CpRuntime);G482Initialize(&g_A740.NativeIo);
    g_A740.Status=STATUS_DEVICE_NOT_READY;g_A740.NextVa=TGPU_VA_USER_START;
}
NTSTATUS A740LastStatus(VOID) { return g_A740.Status; }
ULONGLONG A740ChipId(VOID) { return g_A740.ChipId; }
NTSTATUS A740GpuId(PULONGLONG Value)
{
    if(!Value||!g_A740.ChipId) return STATUS_DEVICE_NOT_READY;
    *Value=740;return STATUS_SUCCESS;
}
static NTSTATUS BindDeviceLocked(PDEVICE_OBJECT Pdo,PCM_RESOURCE_LIST Resources)
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
    /* The full runtime contract maps exact OS-granted apertures only. It
     * does NOT access hardware or query HAL without the real owner below. */
    if(Resources&&Resources->List[0].PartialResourceList.Count==G482_BANKS){
        st=G482Bind(&g_A740.NativeIo,Pdo,Resources);
        LogPrint("G482 native grants status %08x mapped %x missing %x; D0 owner/HAL withheld\n",st,g_A740.NativeIo.MappedMask,g_A740.NativeIo.MissingMask);
        return g_A740.Status=st;
    }
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
static NTSTATUS ReleaseProbeLocked(VOID)
{
    if(KeGetCurrentIrql()!=PASSIVE_LEVEL||g_A740.Hal.ProbeRetained||
       g_A740.Gpu.Hal||g_A740.Gmu.Hal||g_A740.MastersStarted||
       (g_A740.GmuRuntime.Attempted&&!g_A740.GmuRuntime.Closed)||
       (g_A740.CpRuntime.Attempted&&!g_A740.CpRuntime.Closed))
        return STATUS_DEVICE_BUSY;
    if(g_A740.NativeIo.MappedMask){NTSTATUS n=G482Release(&g_A740.NativeIo);if(n!=STATUS_SUCCESS)return n;}
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
        at.QuadPart=(LONGLONG)Pa;mapped=MmMapIoSpaceEx(at,4,PAGE_READONLY|PAGE_NOCACHE);
        if(!mapped) return STATUS_INSUFFICIENT_RESOURCES;
        *Value=READ_REGISTER_ULONG(mapped);MmUnmapIoSpace(mapped,4);return STATUS_SUCCESS;
    }
    return STATUS_RESOURCE_TYPE_NOT_FOUND;
}
NTSTATUS A740ReadPoweredClockResources(VOID)
{
    static const ULONGLONG gates[]={0x03d9911c,0x03d97000,0x00171010,0x00171018};
    ULONG value;NTSTATUS st;
    if(g_A740.NativeIo.Bound)return STATUS_NOT_SUPPORTED; /* Native path uses owned qualification. */
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
        if(!G323BranchReady(i==0?5:i==1?6:i==2?3:4,value)) return STATUS_DEVICE_NOT_READY;
    }
    return STATUS_SUCCESS;
}
static NTSTATUS OpenMappedRolesLocked(const ULONG *Gpu,ULONG Ng,const ULONG *Gmu,ULONG Nm,
                            IOMMU_DMA_DOMAIN_TYPE Type)
{
    NTSTATUS st;
    if(g_A740.NativeIo.Bound)return STATUS_NOT_SUPPORTED; /* No legacy unowned attach bypass. */
    if(!Gpu||!Gmu||!Ng||!Nm||Ng>A740_HAL_MAX_ROLE_INPUTS||Nm>A740_HAL_MAX_ROLE_INPUTS||
       !g_A740.Bound||g_A740.RolesOpened||g_A740.MastersStarted||g_A740.GmuRuntime.Attempted)
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
    /* Even an actual internal CP-init fence does not qualify user BO/VM,
     * scheduler or rendering. CpReady remains closed until that integration. */
    return g_A740.CpReady;
}
VOID HwStop(VOID) {G433Cancel(&g_A740.CpRuntime);G321Cancel(&g_A740.GmuRuntime);g_A740.CpReady=FALSE;}
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
{UNREFERENCED_PARAMETER(Va);UNREFERENCED_PARAMETER(Mdl);UNREFERENCED_PARAMETER(Bytes);return STATUS_NOT_SUPPORTED; /* No legacy-role BO attach. */}
VOID MmuUnmap(ULONGLONG Va,SIZE_T Bytes)
{(void)A740HalUnmap(&g_A740.Gpu,Va,Bytes);}
PMDL TgAllocPages(SIZE_T Bytes,PULONGLONG Iova,PVOID *KernelVa)
{
    PHYSICAL_ADDRESS low={0},high,skip={0};PMDL mdl;PVOID va;ULONGLONG gpu;
    if(!Iova||!KernelVa||!g_A740.CpRuntime.Prepared||g_A740.CpRuntime.Core.stage!=9||!Bytes||Bytes>0x40000000u||
       (Bytes&(PAGE_SIZE-1))) return NULL;
    high.QuadPart=MAXLONGLONG;
    mdl=MmAllocatePagesForMdlEx(low,high,skip,Bytes,MmWriteCombined,MM_ALLOCATE_FULLY_REQUIRED);
    if(!mdl) return NULL;
    va=MmMapLockedPagesSpecifyCache(mdl,KernelMode,MmWriteCombined,NULL,FALSE,
                                   NormalPagePriority|MdlMappingNoExecute);
    if(!va) {MmFreePagesFromMdl(mdl);ExFreePool(mdl);return NULL;}
    RtlZeroMemory(va,Bytes);gpu=VaAlloc(Bytes);
    if(!gpu||!NT_SUCCESS(G433MapOwnedBo(&g_A740.CpRuntime,mdl,va,gpu,Bytes))) {
        if(g_A740.CpRuntime.Role.Poisoned) {
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

static NTSTATUS PrepareGmuLocked(const ULONG *Ids,ULONG Count,const G321_OWNER *Owner,
 const g196_inputs *Inputs,const G482_BOARD_INPUT *Board,ULONGLONG Generation,ULONGLONG StopSerial)
{
 if(!g_A740.NativeIo.Bound)return STATUS_RESOURCE_TYPE_NOT_FOUND;
 if(!g_A740.Bound||g_A740.Gmu.Hal||g_A740.RolesOpened||g_A740.MastersStarted)
  return STATUS_INVALID_DEVICE_STATE;
 NTSTATUS st=G321Prepare(&g_A740.GmuRuntime,&g_A740.Hal,Ids,Count,
  Owner,Inputs,&g_A740.NativeIo,Board,Generation,StopSerial);
 LogPrint("G321 GMU preparation %08x prepared %u poisoned %u extents %u\n",
  st,g_A740.GmuRuntime.Prepared,g_A740.GmuRuntime.Poisoned,g_A740.GmuRuntime.Plan.count);
 return g_A740.Status=st;
}
static NTSTATUS RunGmuLocked(VOID)
{
 NTSTATUS st=G321Start(&g_A740.GmuRuntime);
 /* A failed CM3 write can reach hardware: mirror conservative retention. */
 if(g_A740.GmuRuntime.MastersMayRun)g_A740.MastersStarted=TRUE;
 LogPrint("G321 GMU run %08x core %u stage %u failure-stage %u ACK-mask %x retained %u\n",
  st,g_A740.GmuRuntime.CoreStatus,g_A740.GmuRuntime.Core.stage,
  g_A740.GmuRuntime.Core.failure_stage,g_A740.GmuRuntime.Core.startup_acked,
  g_A740.GmuRuntime.MastersMayRun);
 /* Actual HFI ACKs still do not authorize CP submission or WDDM readiness. */
 return g_A740.Status=st;
}
static NTSTATUS ReleaseGmuStoppedLocked(ULONGLONG Serial)
{
 if(g_A740.CpRuntime.Attempted&&!g_A740.CpRuntime.Closed)return STATUS_DEVICE_BUSY;
 NTSTATUS st=G321ReleaseStopped(&g_A740.GmuRuntime,Serial);
 if(st==STATUS_SUCCESS)g_A740.MastersStarted=FALSE;
 return g_A740.Status=st;
}

static NTSTATUS LockOwnerComposition(VOID)
{
 LARGE_INTEGER timeout;timeout.QuadPart=-500000;
 if(KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_DEVICE_STATE;
 return KeWaitForSingleObject(&g_A740.Lock,Executive,KernelMode,FALSE,&timeout);
}
NTSTATUS A740BindDevice(PDEVICE_OBJECT Pdo,PCM_RESOURCE_LIST Resources)
{NTSTATUS st=LockOwnerComposition();if(st!=STATUS_SUCCESS)return st;st=BindDeviceLocked(Pdo,Resources);KeReleaseMutex(&g_A740.Lock,FALSE);return st;}
NTSTATUS A740ReleaseProbe(VOID)
{NTSTATUS st=LockOwnerComposition();if(st!=STATUS_SUCCESS)return st;st=ReleaseProbeLocked();KeReleaseMutex(&g_A740.Lock,FALSE);return st;}
NTSTATUS A740OpenMappedRoles(const ULONG *Gpu,ULONG Ng,const ULONG *Gmu,ULONG Nm,IOMMU_DMA_DOMAIN_TYPE Type)
{NTSTATUS st=LockOwnerComposition();if(st!=STATUS_SUCCESS)return st;st=OpenMappedRolesLocked(Gpu,Ng,Gmu,Nm,Type);KeReleaseMutex(&g_A740.Lock,FALSE);return st;}
NTSTATUS A740PrepareGmu(const ULONG *Ids,ULONG Count,const G321_OWNER *Owner,
 const g196_inputs *Inputs,const G482_BOARD_INPUT *Board,ULONGLONG Generation,ULONGLONG StopSerial)
{NTSTATUS st=LockOwnerComposition();if(st!=STATUS_SUCCESS)return st;st=PrepareGmuLocked(Ids,Count,Owner,Inputs,Board,Generation,StopSerial);KeReleaseMutex(&g_A740.Lock,FALSE);return st;}
NTSTATUS A740RunGmu(VOID)
{NTSTATUS st=LockOwnerComposition();if(st!=STATUS_SUCCESS)return st;st=RunGmuLocked();KeReleaseMutex(&g_A740.Lock,FALSE);return st;}
NTSTATUS A740ReleaseGmuStopped(ULONGLONG Serial)
{NTSTATUS st=LockOwnerComposition();if(st!=STATUS_SUCCESS)return st;st=ReleaseGmuStoppedLocked(Serial);KeReleaseMutex(&g_A740.Lock,FALSE);return st;}

NTSTATUS A740PrepareCp(const ULONG *Ids,ULONG Count,const G433_GPU_OPS *Ops,const UCHAR *Sqe,SIZE_T Bytes,ULONGLONG Serial)
{NTSTATUS st=LockOwnerComposition();if(st!=STATUS_SUCCESS)return st;
 if(g_A740.RolesOpened||g_A740.Gpu.Hal||g_A740.Gmu.Hal)st=STATUS_DEVICE_BUSY;
 else st=G433Prepare(&g_A740.CpRuntime,&g_A740.GmuRuntime,&g_A740.Hal,Ids,Count,Ops,Sqe,Bytes,Serial);
 g_A740.Status=st;KeReleaseMutex(&g_A740.Lock,FALSE);return st;}
NTSTATUS A740RunCp(VOID)
{NTSTATUS st=LockOwnerComposition();if(st!=STATUS_SUCCESS)return st;st=G433Run(&g_A740.CpRuntime);
 if(g_A740.CpRuntime.MastersMayRun)g_A740.MastersStarted=TRUE;
 LogPrint("G440 GX stage %u status %u freq-ACK %u OOB-retained %u GX %x/%u -> %x/%u\n",g_A740.CpRuntime.Power.stage,g_A740.CpRuntime.Power.status,g_A740.CpRuntime.Power.freq_acked,g_A740.CpRuntime.Power.oob_may_be_held,g_A740.CpRuntime.Power.gx_before,g_A740.CpRuntime.Power.gx_before_valid,g_A740.CpRuntime.Power.gx_after,g_A740.CpRuntime.Power.gx_after_valid);
 LogPrint("G456 hw_init stage %u status %08x trace %u writes %u complete %u HBB %u\n",g_A740.CpRuntime.Hwinit.Stage,g_A740.CpRuntime.Hwinit.Status,g_A740.CpRuntime.Hwinit.Count,g_A740.CpRuntime.Hwinit.Writes,g_A740.CpRuntime.Hwinit.Complete,g_A740.CpRuntime.Hwinit.HighestBankBit);
 LogPrint("G433 CP init %08x stage %u issued %u observed %u complete %u retained %u\n",st,g_A740.CpRuntime.Core.stage,g_A740.CpRuntime.Core.issued,g_A740.CpRuntime.Core.last_observed,g_A740.CpRuntime.Core.completed,g_A740.CpRuntime.MastersMayRun);
 /* CP init fence does not qualify donor global BO/VM/user submission. */
 g_A740.Status=st;KeReleaseMutex(&g_A740.Lock,FALSE);return st;}
NTSTATUS A740ReleaseCpStopped(ULONGLONG Serial)
{NTSTATUS st=LockOwnerComposition();if(st!=STATUS_SUCCESS)return st;st=G433ReleaseStopped(&g_A740.CpRuntime,Serial);g_A740.Status=st;KeReleaseMutex(&g_A740.Lock,FALSE);return st;}

NTSTATUS A740QualifyRuntime(const G321_OWNER *Owner,ULONGLONG Generation,ULONGLONG StopSerial)
{
 NTSTATUS st=LockOwnerComposition();BOOLEAN entered=FALSE;if(st!=STATUS_SUCCESS)return st;
 if(!g_A740.NativeIo.Bound){st=STATUS_RESOURCE_TYPE_NOT_FOUND;goto done;}
 if(!Owner||!Owner->Enter||!Owner->Leave||!Owner->Lease||!Owner->Stopped||!Generation||!StopSerial||g_A740.GmuRuntime.Attempted){st=STATUS_INVALID_PARAMETER;goto done;}
 st=Owner->Enter(Owner->Cookie,Generation);if(st!=STATUS_SUCCESS)goto done;entered=TRUE;
 st=Owner->Lease(Owner->Cookie,Generation);if(st!=STATUS_SUCCESS)goto done;
 st=Owner->Stopped(Owner->Cookie,StopSerial,Generation);if(st!=STATUS_SUCCESS)goto done;
 st=G482RequirePoweredHandoff(&g_A740.NativeIo);if(st!=STATUS_SUCCESS)goto done;
 st=A740HalDiscover(&g_A740.Hal,g_A740.Pdo);
 /* A complete actual HAL report still grants neither a running GMU nor
  * render readiness. No producer of the actual owner is fabricated here. */
done:if(entered)Owner->Leave(Owner->Cookie);g_A740.Status=st;KeReleaseMutex(&g_A740.Lock,FALSE);return st;
}

NTSTATUS A740BindSubmitAuthorization(const G433_SUBMIT_AUTH*auth){
 NTSTATUS st=LockOwnerComposition();if(st!=STATUS_SUCCESS)return st;
 if(!auth||!auth->Begin||!auth->End||g_A740.SubmitAuth.Begin||!g_A740.CpRuntime.Prepared||g_A740.CpRuntime.Core.stage!=9||g_A740.CpRuntime.Poisoned||g_A740.CpRuntime.Closed)st=STATUS_DEVICE_NOT_READY;
 else {g_A740.SubmitAuth=*auth;st=STATUS_SUCCESS;}
 /* Provider binding is not WDDM readiness and does not change CpReady. */
 KeReleaseMutex(&g_A740.Lock,FALSE);return st;
}
NTSTATUS HwSubmitOwned(PVOID device,PEPROCESS process,TGPU_BO*const*bos,const struct drm_msm_gem_submit_bo*access,ULONG nb,const ULONGLONG*va,const ULONG*words,ULONG ni,PULONG fence){
 NTSTATUS st;G433_SUBMIT_BO*owned=NULL;g433_ib*ib=NULL;
 if(!device||!process||process!=PsGetCurrentProcess()||!bos||!access||!nb||nb>4096||!va||!words||!ni||ni>512||!fence)return STATUS_INVALID_PARAMETER;
 st=LockOwnerComposition();if(st!=STATUS_SUCCESS)return st;
 if(!g_A740.SubmitAuth.Begin){st=STATUS_DEVICE_NOT_READY;goto done;}
 owned=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*owned)*nb,TGPU_POOL_TAG);ib=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*ib)*ni,TGPU_POOL_TAG);
 if(!owned||!ib){st=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 for(ULONG i=0;i<nb;i++){TGPU_BO*b=bos[i];if(!b||b->Refs<=0||b->Handle!=access[i].handle){st=STATUS_INVALID_HANDLE;goto done;}owned[i]=(G433_SUBMIT_BO){b->Handle,access[i].flags,b->Mdl,b->KernelVa,b->Iova,b->Size};}
 for(ULONG i=0;i<ni;i++)ib[i]=(g433_ib){va[i],words[i]};
 st=G433SubmitAuthorized(&g_A740.CpRuntime,device,process,owned,nb,ib,ni,&g_A740.SubmitAuth,fence);
 done:if(owned)ExFreePoolWithTag(owned,TGPU_POOL_TAG);if(ib)ExFreePoolWithTag(ib,TGPU_POOL_TAG);KeReleaseMutex(&g_A740.Lock,FALSE);return st;
}
