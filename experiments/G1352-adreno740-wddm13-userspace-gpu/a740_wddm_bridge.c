#include "gpu_owner.h"
#include "gpu_cp_native.h"
#include "vendor/AdrenoPM4.h"
#include <intrin.h>

#define TGPU_POOL_TAG       'WupG'
#define TGPU_VA_USER_START  0x02000000ULL
#define TGPU_VA_KERNEL      0xF0000000ULL

struct _TGPU_BO;
struct drm_msm_gem_submit_bo;
typedef struct _TGPU_BO TGPU_BO;

VOID LogPrint(_In_z_ _Printf_format_string_ PCSTR Fmt, ...);
NTSTATUS MmuMap(ULONGLONG Va, PMDL Mdl, SIZE_T Bytes);
VOID MmuUnmap(ULONGLONG Va, SIZE_T Bytes);
ULONGLONG VaAlloc(SIZE_T Bytes);
NTSTATUS HwSubmit(const ULONGLONG *Ib, const ULONG *Words, ULONG Count, PULONG Fence);

#define CB0_BASE 0x20000u
#define RB_DWORDS 0x2000u /* 32 KiB ringbuffer at 0x200000 */
#define MAX_PT_PAGES 512

typedef struct _PT_PAGE {
    ULONGLONG Pa;
    ULONGLONG *Cpu;
    PMDL Mdl;
} PT_PAGE;

static OGO_CONTEXT *g_Ogo;
static volatile LONG g_ApertureConsumed;
static BOOLEAN g_CpReady;
static NTSTATUS g_LastStatus = STATUS_DEVICE_NOT_READY;
static KMUTEX g_HwLock;
static BOOLEAN g_HwLockInit;
static ULONG g_Wptr = 17;
static ULONG g_NextFence = 2;
static ULONGLONG g_NextVa = TGPU_VA_USER_START;

/* Dynamic CB0 page-table tracking */
static ULONGLONG *g_L1Cpu;
static PT_PAGE g_PtPages[MAX_PT_PAGES];
static ULONG g_PtCount;

/* Exports required by g1350 bootstrap.c */
BOOLEAN OgoCpRequested(VOID) { return TRUE; }
BOOLEAN OgoApertureRequested(VOID) { return TRUE; }
BOOLEAN OgoConsumeAperture(VOID) { return InterlockedCompareExchange(&g_ApertureConsumed, 1, 0) == 0; }

static ULONGLONG *FindOrMapTable(ULONGLONG Pa) {
    if (!Pa) return NULL;
    /* First check the already-mapped non-cached CB0 table pool from ArmSmmu4K */
    if (g_Ogo && g_Ogo->Cp && g_Ogo->Cp->Tables.Pool) {
        ULONGLONG poolPa = (ULONGLONG)g_Ogo->Cp->Tables.PoolPhysical.QuadPart;
        SIZE_T poolBytes = g_Ogo->Cp->Tables.PoolBytes;
        if (Pa >= poolPa && Pa + PAGE_SIZE <= poolPa + poolBytes) {
            return (ULONGLONG *)((PUCHAR)g_Ogo->Cp->Tables.Pool + (SIZE_T)(Pa - poolPa));
        }
    }
    /* Then check our dynamically allocated L2/L3 table pages */
    for (ULONG i = 0; i < g_PtCount; i++) {
        if (g_PtPages[i].Pa == Pa) return g_PtPages[i].Cpu;
    }
    return NULL;
}

static ULONGLONG *AllocTablePage(ULONGLONG *OutPa) {
    if (g_PtCount >= MAX_PT_PAGES) return NULL;
    PHYSICAL_ADDRESS low = {0}, high, skip = {0};
    high.QuadPart = 0xFFFFFFFFULL; /* < 4 GiB, well inside 36-bit OAS */
    PMDL mdl = MmAllocatePagesForMdlEx(low, high, skip, PAGE_SIZE, MmNonCached, MM_ALLOCATE_FULLY_REQUIRED);
    if (!mdl) return NULL;
    PVOID va = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE,
                                            NormalPagePriority | MdlMappingNoExecute);
    if (!va) { MmFreePagesFromMdl(mdl); ExFreePool(mdl); return NULL; }
    RtlZeroMemory(va, PAGE_SIZE);
    __dsb(_ARM64_BARRIER_OSHST);
    ULONGLONG pa = (ULONGLONG)MmGetMdlPfnArray(mdl)[0] << PAGE_SHIFT;
    g_PtPages[g_PtCount].Pa = pa;
    g_PtPages[g_PtCount].Cpu = (ULONGLONG *)va;
    g_PtPages[g_PtCount].Mdl = mdl;
    g_PtCount++;
    *OutPa = pa;
    return (ULONGLONG *)va;
}

static VOID Cb0TlbSync(VOID) {
    if (!g_Ogo || !g_Ogo->Cp || !g_Ogo->Cp->Smmu) return;
    PUCHAR sb = (PUCHAR)g_Ogo->Cp->Smmu;
    WRITE_REGISTER_ULONG((PULONG)(sb + CB0_BASE + 0x610), 0);          /* TLBIASID (ASID=0) */
    __dsb(_ARM64_BARRIER_OSH);
    WRITE_REGISTER_ULONG((PULONG)(sb + CB0_BASE + 0x7f0), 0xFFFFFFFFu);/* TLBSYNC */
    __dsb(_ARM64_BARRIER_OSH);
    for (ULONG i = 0; i < 2000; i++) {
        if (!(READ_REGISTER_ULONG((PULONG)(sb + CB0_BASE + 0x7f4)) & 1u)) break;
        KeStallExecutionProcessor(1);
    }
}

static NTSTATUS Cb0MapPage(ULONGLONG Iova, ULONGLONG Pa) {
    if (!g_L1Cpu || (Iova & 0xFFFULL) || (Pa & 0xFFFULL) || Iova >= (1ULL << 39))
        return STATUS_INVALID_PARAMETER;
    ULONG l1i = (ULONG)((Iova >> 30) & 0x1FFu);
    ULONG l2i = (ULONG)((Iova >> 21) & 0x1FFu);
    ULONG l3i = (ULONG)((Iova >> 12) & 0x1FFu);
    ULONGLONG e1 = g_L1Cpu[l1i];
    ULONGLONG *l2 = NULL;
    if (!(e1 & 1ULL)) {
        ULONGLONG l2pa = 0;
        l2 = AllocTablePage(&l2pa);
        if (!l2) return STATUS_INSUFFICIENT_RESOURCES;
        g_L1Cpu[l1i] = (l2pa & ~0xFFFULL) | 3ULL;
        __dsb(_ARM64_BARRIER_OSHST);
    } else {
        l2 = FindOrMapTable(e1 & 0x0000FFFFFFFFF000ULL);
        if (!l2) return STATUS_INSUFFICIENT_RESOURCES;
    }
    ULONGLONG e2 = l2[l2i];
    ULONGLONG *l3 = NULL;
    if (!(e2 & 1ULL)) {
        ULONGLONG l3pa = 0;
        l3 = AllocTablePage(&l3pa);
        if (!l3) return STATUS_INSUFFICIENT_RESOURCES;
        l2[l2i] = (l3pa & ~0xFFFULL) | 3ULL;
        __dsb(_ARM64_BARRIER_OSHST);
    } else {
        l3 = FindOrMapTable(e2 & 0x0000FFFFFFFFF000ULL);
        if (!l3) return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Match ArmSmmu4K.c: nG=1 (1<<11) | AF=1 (1<<10) | SH=2 (OS, 2<<8) | AP=01 (RW, 1<<6) | AttrIdx=0 (NC) | Page=3 */
    l3[l3i] = (Pa & 0x0000FFFFFFFFF000ULL) | 0x0000000000000E43ULL;
    return STATUS_SUCCESS;
}

static VOID Cb0UnmapPage(ULONGLONG Iova) {
    if (!g_L1Cpu || (Iova & 0xFFFULL) || Iova >= (1ULL << 39)) return;
    ULONG l1i = (ULONG)((Iova >> 30) & 0x1FFu);
    ULONG l2i = (ULONG)((Iova >> 21) & 0x1FFu);
    ULONG l3i = (ULONG)((Iova >> 12) & 0x1FFu);
    ULONGLONG e1 = g_L1Cpu[l1i];
    if (!(e1 & 1ULL)) return;
    ULONGLONG *l2 = FindOrMapTable(e1 & 0x0000FFFFFFFFF000ULL);
    if (!l2) return;
    ULONGLONG e2 = l2[l2i];
    if (!(e2 & 1ULL)) return;
    ULONGLONG *l3 = FindOrMapTable(e2 & 0x0000FFFFFFFFF000ULL);
    if (!l3) return;
    l3[l3i] = 0;
}

static KEVENT g_BootDone;
static KEVENT g_KeepAlive;
static NTSTATUS g_BootStatus;
static VOID OgoBootstrapThread(PVOID Ctx) {
    OGO_CONTEXT *p = (OGO_CONTEXT *)Ctx;
    g_BootStatus = OgoBootstrap(p);
    KeSetEvent(&g_BootDone, IO_NO_INCREMENT, FALSE);
    if (NT_SUCCESS(g_BootStatus)) {
        /* Stay alive while holding CghNativeAcquire's KMUTEX so we never trigger BugCheck 0x20! */
        KeWaitForSingleObject(&g_KeepAlive, Executive, KernelMode, FALSE, NULL);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS A740BindDevice(PDEVICE_OBJECT Pdo, PCM_RESOURCE_LIST Translated) {
    if (!g_HwLockInit) { KeInitializeMutex(&g_HwLock, 0); g_HwLockInit = TRUE; }
    if (g_CpReady) return STATUS_SUCCESS;
    if (!Pdo || !Translated) return STATUS_INVALID_PARAMETER;

    g_Ogo = (OGO_CONTEXT *)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*g_Ogo), TGPU_POOL_TAG);
    if (!g_Ogo) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_Ogo, sizeof(*g_Ogo));
    g_Ogo->Pdo = Pdo;
    g_Ogo->Resources = Translated;
    g_Ogo->Generation = 1;
    g_Ogo->RunId = 0x74000001ULL;
    g_Ogo->CpInit = TRUE;
    g_Ogo->Started = TRUE;
    g_Ogo->D0 = TRUE;
    KeInitializeMutex(&g_Ogo->RamLock, 0);
    KeInitializeMutex(&g_Ogo->Lock, 0);
    KeInitializeEvent(&g_BootDone, NotificationEvent, FALSE);
    KeInitializeEvent(&g_KeepAlive, NotificationEvent, FALSE);

    LogPrint("A740BindDevice: launching proven OgoBootstrap on System thread (irql=%u sys=%u)...\n",
             (ULONG)KeGetCurrentIrql(), (ULONG)PsIsSystemThread(PsGetCurrentThread()));
    HANDLE th = NULL;
    NTSTATUS st = PsCreateSystemThread(&th, THREAD_ALL_ACCESS, NULL, NULL, NULL, OgoBootstrapThread, g_Ogo);
    if (!NT_SUCCESS(st)) {
        LogPrint("A740BindDevice: PsCreateSystemThread failed %08x\n", st);
        return st;
    }
    KeWaitForSingleObject(&g_BootDone, Executive, KernelMode, FALSE, NULL);
    ZwClose(th);
    st = g_BootStatus;
    g_LastStatus = st;
    if (!NT_SUCCESS(st)) {
        LogPrint("A740BindDevice: OgoBootstrap failed %08x phase=%u input=%08x gmu=%08x clean=%08x life=%08x hold=%08x clkB=%u clkT=%llx hSt=%u hErr=%u ioM=%x\n",
                 st, g_Ogo->Phase, g_Ogo->InputStatus, g_Ogo->GmuStatus, g_Ogo->CleanupStatus,
                 g_Ogo->Life.Status, g_Ogo->Hold.Status, (ULONG)g_Ogo->Hold.Clock.Bound,
                 g_Ogo->Hold.Clock.Token, (ULONG)g_Ogo->Hold.Hold.state, (ULONG)g_Ogo->Hold.Hold.error,
                 g_Ogo->Io.MappedMask);
        return st;
    }
    if (!g_Ogo->Cp || !g_Ogo->Cp->Run.Buffer[0].Cpu || !g_Ogo->Cp->Run.Buffer[1].Cpu) {
        return STATUS_DEVICE_NOT_READY;
    }
    /* Map CB0 L1 root page for dynamic user BO mapping */
    ULONGLONG rootPa = g_Ogo->Cp->Tables.Tables.root_physical;
    g_L1Cpu = FindOrMapTable(rootPa);
    if (!g_L1Cpu) {
        LogPrint("A740BindDevice: failed to map CB0 L1 root %llx\n", rootPa);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    g_Wptr = 17;
    g_NextFence = 2;
    g_NextVa = TGPU_VA_USER_START;
    g_CpReady = TRUE;
    LogPrint("A740BindDevice: READY! rootPa=%llx fence1=%u rptr=%u\n",
             rootPa,
             ((volatile ULONG *)g_Ogo->Cp->Run.Buffer[1].Cpu)[1],
             ((volatile ULONG *)g_Ogo->Cp->Run.Buffer[1].Cpu)[0]);
    return STATUS_SUCCESS;
}

VOID HwInit(VOID) { if (!g_HwLockInit) { KeInitializeMutex(&g_HwLock, 0); g_HwLockInit = TRUE; } }
BOOLEAN HwStart(VOID) { return g_CpReady; }
VOID HwStop(VOID) { /* keep GPU/SMMU retained cleanly */ }
BOOLEAN HwReady(VOID) { return g_CpReady; }
BOOLEAN HwRecover(VOID) { return FALSE; }
BOOLEAN HwWedged(VOID) { return FALSE; }
ULONG HwGmemSize(VOID) { return 0x300000u; /* 3 MiB Adreno 740 GMEM */ }
ULONGLONG A740ChipId(VOID) { return g_CpReady ? 0x43050a01ULL : 0ULL; }
NTSTATUS A740GpuId(PULONGLONG Value) { if (!Value || !g_CpReady) return STATUS_DEVICE_NOT_READY; *Value = 740; return STATUS_SUCCESS; }
NTSTATUS A740LastStatus(VOID) { return g_LastStatus; }
NTSTATUS A740ReleaseProbe(VOID) { return STATUS_SUCCESS; }

ULONGLONG HwTimestamp(VOID) {
    if (!g_CpReady || !g_Ogo) return 0;
    ULONG lo = 0, hi = 0;
    (void)G482GpuRead(&g_Ogo->Io, 0x0e80u * 4u, &lo);
    (void)G482GpuRead(&g_Ogo->Io, 0x0e81u * 4u, &hi);
    return ((ULONGLONG)hi << 32) | lo;
}

ULONG HwCompletedFence(VOID) {
    if (!g_CpReady || !g_Ogo || !g_Ogo->Cp) return 0;
    __dmb(_ARM64_BARRIER_OSHLD);
    return ((volatile ULONG *)g_Ogo->Cp->Run.Buffer[1].Cpu)[1];
}

BOOLEAN HwWaitFence(ULONG Fence, ULONG TimeoutMs) {
    if (!g_CpReady) return Fence == 0;
    if (HwCompletedFence() >= Fence) return TRUE;
    ULONG loops = TimeoutMs ? TimeoutMs * 10u : 1u;
    if (loops > 50000u) loops = 50000u;
    for (ULONG i = 0; i < loops; i++) {
        if (HwCompletedFence() >= Fence) return TRUE;
        LARGE_INTEGER dt; dt.QuadPart = -1000; /* 100 us */
        KeDelayExecutionThread(KernelMode, FALSE, &dt);
    }
    return HwCompletedFence() >= Fence;
}

ULONGLONG VaAlloc(SIZE_T Bytes) {
    if (!Bytes || (Bytes & (PAGE_SIZE - 1)) || Bytes > TGPU_VA_KERNEL - TGPU_VA_USER_START) return 0;
    ULONGLONG va = g_NextVa;
    if (va > TGPU_VA_KERNEL - Bytes - PAGE_SIZE) return 0;
    g_NextVa += Bytes + PAGE_SIZE;
    return va;
}
VOID VaFree(ULONGLONG Va, SIZE_T Bytes) { UNREFERENCED_PARAMETER(Va); UNREFERENCED_PARAMETER(Bytes); }

NTSTATUS MmuMap(ULONGLONG Va, PMDL Mdl, SIZE_T Bytes) {
    if (!g_CpReady || !Mdl || !Bytes || (Bytes & 0xFFF)) return STATUS_INVALID_PARAMETER;
    KeWaitForSingleObject(&g_HwLock, Executive, KernelMode, FALSE, NULL);
    PPFN_NUMBER pfns = MmGetMdlPfnArray(Mdl);
    SIZE_T pages = Bytes >> PAGE_SHIFT;
    NTSTATUS st = STATUS_SUCCESS;
    for (SIZE_T i = 0; i < pages; i++) {
        st = Cb0MapPage(Va + (i << PAGE_SHIFT), (ULONGLONG)pfns[i] << PAGE_SHIFT);
        if (!NT_SUCCESS(st)) break;
    }
    __dsb(_ARM64_BARRIER_OSHST);
    Cb0TlbSync();
    KeReleaseMutex(&g_HwLock, FALSE);
    return st;
}

VOID MmuUnmap(ULONGLONG Va, SIZE_T Bytes) {
    if (!g_CpReady || !Bytes || (Bytes & 0xFFF)) return;
    KeWaitForSingleObject(&g_HwLock, Executive, KernelMode, FALSE, NULL);
    SIZE_T pages = Bytes >> PAGE_SHIFT;
    for (SIZE_T i = 0; i < pages; i++) Cb0UnmapPage(Va + (i << PAGE_SHIFT));
    __dsb(_ARM64_BARRIER_OSHST);
    Cb0TlbSync();
    KeReleaseMutex(&g_HwLock, FALSE);
}

PMDL TgAllocPages(SIZE_T Bytes, PULONGLONG Iova, PVOID *KernelVa) {
    if (!g_CpReady || !Iova || !KernelVa || !Bytes || Bytes > 0x40000000u || (Bytes & (PAGE_SIZE - 1)))
        return NULL;
    PHYSICAL_ADDRESS low = {0}, high, skip = {0};
    high.QuadPart = 0xFFFFFFFFULL; /* < 4 GiB */
    PMDL mdl = MmAllocatePagesForMdlEx(low, high, skip, Bytes, MmWriteCombined, MM_ALLOCATE_FULLY_REQUIRED);
    if (!mdl) return NULL;
    PVOID va = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmWriteCombined, NULL, FALSE,
                                            NormalPagePriority | MdlMappingNoExecute);
    if (!va) { MmFreePagesFromMdl(mdl); ExFreePool(mdl); return NULL; }
    RtlZeroMemory(va, Bytes);
    __dsb(_ARM64_BARRIER_OSHST);
    ULONGLONG gpu = VaAlloc(Bytes);
    if (!gpu || !NT_SUCCESS(MmuMap(gpu, mdl, Bytes))) {
        MmUnmapLockedPages(va, mdl); MmFreePagesFromMdl(mdl); ExFreePool(mdl);
        return NULL;
    }
    *Iova = gpu;
    *KernelVa = va;
    return mdl;
}

VOID TgFreePages(PMDL Mdl, PVOID Va, SIZE_T Bytes, ULONGLONG Iova) {
    if (Iova && Bytes) MmuUnmap(Iova, Bytes);
    if (Va && Mdl) MmUnmapLockedPages(Va, Mdl);
    if (Mdl) { MmFreePagesFromMdl(Mdl); ExFreePool(Mdl); }
}

static VOID RbEmit(volatile ULONG *Rb, ULONG Word) {
    Rb[g_Wptr] = Word;
    g_Wptr = (g_Wptr + 1u) & (RB_DWORDS - 1u);
}

NTSTATUS HwSubmit(const ULONGLONG *Ib, const ULONG *Words, ULONG Count, PULONG Fence) {
    if (!g_CpReady || !g_Ogo || !g_Ogo->Cp || !Fence) return STATUS_DEVICE_NOT_READY;
    if (Count > 64) return STATUS_INVALID_PARAMETER;
    KeWaitForSingleObject(&g_HwLock, Executive, KernelMode, FALSE, NULL);
    volatile ULONG *rb = (volatile ULONG *)g_Ogo->Cp->Run.Buffer[0].Cpu;
    ULONGLONG fenceAddr = g_Ogo->Cp->Run.Layout.Iova[1] + 4ULL; /* 0x300004 */
    ULONG fence = g_NextFence++;
    for (ULONG i = 0; i < Count; i++) {
        uint32_t hdr = 0;
        if (AdrenoPM4Type7(0x3fu, 3u, &hdr)) { KeReleaseMutex(&g_HwLock, FALSE); return STATUS_INVALID_PARAMETER; }
        RbEmit(rb, hdr);
        RbEmit(rb, (ULONG)(Ib[i] & 0xFFFFFFFFULL));
        RbEmit(rb, (ULONG)(Ib[i] >> 32));
        RbEmit(rb, Words[i]);
    }
    uint32_t evHdr = 0;
    (void)AdrenoPM4Type7(0x46u, 4u, &evHdr);
    RbEmit(rb, evHdr);
    RbEmit(rb, 0x88000031u);
    RbEmit(rb, (ULONG)(fenceAddr & 0xFFFFFFFFULL));
    RbEmit(rb, (ULONG)(fenceAddr >> 32));
    RbEmit(rb, fence);
    __dsb(_ARM64_BARRIER_OSHST);
    NTSTATUS st = G482GpuWrite(&g_Ogo->Io, 0x807u * 4u, g_Wptr);
    __dsb(_ARM64_BARRIER_OSH);
    *Fence = fence;
    KeReleaseMutex(&g_HwLock, FALSE);
    return st;
}

NTSTATUS HwSubmitOwned(PVOID Device, PEPROCESS Process, TGPU_BO *const *Bos,
                       const struct drm_msm_gem_submit_bo *Access, ULONG BoCount,
                       const ULONGLONG *IbIova, const ULONG *IbDwords, ULONG Count, PULONG Fence) {
    UNREFERENCED_PARAMETER(Device); UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(Bos); UNREFERENCED_PARAMETER(Access); UNREFERENCED_PARAMETER(BoCount);
    return HwSubmit(IbIova, IbDwords, Count, Fence);
}
