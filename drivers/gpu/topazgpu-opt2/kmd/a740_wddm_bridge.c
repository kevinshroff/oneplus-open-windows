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
ULONG HwCompletedFence(VOID);
NTSTATUS HwSubmit(const ULONGLONG *Ib, const ULONG *Words, ULONG Count, PULONG Fence);

#define CB0_BASE 0x20000u
#define RB_DWORDS 0x2000u /* 32 KiB ringbuffer at 0x200000 */
#define MAX_PT_PAGES 8192 /* 4 KiB L2/L3 table pages; each L3 maps 2 MiB */

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
static ULONGLONG g_MaxPa = 0xFFFFFFFFULL; /* raised from CB0 TCR2.PASize at bind */
static ULONG g_VaFreeCount;

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
    high.QuadPart = 0xFFFFFFFFULL; /* prefer < 4 GiB; fall back to the CB0 output range */
    PMDL mdl = MmAllocatePagesForMdlEx(low, high, skip, PAGE_SIZE, MmNonCached, MM_ALLOCATE_FULLY_REQUIRED);
    if (!mdl && g_MaxPa > 0xFFFFFFFFULL) {
        high.QuadPart = (LONGLONG)g_MaxPa;
        mdl = MmAllocatePagesForMdlEx(low, high, skip, PAGE_SIZE, MmNonCached, MM_ALLOCATE_FULLY_REQUIRED);
    }
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


/* ---- Adreno 740 ZAP Shader (PAS 13) + CP_SET_SECURE_MODE(0) ---- */
typedef struct _A740_SMC_ARGS {
    ULONG_PTR Arg0, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6, Arg7;
} A740_SMC_ARGS;
VOID A740ArmCallSmc(A740_SMC_ARGS *Args);

#define A740_SCM_FN(svc, cmd) (0x42000000u | ((ULONG)(svc) << 8) | (ULONG)(cmd))
#define A740_GPU_PAS_ID       13u
#define A740_ZAP_REGION       0x9b09a000ULL
#define A740_ZAP_REGION_SIZE  0x2000u

static ULONG_PTR A740Scm(ULONG Fn, ULONG_PTR ArgInfo, ULONG_PTR A, ULONG_PTR B, ULONG_PTR C, ULONG_PTR *Res1) {
    A740_SMC_ARGS args;
    RtlZeroMemory(&args, sizeof(args));
    args.Arg0 = Fn; args.Arg1 = ArgInfo; args.Arg2 = A; args.Arg3 = B; args.Arg4 = C;
    A740ArmCallSmc(&args);
    for (ULONG n = 0; args.Arg0 == 1 && n < 100000u; n++) {
        ULONG_PTR a6 = args.Arg6;
        RtlZeroMemory(&args, sizeof(args));
        args.Arg0 = 1; args.Arg1 = ArgInfo; args.Arg2 = A; args.Arg3 = B; args.Arg4 = C; args.Arg6 = a6;
        A740ArmCallSmc(&args);
    }
    if (Res1) *Res1 = args.Arg1;
    return args.Arg0;
}

static PUCHAR A740ReadFile(PCWSTR Path, PULONG OutSize) {
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE h = NULL;
    FILE_STANDARD_INFORMATION fsi;
    RtlInitUnicodeString(&us, Path);
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&h, FILE_GENERIC_READ, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                                 FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
        return NULL;
    if (!NT_SUCCESS(ZwQueryInformationFile(h, &iosb, &fsi, sizeof(fsi), FileStandardInformation)) ||
        fsi.EndOfFile.QuadPart <= 0 || fsi.EndOfFile.QuadPart > 0x100000) {
        ZwClose(h); return NULL;
    }
    ULONG sz = (ULONG)fsi.EndOfFile.QuadPart;
    PUCHAR buf = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, sz, TGPU_POOL_TAG);
    if (!buf) { ZwClose(h); return NULL; }
    if (!NT_SUCCESS(ZwReadFile(h, NULL, NULL, NULL, &iosb, buf, sz, NULL, NULL)) || iosb.Information != sz) {
        ExFreePoolWithTag(buf, TGPU_POOL_TAG); ZwClose(h); return NULL;
    }
    ZwClose(h);
    *OutSize = sz;
    return buf;
}

static BOOLEAN A740ZapLoad(VOID) {
    ULONG mdtSz = 0, segSz = 0;
    PUCHAR mdt = A740ReadFile(L"\\??\\C:\\topaz\\fw\\a740_zap.mdt", &mdtSz);
    PUCHAR seg = A740ReadFile(L"\\??\\C:\\topaz\\fw\\a740_zap.b01", &segSz);
    if (!mdt || !seg || mdtSz < 52) {
        LogPrint("A740ZapLoad: fw files missing (mdt=%p/%u b01=%p/%u)\n", mdt, mdtSz, seg, segSz);
        if (mdt) ExFreePoolWithTag(mdt, TGPU_POOL_TAG);
        if (seg) ExFreePoolWithTag(seg, TGPU_POOL_TAG);
        return FALSE;
    }
    PHYSICAL_ADDRESS lo = {0}, hi, bound = {0};
    hi.QuadPart = 0xEFFFFFFFULL;
    SIZE_T metaPages = (mdtSz + PAGE_SIZE - 1u) & ~(PAGE_SIZE - 1u);
    PUCHAR meta = (PUCHAR)MmAllocateContiguousMemorySpecifyCache(metaPages, lo, hi, bound, MmWriteCombined);
    BOOLEAN ok = FALSE;
    if (!meta) {
        LogPrint("A740ZapLoad: meta alloc failed\n");
        goto out;
    }
    RtlCopyMemory(meta, mdt, mdtSz);
    __dsb(_ARM64_BARRIER_SY);
    PHYSICAL_ADDRESS metaPa = MmGetPhysicalAddress(meta);
    ULONG_PTR st = 0, res = 0;
    A740Scm(A740_SCM_FN(0x02, 0x06), 1, A740_GPU_PAS_ID, 0, 0, &res); /* PIL_SHUTDOWN */
    st = A740Scm(A740_SCM_FN(0x02, 0x01), 2u | (2u << 6), A740_GPU_PAS_ID, (ULONG_PTR)metaPa.QuadPart, 0, &res);
    LogPrint("A740ZapLoad: PIL_INIT_IMAGE st=%llx res=%llx (mdtSz=%u pa=%llx)\n",
             (ULONGLONG)st, (ULONGLONG)res, mdtSz, (ULONGLONG)metaPa.QuadPart);
    if (st != 0 || res != 0) goto out;

    st = A740Scm(A740_SCM_FN(0x02, 0x02), 3, A740_GPU_PAS_ID, (ULONG_PTR)A740_ZAP_REGION, A740_ZAP_REGION_SIZE, &res);
    LogPrint("A740ZapLoad: PIL_MEM_SETUP(0x9b09a000, 0x2000) st=%llx res=%llx\n", (ULONGLONG)st, (ULONGLONG)res);
    if (st != 0 || res != 0) goto out;

    PHYSICAL_ADDRESS zapPa; zapPa.QuadPart = (LONGLONG)A740_ZAP_REGION;
    volatile UCHAR *dst = (volatile UCHAR *)MmMapIoSpaceEx(zapPa, A740_ZAP_REGION_SIZE, PAGE_READWRITE | PAGE_WRITECOMBINE);
    if (!dst) {
        LogPrint("A740ZapLoad: MmMapIoSpaceEx failed\n");
        goto out;
    }
    RtlZeroMemory((PVOID)dst, A740_ZAP_REGION_SIZE);
    RtlCopyMemory((PVOID)dst, seg, segSz < A740_ZAP_REGION_SIZE ? segSz : A740_ZAP_REGION_SIZE);
    __dsb(_ARM64_BARRIER_SY);
    MmUnmapIoSpace((PVOID)dst, A740_ZAP_REGION_SIZE);

    st = A740Scm(A740_SCM_FN(0x02, 0x05), 1, A740_GPU_PAS_ID, 0, 0, &res);
    LogPrint("A740ZapLoad: PIL_AUTH_RESET st=%llx res=%llx\n", (ULONGLONG)st, (ULONGLONG)res);
    ok = (st == 0 && res == 0);
out:
    if (meta) MmFreeContiguousMemorySpecifyCache(meta, metaPages, MmWriteCombined);
    ExFreePoolWithTag(seg, TGPU_POOL_TAG);
    ExFreePoolWithTag(mdt, TGPU_POOL_TAG);
    return ok;
}

static VOID A740ExitSecureMode(VOID) {
    ULONG trustBefore = 0xDEADBEEFu, trustAfter = 0xDEADBEEFu;
    (void)G482GpuRead(&g_Ogo->Io, 0xF400u * 4u, &trustBefore);
    LogPrint("A740ExitSecureMode: RBBM_SECVID_TRUST_CNTL before=%08x\n", trustBefore);
    if (!A740ZapLoad()) {
        LogPrint("A740ExitSecureMode: ZapLoad failed, skipping CP_SET_SECURE_MODE\n");
        return;
    }
    volatile ULONG *rb = (volatile ULONG *)g_Ogo->Cp->Run.Buffer[0].Cpu;
    ULONGLONG fenceAddr = g_Ogo->Cp->Run.Layout.Iova[1] + 4ULL;
    ULONG fence = g_NextFence++;
    uint32_t smHdr = 0, scrHdr = 0, evHdr = 0;
    (void)AdrenoPM4Type7(0x66u, 1u, &smHdr); /* CP_SET_SECURE_MODE */
    (void)AdrenoPM4Type4(0x885u, 1u, &scrHdr);
    (void)AdrenoPM4Type7(0x46u, 4u, &evHdr);
    rb[g_Wptr] = smHdr;  g_Wptr = (g_Wptr + 1u) & (RB_DWORDS - 1u);
    rb[g_Wptr] = 0u;     g_Wptr = (g_Wptr + 1u) & (RB_DWORDS - 1u);
    rb[g_Wptr] = scrHdr; g_Wptr = (g_Wptr + 1u) & (RB_DWORDS - 1u);
    rb[g_Wptr] = fence;  g_Wptr = (g_Wptr + 1u) & (RB_DWORDS - 1u);
    rb[g_Wptr] = evHdr;  g_Wptr = (g_Wptr + 1u) & (RB_DWORDS - 1u);
    rb[g_Wptr] = 0x88000031u; g_Wptr = (g_Wptr + 1u) & (RB_DWORDS - 1u);
    rb[g_Wptr] = (ULONG)(fenceAddr & 0xFFFFFFFFULL); g_Wptr = (g_Wptr + 1u) & (RB_DWORDS - 1u);
    rb[g_Wptr] = (ULONG)(fenceAddr >> 32);           g_Wptr = (g_Wptr + 1u) & (RB_DWORDS - 1u);
    rb[g_Wptr] = fence;  g_Wptr = (g_Wptr + 1u) & (RB_DWORDS - 1u);
    __dsb(_ARM64_BARRIER_OSHST);
    (void)G482GpuWrite(&g_Ogo->Io, 0x807u * 4u, g_Wptr);
    __dsb(_ARM64_BARRIER_OSH);
    for (ULONG k = 0; k < 2000u && HwCompletedFence() < fence; k++) {
        LARGE_INTEGER dt; dt.QuadPart = -1000;
        KeDelayExecutionThread(KernelMode, FALSE, &dt);
    }
    (void)G482GpuRead(&g_Ogo->Io, 0xF400u * 4u, &trustAfter);
    LogPrint("A740ExitSecureMode: CP_SET_SECURE_MODE(0) fence=%u done=%u RBBM_SECVID_TRUST_CNTL after=%08x\n",
             fence, HwCompletedFence(), trustAfter);
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
    g_VaFreeCount = 0;
    if (g_Ogo->Cp->Smmu) {
        static const UCHAR PaBits[8] = {32, 36, 40, 42, 44, 48, 52, 32};
        PUCHAR sb = (PUCHAR)g_Ogo->Cp->Smmu;
        ULONG tcr  = READ_REGISTER_ULONG((PULONG)(sb + CB0_BASE + 0x30));
        ULONG tcr2 = READ_REGISTER_ULONG((PULONG)(sb + CB0_BASE + 0x10));
        ULONG cba2 = READ_REGISTER_ULONG((PULONG)(sb + 0x1800));    /* CBA2R0: VA64 */
        UCHAR bits = PaBits[(tcr2 >> 16) & 7u];
        /* only trust a >32-bit PASize when the context is in AArch64 (VA64) format; all SM8550 DRAM
         * lies below 64 GiB, so cap the allocation range at 36 bits */
        if ((cba2 & 1u) && bits >= 36) g_MaxPa = (1ULL << 36) - 1ULL;
        LogPrint("A740BindDevice: CB0 TCR=%08x TCR2=%08x CBA2R=%08x -> PA limit %llx\n", tcr, tcr2, cba2, g_MaxPa);
    }
    g_CpReady = TRUE;
    A740ExitSecureMode();
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

volatile LONG64 g_StWaits, g_StWaitUs, g_StWaitMaxUs, g_StSubmits;
static LONG64 BrNowUs(VOID) { LARGE_INTEGER f, c = KeQueryPerformanceCounter(&f); return c.QuadPart * 1000000LL / f.QuadPart; }
BOOLEAN HwWaitFenceInner(ULONG Fence, ULONG TimeoutMs);
BOOLEAN HwWaitFence(ULONG Fence, ULONG TimeoutMs) {
    LONG64 t0, dt; BOOLEAN r;
    if (!g_CpReady) return Fence == 0;
    if (HwCompletedFence() >= Fence) return TRUE;
    t0 = BrNowUs();
    r = HwWaitFenceInner(Fence, TimeoutMs);
    dt = BrNowUs() - t0;
    InterlockedIncrement64(&g_StWaits); InterlockedAdd64(&g_StWaitUs, dt);
    if (dt > g_StWaitMaxUs) g_StWaitMaxUs = dt;
    return r;
}
BOOLEAN HwWaitFenceInner(ULONG Fence, ULONG TimeoutMs) {
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

/* GPU VA allocator: bump pointer plus a first-fit free list so BOs freed by
 * restarting processes (DWM) give their address space back. */
#define VA_FREE_MAX 1024
typedef struct _VA_RANGE { ULONGLONG Va; SIZE_T Bytes; } VA_RANGE;
static VA_RANGE g_VaFree[VA_FREE_MAX];
static KSPIN_LOCK g_VaLock;
static BOOLEAN g_VaLockInit;

static VOID VaLockInit(VOID) { if (!g_VaLockInit) { KeInitializeSpinLock(&g_VaLock); g_VaLockInit = TRUE; } }

ULONGLONG VaAlloc(SIZE_T Bytes) {
    if (!Bytes || (Bytes & (PAGE_SIZE - 1)) || Bytes > TGPU_VA_KERNEL - TGPU_VA_USER_START) return 0;
    SIZE_T need = Bytes + PAGE_SIZE; /* keep one guard page between BOs */
    KIRQL irql;
    VaLockInit();
    KeAcquireSpinLock(&g_VaLock, &irql);
    ULONGLONG va = 0;
    ULONG best = MAXULONG;
    for (ULONG i = 0; i < g_VaFreeCount; i++) {
        if (g_VaFree[i].Bytes >= need && (best == MAXULONG || g_VaFree[i].Bytes < g_VaFree[best].Bytes))
            best = i;
    }
    if (best != MAXULONG) {
        va = g_VaFree[best].Va;
        if (g_VaFree[best].Bytes > need) {
            g_VaFree[best].Va += need;
            g_VaFree[best].Bytes -= need;
        } else {
            g_VaFree[best] = g_VaFree[--g_VaFreeCount];
        }
    } else if (g_NextVa <= TGPU_VA_KERNEL - need) {
        va = g_NextVa;
        g_NextVa += need;
    }
    KeReleaseSpinLock(&g_VaLock, irql);
    return va;
}

VOID VaFree(ULONGLONG Va, SIZE_T Bytes) {
    if (!Va || !Bytes) return;
    SIZE_T len = Bytes + PAGE_SIZE;
    KIRQL irql;
    VaLockInit();
    KeAcquireSpinLock(&g_VaLock, &irql);
    /* merge with neighbours */
    for (ULONG i = 0; i < g_VaFreeCount; ) {
        if (g_VaFree[i].Va + g_VaFree[i].Bytes == Va) {
            Va = g_VaFree[i].Va; len += g_VaFree[i].Bytes;
            g_VaFree[i] = g_VaFree[--g_VaFreeCount];
            continue;
        }
        if (Va + len == g_VaFree[i].Va) {
            len += g_VaFree[i].Bytes;
            g_VaFree[i] = g_VaFree[--g_VaFreeCount];
            continue;
        }
        i++;
    }
    if (Va + len == g_NextVa) {
        g_NextVa = Va;                      /* give the tail back to the bump pointer */
    } else if (g_VaFreeCount < VA_FREE_MAX) {
        g_VaFree[g_VaFreeCount].Va = Va;
        g_VaFree[g_VaFreeCount].Bytes = len;
        g_VaFreeCount++;
    }                                       /* else: leak the range (bounded) */
    KeReleaseSpinLock(&g_VaLock, irql);
}

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

static volatile LONG g_HighAllocLogged;

static PMDL AllocWcPages(ULONGLONG HighPa, SIZE_T Bytes) {
    PHYSICAL_ADDRESS low = {0}, high, skip = {0};
    high.QuadPart = (LONGLONG)HighPa;
    return MmAllocatePagesForMdlEx(low, high, skip, Bytes, MmWriteCombined, MM_ALLOCATE_FULLY_REQUIRED);
}

PMDL TgAllocPages(SIZE_T Bytes, PULONGLONG Iova, PVOID *KernelVa) {
    if (!g_CpReady || !Iova || !KernelVa || !Bytes || Bytes > 0x40000000u || (Bytes & (PAGE_SIZE - 1)))
        return NULL;
    /* Prefer < 4 GiB (proven path); only ~2 GiB of RAM sits below 4 GiB on SM8550 and most of it is
     * reserved, so large scanout-sized BOs (DWM) fall back to the full range the CB0 context can
     * output (TCR2.PASize, read live at bind). */
    static volatile LONG failLogs;
    /* Large BOs (render targets, scanout copies) go to high memory first so the scarce
     * < 4 GiB pool stays available for page tables and small BOs. */
    BOOLEAN highFirst = (Bytes >= 0x200000u) && g_MaxPa > 0xFFFFFFFFULL;
    PMDL mdl = AllocWcPages(highFirst ? g_MaxPa : 0xFFFFFFFFULL, Bytes);
    if (!mdl && !highFirst && g_MaxPa > 0xFFFFFFFFULL) {
        mdl = AllocWcPages(g_MaxPa, Bytes);
        if (mdl && InterlockedCompareExchange(&g_HighAllocLogged, 1, 0) == 0)
            LogPrint("TgAllocPages: %llu KB from full PA range (max %llx), first pfn %llx\n",
                     (ULONGLONG)Bytes / 1024, g_MaxPa, (ULONGLONG)MmGetMdlPfnArray(mdl)[0]);
    }
    if (!mdl) {
        if (InterlockedIncrement(&failLogs) <= 20) LogPrint("TgAllocPages: no pages for %llu KB\n", (ULONGLONG)Bytes / 1024);
        return NULL;
    }
    if (MmGetMdlByteCount(mdl) < Bytes) { MmFreePagesFromMdl(mdl); ExFreePool(mdl); return NULL; }
    PVOID va = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmWriteCombined, NULL, FALSE,
                                            NormalPagePriority | MdlMappingNoExecute);
    if (!va) { MmFreePagesFromMdl(mdl); ExFreePool(mdl); return NULL; }
    RtlZeroMemory(va, Bytes);
    __dsb(_ARM64_BARRIER_OSHST);
    ULONGLONG gpu = VaAlloc(Bytes);
    NTSTATUS mst = gpu ? MmuMap(gpu, mdl, Bytes) : STATUS_NO_MEMORY;
    if (!NT_SUCCESS(mst)) {
        if (InterlockedIncrement(&failLogs) <= 20)
            LogPrint("TgAllocPages: %llu KB va %llx map %08x (pt pages %u, free ranges %u, next va %llx)\n",
                     (ULONGLONG)Bytes / 1024, gpu, mst, g_PtCount, g_VaFreeCount, g_NextVa);
        if (gpu) { MmuUnmap(gpu, Bytes); VaFree(gpu, Bytes); }
        MmUnmapLockedPages(va, mdl); MmFreePagesFromMdl(mdl); ExFreePool(mdl);
        return NULL;
    }
    *Iova = gpu;
    *KernelVa = va;
    return mdl;
}

VOID TgFreePages(PMDL Mdl, PVOID Va, SIZE_T Bytes, ULONGLONG Iova) {
    if (Iova && Bytes) { MmuUnmap(Iova, Bytes); VaFree(Iova, Bytes); }
    if (Va && Mdl) MmUnmapLockedPages(Va, Mdl);
    if (Mdl) { MmFreePagesFromMdl(Mdl); ExFreePool(Mdl); }
}

static VOID RbEmit(volatile ULONG *Rb, ULONG Word) {
    Rb[g_Wptr] = Word;
    g_Wptr = (g_Wptr + 1u) & (RB_DWORDS - 1u);
}

static ULONG g_DiagSubmits;

NTSTATUS HwSubmit(const ULONGLONG *Ib, const ULONG *Words, ULONG Count, PULONG Fence) {
    if (!g_CpReady || !g_Ogo || !g_Ogo->Cp || !Fence) return STATUS_DEVICE_NOT_READY;
    if (!Count || Count > 512) return STATUS_INVALID_PARAMETER;
    KeWaitForSingleObject(&g_HwLock, Executive, KernelMode, FALSE, NULL);
    volatile ULONG *rb = (volatile ULONG *)g_Ogo->Cp->Run.Buffer[0].Cpu;
    /* Never overwrite ring dwords the CP has not fetched yet. */
    {
        ULONG need = 2u + Count * 4u + 5u + 8u;
        ULONG k;
        for (k = 0; k < 40000u; k++) {   /* up to ~4 s */
            ULONG rp = 0;
            (void)G482GpuRead(&g_Ogo->Io, 0x806u * 4u, &rp);
            ULONG freeDw = (rp + RB_DWORDS - g_Wptr - 1u) & (RB_DWORDS - 1u);
            if (freeDw >= need) break;
            LARGE_INTEGER dt; dt.QuadPart = -1000; /* 100 us */
            KeDelayExecutionThread(KernelMode, FALSE, &dt);
        }
        if (k == 40000u) {
            LogPrint("HwSubmit: ring full (wptr %u, need %u) - GPU not progressing\n", g_Wptr, need);
            KeReleaseMutex(&g_HwLock, FALSE);
            return STATUS_IO_TIMEOUT;
        }
    }
    ULONGLONG fenceAddr = g_Ogo->Cp->Run.Layout.Iova[1] + 4ULL;
    ULONG fence = g_NextFence++;
    /* Ensure A7xx BR+BV threads are enabled (g433 init left THREAD=0!) */
    uint32_t tcHdr = 0;
    if (!AdrenoPM4Type7(0x17u, 1u, &tcHdr)) {
        RbEmit(rb, tcHdr);
        RbEmit(rb, 0x08000003u); /* CONCURRENT_BIN_DISABLE | CP_SET_THREAD_BOTH */
    }
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
    InterlockedIncrement64(&g_StSubmits);
    __dsb(_ARM64_BARRIER_OSH);
    *Fence = fence;
    if (g_DiagSubmits < 12u) {
        g_DiagSubmits++;
        for (ULONG k = 0; k < 500u && HwCompletedFence() < fence; k++) {
            LARGE_INTEGER dt; dt.QuadPart = -1000;
            KeDelayExecutionThread(KernelMode, FALSE, &dt);
        }
        ULONG rbbm_st = 0, rbbm_int0 = 0, cp_hwf = 0, cp_int = 0, cp_prot = 0, rptr = 0, ib1_lo = 0, ib1_rem = 0;
        (void)G482GpuRead(&g_Ogo->Io, 0x210u * 4u, &rbbm_st);
        (void)G482GpuRead(&g_Ogo->Io, 0x201u * 4u, &rbbm_int0);
        (void)G482GpuRead(&g_Ogo->Io, 0x821u * 4u, &cp_hwf);
        (void)G482GpuRead(&g_Ogo->Io, 0x823u * 4u, &cp_int);
        (void)G482GpuRead(&g_Ogo->Io, 0x824u * 4u, &cp_prot);
        (void)G482GpuRead(&g_Ogo->Io, 0x806u * 4u, &rptr);
        (void)G482GpuRead(&g_Ogo->Io, 0x928u * 4u, &ib1_lo);
        (void)G482GpuRead(&g_Ogo->Io, 0x92au * 4u, &ib1_rem);
        ULONG fsr = 0, far_lo = 0, far_hi = 0;
        if (g_Ogo->Cp->Smmu) {
            PUCHAR sb = (PUCHAR)g_Ogo->Cp->Smmu;
            fsr = READ_REGISTER_ULONG((PULONG)(sb + CB0_BASE + 0x58));
            far_lo = READ_REGISTER_ULONG((PULONG)(sb + CB0_BASE + 0x60));
            far_hi = READ_REGISTER_ULONG((PULONG)(sb + CB0_BASE + 0x64));
        }
        LogPrint("DIAG submit#%u fence=%u done=%u n=%u ib0=%llx dw0=%u rptr=%u/%u rbbm=%08x int0=%08x hwf=%08x cpint=%08x prot=%08x ib1=%08x/%u fsr=%08x far=%08x%08x\n",
                 g_DiagSubmits, fence, HwCompletedFence(), Count,
                 Count ? Ib[0] : 0ULL, Count ? Words[0] : 0u,
                 rptr, g_Wptr, rbbm_st, rbbm_int0, cp_hwf, cp_int, cp_prot,
                 ib1_lo, ib1_rem, fsr, far_hi, far_lo);
    }
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
