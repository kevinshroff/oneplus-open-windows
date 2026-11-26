/*
 * Step C2 (docs/P8_gpu.md): the display side of TopazGpuW on the ACPI device GPU0 (TPZG0610).
 * Dxgkrnl treats an ACPI-enumerated display adapter as the platform GPU that owns the internal
 * panel, so this adapter has 1 VidPN source and 1 target (the DSI panel, 1080x2400 XRGB8888).
 *
 * Scanout: there is no MDP driver yet; the panel keeps scanning the UEFI GOP framebuffer at
 * 0x5C000000 (video mode, set up by the bootloader). The "flip" to a primary allocation is a CPU
 * copy of that allocation into the framebuffer (engine thread); blts into the scanned-out primary
 * copy their rectangles too. VSync is a 60 Hz timer reported as DXGK_INTERRUPT_CRTC_VSYNC through
 * DxgkCbSynchronizeExecution. Brightness: DCS 0x51 through DSI0 (same path as TopazDisplay
 * topaz_bl.cxx, docs/NOTES_brightness.md). VidPN code follows the KMDOD sample (TopazDisplay).
 */
#include "tgpu.h"

#ifndef TGPU_FB_WIDTH
#define TGPU_FB_WIDTH  2440u
#define TGPU_FB_HEIGHT 2268u
#define TGPU_FB_PITCH  (2440u * 4u)
#define TGPU_FB_PA     0x0ULL
#endif


/* GUID_DEVINTERFACE_BRIGHTNESS (ntddvdeo.h, already included by dispmprt.h without initguid) */
static const GUID g_BrightnessGuid = { 0xFDE5BBA4, 0xB3F9, 0x46FB, { 0xBD, 0xAA, 0x07, 0x28, 0xCE, 0x31, 0x00, 0xB4 } };



/* panel timing reported to Windows (blanking is nominal: command-mode panel) */
#define H_ACTIVE    (g_Post.Width ? g_Post.Width : 2440u)
#define V_ACTIVE    (g_Post.Height ? g_Post.Height : 2268u)
#define H_TOTAL     (H_ACTIVE + 160u)
#define V_TOTAL     (V_ACTIVE + 32u)
/* v0.50: the bootloader leaves the inner panel (AC052 P) in its 120 Hz mode and MDP autorefresh pushes a frame on
   every panel TE (INTF1 frame counter +0x0AC counts 120/s).
   v0.52: when that is measured at start and zero-copy scanout is active, the driver offers BOTH 60 and 120 Hz
   (target and monitor modes, EDID + DisplayID 1.3 extension for the 120 Hz timing) and follows whatever refresh
   Windows commits. STILL EXPERIMENTAL and opt-in (C:\topaz\panel.120hz): once Windows commits 120 Hz, DWM
   allocates new full-screen buffers continuously (~400 x 24 MB in a minute vs 18 per boot at 60 Hz) and they
   are only freed when its device goes away, so it runs out of memory and crash-loops (0xC00001AD). */
static ULONG g_Refresh = 60;                    /* refresh of the committed mode */
static BOOLEAN g_Panel120;                      /* 120 Hz is offered */
ULONG DispRefreshHz(VOID) { return g_Refresh; }
#define REFRESH     g_Refresh
#define INTF1_FRAME_COUNT 0x360ACu
#define INTF_XO_COUNTER   0x36214u              /* free-running 19.2 MHz */

static PDXGKRNL_INTERFACE g_Dxgk;
static DXGK_DISPLAY_INFORMATION g_Post;
static PUCHAR g_Fb;                             /* WC mapping of the framebuffer */
static BOOLEAN g_Visible = TRUE;
static BOOLEAN g_Committed;

static TGPU_ALLOCATION * volatile g_ScanCur;    /* primary being "scanned out" */

/* v0.38 direct scanout: the bootloader's MDP path is VIG0 -> LM0 -> CTL0 -> INTF1 -> DSI0, fetching the
   GOP framebuffer 0x5C000000 (stride 4320); the MDP SMMU context (SID 0x420 -> CB3) has translation off,
   so VIG0 can fetch any physical address. Flipping to a BO-backed primary = new SRC0_ADDR/YSTRIDE0 +
   CTL flush (double-buffered, latched at the panel vsync): no CPU copy. Allocations without a BO
   (Dxgkrnl's own primaries) go back to the framebuffer + CPU copy. C:\topaz\gpuw.nodirect disables it. */
/* SM8550 (stock DT qcom,sde-*-off, MDSS 0x0AE00000): UEFI drives the inner panel with VIG0 (left half) and
   VIG1 (right half, SRC_XY x=1220) from the GOP framebuffer 0xB8000000, stride 9760, CTL0, command mode with
   autorefresh. The MDSS stream (SID 0x1C00) uses apps-SMMU context bank 4, which UEFI left with translation
   off; DWM's scanout buffers are scattered pages, so CB4 gets our own page tables (Cb4Enable). */
#define MDSS_PA             0x0AE00000ULL
#define MDSS_LEN            0x84000u
#define MDP_VIG0            0x5000
#define MDP_VIG1            0x7000
#define SSPP_SRC0_ADDR      0x14
#define SSPP_SRC_YSTRIDE0   0x24
#define SSPP_CUR_ADDR       0xA4
#define MDP_CTL0            0x16000
#define CTL_FLUSH           0x18
#define CTL_FLUSH_VIG0      (1u << 0)
#define CTL_FLUSH_VIG1      (1u << 1)
#define CTL_FLUSH_CTL       (1u << 17)
static volatile UCHAR *g_Mdp;
static BOOLEAN g_DirectOk;                      /* mapped and not disabled */
static volatile LONG g_DirectActive;            /* VIG0 currently fetches a BO */
static KMUTEX g_ScanLock;                       /* engine copies vs. DestroyAllocation (defined below) */
static ULONG g_FbAddr, g_FbStride;              /* bootloader values, restored on fallback/stop */
static ULONG g_DirectFlips;
static PKEVENT g_UiEv;                          /* \BaseNamedObjects\OpenUiActivity: CPU governor UI boost */
static HANDLE g_UiEvH;
static volatile LONG g_UiFlips;

static BOOLEAN FileExists(PCWSTR Path)
{
    UNICODE_STRING n;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE h;
    RtlInitUnicodeString(&n, Path);
    InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&h, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
                                 FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0))) {
        return FALSE;
    }
    ZwClose(h);
    return TRUE;
}

static VOID MdpScanFrom(ULONG Pa, ULONG Stride)
{
    WRITE_REGISTER_ULONG((volatile ULONG *)(g_Mdp + MDP_VIG0 + SSPP_SRC0_ADDR), Pa);
    WRITE_REGISTER_ULONG((volatile ULONG *)(g_Mdp + MDP_VIG0 + SSPP_SRC_YSTRIDE0), Stride);
    WRITE_REGISTER_ULONG((volatile ULONG *)(g_Mdp + MDP_VIG1 + SSPP_SRC0_ADDR), Pa);
    WRITE_REGISTER_ULONG((volatile ULONG *)(g_Mdp + MDP_VIG1 + SSPP_SRC_YSTRIDE0), Stride);
    WRITE_REGISTER_ULONG((volatile ULONG *)(g_Mdp + MDP_CTL0 + CTL_FLUSH), CTL_FLUSH_VIG0 | CTL_FLUSH_VIG1 | CTL_FLUSH_CTL);
}

/* ---- apps-SMMU context bank 4 (MDSS) page tables: identity 2..4 GiB (framebuffer, DSI DMA buffers) with
   1 GiB blocks; scanout BOs mapped page by page into 0x10000000.. (32 MiB slots) */
#define SMMU_PA        0x15000000ULL
#define CB4_PA         (SMMU_PA + 128ULL * 0x1000 + 4ULL * 0x1000)
#define CB_SCTLR 0x000
#define CB_TCR2  0x010
#define CB_TTBR0 0x020
#define CB_TCR   0x030
#define CB_MAIR0 0x038
#define CB_FSR   0x058
#define CB_FAR   0x060
#define CB_TLBIALL 0x618
#define CB_TLBSYNC 0x7F0
#define CB_TLBSTATUS 0x7F4
#define SCAN_SLOTS 16
#define SCAN_SLOT_BYTES 0x2000000ULL
#define SCAN_IOVA0 0x10000000ULL
#define PT_MAX 224                                   /* 16 slots x 12 L3 + L2s + L1 */
typedef struct _SCAN_MAP { TGPU_BO *Bo; ULONG Refs; ULONGLONG Iova; SIZE_T Bytes; } SCAN_MAP;
static SCAN_MAP g_ScanMap[SCAN_SLOTS];
static volatile UCHAR *g_Cb4;
static ULONGLONG *g_Cb4L1;
static PHYSICAL_ADDRESS g_Cb4L1Pa;
static ULONGLONG *g_PtVa[PT_MAX];
static ULONGLONG g_PtPa[PT_MAX];
static ULONG g_PtN, g_Cb4SctlrOrig;
static BOOLEAN g_Cb4On;
static KSPIN_LOCK g_ScanMapLock;

static ULONG CbRd(ULONG o) { return READ_REGISTER_ULONG((volatile ULONG *)(g_Cb4 + o)); }
static VOID CbWr(ULONG o, ULONG v) { WRITE_REGISTER_ULONG((volatile ULONG *)(g_Cb4 + o), v); }

static VOID Cb4Tlbi(VOID)
{
    ULONG i;
    __dsb(_ARM64_BARRIER_SY);
    CbWr(CB_TLBIALL, 0);
    CbWr(CB_TLBSYNC, 0);
    for (i = 0; i < 1000 && (CbRd(CB_TLBSTATUS) & 1); i++) KeStallExecutionProcessor(1);
}

static ULONGLONG *PtAlloc(ULONGLONG *Pa)
{
    PHYSICAL_ADDRESS lo, hi, sk;
    PVOID va;
    if (g_PtN >= PT_MAX) return NULL;
    lo.QuadPart = 0; hi.QuadPart = 0xFFFFFFFFFULL; sk.QuadPart = 0;
    va = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, lo, hi, sk, MmNonCached);
    if (va == NULL) return NULL;
    RtlZeroMemory(va, PAGE_SIZE);
    g_PtVa[g_PtN] = (ULONGLONG *)va;
    g_PtPa[g_PtN] = (ULONGLONG)MmGetPhysicalAddress(va).QuadPart;
    *Pa = g_PtPa[g_PtN];
    return g_PtVa[g_PtN++];
}

static ULONGLONG *PtFind(ULONGLONG Pa)
{
    ULONG i;
    for (i = 0; i < g_PtN; i++) if (g_PtPa[i] == Pa) return g_PtVa[i];
    return NULL;
}

/* PASSIVE: map/unmap one 4 KiB page at Iova (< 2 GiB) */
static BOOLEAN Cb4Map(ULONGLONG Iova, ULONGLONG Pa)
{
    ULONG i1 = (ULONG)(Iova >> 30) & 511, i2 = (ULONG)(Iova >> 21) & 511, i3 = (ULONG)(Iova >> 12) & 511;
    ULONGLONG *l2, *l3, tp;
    if (!(g_Cb4L1[i1] & 1)) { if (!(l2 = PtAlloc(&tp))) return FALSE; g_Cb4L1[i1] = tp | 3; }
    else l2 = PtFind(g_Cb4L1[i1] & 0xFFFFFFFFF000ULL);
    if (!l2) return FALSE;
    if (!(l2[i2] & 1)) { if (!(l3 = PtAlloc(&tp))) return FALSE; l2[i2] = tp | 3; }
    else l3 = PtFind(l2[i2] & 0xFFFFFFFFF000ULL);
    if (!l3) return FALSE;
    l3[i3] = (Pa & 0xFFFFFFFFF000ULL) | 0x443;          /* page | AF | AP=RW | AttrIdx0 (normal NC) */
    return TRUE;
}

static VOID Cb4Unmap(ULONGLONG Iova)
{
    ULONG i1 = (ULONG)(Iova >> 30) & 511, i2 = (ULONG)(Iova >> 21) & 511, i3 = (ULONG)(Iova >> 12) & 511;
    ULONGLONG *l2, *l3;
    if (!(g_Cb4L1[i1] & 1) || !(l2 = PtFind(g_Cb4L1[i1] & 0xFFFFFFFFF000ULL))) return;
    if (!(l2[i2] & 1) || !(l3 = PtFind(l2[i2] & 0xFFFFFFFFF000ULL))) return;
    l3[i3] = 0;
}

/* PASSIVE, once: build identity tables and turn translation on for CB4 without disturbing the live stream */
static BOOLEAN Cb4Enable(VOID)
{
    PHYSICAL_ADDRESS pa;
    ULONG fsr;
    ULONGLONG l1pa;
    KeInitializeSpinLock(&g_ScanMapLock);
    pa.QuadPart = CB4_PA;
    g_Cb4 = (volatile UCHAR *)MmMapIoSpaceEx(pa, 0x1000, PAGE_READWRITE | PAGE_NOCACHE);
    if (g_Cb4 == NULL) return FALSE;
    g_Cb4SctlrOrig = CbRd(CB_SCTLR);
    if (g_Cb4SctlrOrig & 1) { LogPrint("cb4: translation already on (%08x) - leaving it\n", g_Cb4SctlrOrig); return FALSE; }
    g_Cb4L1 = PtAlloc(&l1pa);
    if (g_Cb4L1 == NULL) return FALSE;
    g_Cb4L1Pa.QuadPart = (LONGLONG)l1pa;
    g_Cb4L1[2] = 0x080000000ULL | 0x441;                 /* 1 GiB blocks, identity, normal NC, RW */
    g_Cb4L1[3] = 0x0C0000000ULL | 0x441;
    __dsb(_ARM64_BARRIER_SY);
    /* programmed as Linux arm-smmu does for an AArch64 stage-1 context (cb4_probe: TCR2 without SEP_UPSTREAM|AS
       translation-faults every fetch on this hypervisor-mediated SMMU; with them the stream translates cleanly) */
    CbWr(CB_TCR2, (7u << 15) | (1u << 4) | 1u);         /* SEP_UPSTREAM | AS (16-bit ASID) | PASize 36-bit */
    CbWr(CB_TCR, 25u | (2u << 12) | (1u << 23));        /* T0SZ 25 (39-bit), SH0 outer, NC walks, 4K, EPD1 */
    WRITE_REGISTER_ULONG64((volatile ULONG64 *)(g_Cb4 + CB_TTBR0), l1pa | (4ULL << 48));   /* ASID 4 */
    CbWr(CB_MAIR0, 0x00000044);                          /* attr0 = normal non-cacheable */
    Cb4Tlbi();
    CbWr(CB_FSR, CbRd(CB_FSR));                          /* clear stale status */
    CbWr(CB_SCTLR, 0x61);                                /* M | CFRE | CFIE, terminate (no stall) on fault */
    KeStallExecutionProcessor(50000);                    /* a few frames of real traffic */
    fsr = CbRd(CB_FSR);
    LogPrint("cb4: translation on, L1 %llx, SCTLR %08x (was %08x), FSR %08x FAR %08x%08x, VIG0 cur %08x\n", l1pa,
             CbRd(CB_SCTLR), g_Cb4SctlrOrig, fsr, CbRd(CB_FAR + 4), CbRd(CB_FAR),
             READ_REGISTER_ULONG((volatile ULONG *)(g_Mdp + MDP_VIG0 + SSPP_CUR_ADDR)));
    if (fsr & 0x400001FEu) {                             /* fault bits only: FSR[10:9] is FORMAT */
        CbWr(CB_SCTLR, g_Cb4SctlrOrig);                  /* back to bypass */
        CbWr(CB_FSR, fsr);
        LogPrint("cb4: fault after enable - translation off again, direct scanout disabled\n");
        return FALSE;
    }
    g_Cb4On = TRUE;
    return TRUE;
}

static VOID Cb4Disable(VOID)
{
    if (g_Cb4On) { CbWr(CB_SCTLR, g_Cb4SctlrOrig); Cb4Tlbi(); g_Cb4On = FALSE; }
}

static ULONGLONG ScanIova(TGPU_BO *Bo)
{
    ULONG i;
    for (i = 0; i < SCAN_SLOTS; i++) if (g_ScanMap[i].Bo == Bo && g_ScanMap[i].Refs) return g_ScanMap[i].Iova;
    return 0;
}

/* PASSIVE (CreateAllocation): map full-screen BO-backed allocations into CB4 so a flip needs no copy */
VOID DispAllocCreated(TGPU_ALLOCATION *Al)
{
    ULONG i, free = SCAN_SLOTS;
    SIZE_T pages, p;
    PPFN_NUMBER pfn;
    if (!g_Cb4On || Al == NULL || Al->Bo == NULL || Al->Bo->Mdl == NULL || Al->Desc.width != g_Post.Width ||
        Al->Desc.height != g_Post.Height || Al->Bo->Size > SCAN_SLOT_BYTES) {
        return;
    }
    KeWaitForSingleObject(&g_ScanLock, Executive, KernelMode, FALSE, NULL);
    for (i = 0; i < SCAN_SLOTS; i++) {
        if (g_ScanMap[i].Refs && g_ScanMap[i].Bo == Al->Bo) { g_ScanMap[i].Refs++; goto done; }
        if (!g_ScanMap[i].Refs && free == SCAN_SLOTS) free = i;
    }
    if (free == SCAN_SLOTS) goto done;
    pages = Al->Bo->Size >> PAGE_SHIFT;
    pfn = MmGetMdlPfnArray(Al->Bo->Mdl);
    for (p = 0; p < pages; p++) {
        if (!Cb4Map(SCAN_IOVA0 + free * SCAN_SLOT_BYTES + (p << PAGE_SHIFT), (ULONGLONG)pfn[p] << PAGE_SHIFT)) {
            LogPrint("cb4: out of page tables mapping bo %p\n", Al->Bo);
            while (p--) Cb4Unmap(SCAN_IOVA0 + free * SCAN_SLOT_BYTES + (p << PAGE_SHIFT));
            goto done;
        }
    }
    __dsb(_ARM64_BARRIER_SY);
    Cb4Tlbi();
    g_ScanMap[free].Bo = Al->Bo;
    g_ScanMap[free].Iova = SCAN_IOVA0 + free * SCAN_SLOT_BYTES;
    g_ScanMap[free].Bytes = Al->Bo->Size;
    g_ScanMap[free].Refs = 1;
    {
        static ULONG n;
        if (++n <= 12) LogPrint("cb4: scanout bo %p (%llu KB) -> mdp iova %llx\n", Al->Bo, (ULONGLONG)Al->Bo->Size / 1024,
                                g_ScanMap[free].Iova);
    }
done:
    KeReleaseMutex(&g_ScanLock, FALSE);
}

static VOID ScanUnmapLocked(TGPU_BO *Bo)
{
    ULONG i;
    SIZE_T p;
    for (i = 0; i < SCAN_SLOTS; i++) {
        if (g_ScanMap[i].Refs && g_ScanMap[i].Bo == Bo && --g_ScanMap[i].Refs == 0) {
            for (p = 0; p < (g_ScanMap[i].Bytes >> PAGE_SHIFT); p++) Cb4Unmap(g_ScanMap[i].Iova + (p << PAGE_SHIFT));
            __dsb(_ARM64_BARRIER_SY);
            Cb4Tlbi();
            g_ScanMap[i].Bo = NULL;
        }
    }
}

/* point VIG0/VIG1 at Al when it is a CB4-mapped full-screen primary; TRUE = no CPU copy needed. Any IRQL. */
static BOOLEAN DirectSelect(TGPU_ALLOCATION *Al)
{
    ULONGLONG iova = (g_DirectOk && Al != NULL && Al->Bo != NULL) ? ScanIova(Al->Bo) : 0;
    if (iova != 0 && Al->Desc.width == g_Post.Width && Al->Desc.height == g_Post.Height &&
        Al->Desc.pitch >= g_Post.Width * 4 && (Al->Desc.pitch & 63) == 0 &&
        Al->Desc.bo_offset + (SIZE_T)Al->Desc.pitch * Al->Desc.height <= Al->Bo->Size) {
        MdpScanFrom((ULONG)(iova + Al->Desc.bo_offset), Al->Desc.pitch);
        InterlockedExchange(&g_DirectActive, 1);
        g_DirectFlips++;
        return TRUE;
    }
    if (g_DirectOk && InterlockedExchange(&g_DirectActive, 0)) {
        MdpScanFrom(g_FbAddr, g_FbStride);
    }
    return FALSE;
}
static PHYSICAL_ADDRESS g_ScanPa;               /* its address as Dxgkrnl knows it (last flip) */
/* v0.45 async present: the UMD no longer waits for the GPU before presenting; a direct flip to a BO whose last
   submit is still running is programmed into the MDP only when that fence completed (1 ms timer) */
static TGPU_ALLOCATION *volatile g_DeferAl;
static volatile ULONG g_DeferFence;
static volatile LONG g_Deferred;
static ULONG g_DeferCount;
static PHYSICAL_ADDRESS g_ShownPa;              /* v0.40: address reported in CRTC_VSYNC = really on screen */
static ULONG g_FlipWaits;
static volatile LONG g_ScanDirty;
static volatile LONG g_FlipPending;
static volatile LONG g_VsyncOn;
static KMUTEX g_ScanLock;                       /* engine copies vs. DestroyAllocation */

static volatile LONG g_FlipCount;              /* v0.39: flips per second in the log */
static KTIMER g_VsyncTimer;
static KDPC g_VsyncDpc;
static BOOLEAN g_TimerOn;
static volatile LONG64 g_LastVsync;             /* KeQueryInterruptTime of the last vsync */
static ULONG g_VsyncCount;

/* ---------------------------------------------------------------- vsync */

static BOOLEAN VsyncSync(PVOID Ctx)
{
    DXGKARGCB_NOTIFY_INTERRUPT_DATA d;

    UNREFERENCED_PARAMETER(Ctx);
    RtlZeroMemory(&d, sizeof(d));
    d.InterruptType = DXGK_INTERRUPT_CRTC_VSYNC;
    d.CrtcVsync.VidPnTargetId = 0;
    d.CrtcVsync.PhysicalAddress = g_ShownPa;
    g_Dxgk->DxgkCbNotifyInterrupt(g_Dxgk->DeviceHandle, &d);
    g_Dxgk->DxgkCbQueueDpc(g_Dxgk->DeviceHandle);
    return TRUE;
}

/* v0.41: vsync work. Called from a 1 ms high-resolution timer: a flip is reported done right after the MDP
   latched it (CTL0_FLUSH VIG0 bit cleared = real panel vsync just passed) and the 60 Hz vsync phase is
   re-aligned to that moment. Before, a 16 ms KTIMER (actually ~15.6 ms clock ticks, not synced to the panel)
   checked the latch once per period, so a flip often took two periods and DWM settled at ~30 FPS. */
static PEX_TIMER g_HrTimer;
static LONG64 g_NextVsync;                       /* interrupt time (100 ns) of the next 60 Hz tick */
#define VSYNC_PERIOD (10000000LL / REFRESH)

/* v0.45.1: a WPR trace showed DxgKrnl getting only 31..40 vsyncs/s (intervals 30..35 ms): the "1 ms" timer
   callback arrived every ~15.6 ms, so `now >= g_NextVsync` held on every second callback only. Measure the
   real callback interval (logged with the fps line) and accept a tick up to half an interval early. */
static LONG64 g_CbLast, g_CbAvg;                 /* 100 ns; g_CbAvg = moving average (1/8) */
static LONG64 g_CbMin, g_CbMax;
static ULONG g_Ticks;                            /* vsyncs reported in the current second */
static BOOLEAN g_TimerRes;
static ULONG g_Shown;                            /* vsyncs with a new picture in the current second */
/* v0.45.3: with the mouse DWM flipped 99..166 times/s at 60 vsyncs/s and most flips never reached the panel: a flip
   was reported done as soon as the CTL flush bit read clear, which can happen sooner than one panel period after
   the previous one. Complete at most one flip per vsync period so DWM is paced to 60 Hz. */
static LONG64 g_LastFlipDone;
/* per-flip timing (100 ns units) for the PACE line */
static LONG64 g_PresLast, g_PresT, g_PresIntSum, g_LatSum, g_LatMax, g_DoneLast, g_DoneIntSum;
static LONG g_PresN, g_LatN, g_DoneN, g_TickN;
static BOOLEAN g_HeldThis;
/* v0.45.5: the stats window was 60 *ticks*, but a completed flip re-locks the tick phase, so while DWM flips ticks
   are rare and "60 vsyncs/s" was true by construction. Use a 1 s wall-clock window and count what DxgKrnl gets. */
static LONG64 g_StatStart;
static ULONG g_Notifies, g_Done;
static volatile LONG g_FlipOverrun, g_FlipImm;   /* v0.45.4: flips replacing a pending one / FlipImmediate flips */
static ULONG g_FlipHeld;                         /* flips held back for pacing in the current second */

static volatile LONG64 g_TotCb, g_TotNotify, g_TotFlipDone;   /* cumulative, for DispLogStats */
/* frame statistics (cumulative; logged by DispLogStats at PASSIVE) */
static volatile LONG64 g_StFlipReq, g_StCopies, g_StCopyUs, g_StCopyMaxUs, g_StCopyBytes;
/* Copy-mode frame ordering: every flip gets a sequence number; the scanout copy waits for that frame's GPU
 * fence, copies it, then publishes g_CopiedSeq. The flip is reported done only once its own copy finished,
 * so DWM never reuses a buffer that is still being copied and never sees a half-rendered frame. */
static volatile LONG g_FlipSeq, g_CopiedSeq;
static KDPC g_CopyDpc;
static volatile LONG g_LastSyncSt, g_LastSyncRet;

static VOID VsyncNotify(BOOLEAN flip)
{
    BOOLEAN ret = FALSE;
    if (g_Dxgk != NULL && (g_VsyncOn || flip)) {
        g_LastSyncSt = g_Dxgk->DxgkCbSynchronizeExecution(g_Dxgk->DeviceHandle, VsyncSync, NULL, 0, &ret);
        g_LastSyncRet = ret;
        InterlockedIncrement64(&g_TotNotify);
        if (++g_VsyncCount <= 3 || (flip && g_VsyncCount < 50)) {
            LogPrint("vsync %u%s pa %llx\n", g_VsyncCount, flip ? " (flip done)" : "", g_ScanPa.QuadPart);
        }
    }
}

/* v0.53 flip queue (MaxQueuedFlipOnVSync = 2): with one flip in flight DWM alternated between frames that made the
   next panel TE and frames that waited a second period (~77 fps at 120 Hz). A flip that arrives while another is
   still waiting for the MDP latch is held here and programmed the moment the earlier one latches; each flip is
   reported done with its own address, so none is skipped. Direct scanout only; C:\topaz\flipq1 keeps depth 1. */
static TGPU_ALLOCATION *volatile g_QAl;
static PHYSICAL_ADDRESS g_QPa;
static volatile LONG g_QValid;
static volatile LONG64 g_QFlips, g_QReplaced, g_QPromoted;
static ULONG g_FlipQueueDepth = 2;
static VOID TimerKick(VOID);

/* program one flip: deferred to its GPU fence, direct (MDP) or via the copy engine. Any IRQL up to DIRQL. */
static BOOLEAN FlipProgram(TGPU_ALLOCATION *Al, PHYSICAL_ADDRESS Pa)
{
    BOOLEAN direct;
    g_ScanCur = Al;
    g_ScanPa = Pa;
    g_PresT = (LONG64)KeQueryInterruptTime();
    InterlockedIncrement(&g_FlipSeq);
    if (g_DirectOk && Al != NULL && Al->Bo != NULL && ScanIova(Al->Bo) != 0 &&
        (LONG)(HwCompletedFence() - Al->Bo->LastFence) < 0) {
        g_DeferAl = Al;                                  /* GPU still rendering it: flip at fence completion */
        g_DeferFence = Al->Bo->LastFence;
        InterlockedExchange(&g_Deferred, 1);
        InterlockedExchange(&g_FlipPending, 1);
        g_DeferCount++;
        TimerKick();
        return TRUE;
    }
    InterlockedExchange(&g_Deferred, 0);
    direct = DirectSelect(Al);
    if (!direct) {
        InterlockedExchange(&g_ScanDirty, 1);
    }
    InterlockedExchange(&g_FlipPending, 1);
    TimerKick();
    if (!direct) {
        KeInsertQueueDpc(&g_CopyDpc, NULL, NULL);       /* start the copy now, not at the next tick */
    }
    return direct;
}

ULONG DispFlipQueueDepth(VOID) { return g_FlipQueueDepth; }

static VOID VsyncWork(BOOLEAN periodicTick)
{
    if (g_UiEv && g_UiFlips && InterlockedExchange(&g_UiFlips, 0)) {
        KeSetEvent(g_UiEv, IO_NO_INCREMENT, FALSE);
    }
    LONG64 now = (LONG64)KeQueryInterruptTime();
    BOOLEAN flip = FALSE, tick = FALSE;
    LONG64 slack = 0;

    InterlockedIncrement64(&g_TotCb);

    if (!periodicTick) {
        if (g_CbLast != 0) {
            LONG64 d = now - g_CbLast;
            g_CbAvg = g_CbAvg == 0 ? d : g_CbAvg + (d - g_CbAvg) / 8;
            if (g_CbMin == 0 || d < g_CbMin) {
                g_CbMin = d;
            }
            if (d > g_CbMax) {
                g_CbMax = d;
            }
        }
        g_CbLast = now;
        slack = g_CbAvg / 2;
        if (slack > VSYNC_PERIOD / 2) {
            slack = VSYNC_PERIOD / 2;
        }
    }

    if (g_Deferred) {
        if (((LONG)(HwCompletedFence() - g_DeferFence) >= 0 || now - g_PresT > 1000000LL) && g_DeferAl == g_ScanCur) {
            if ((LONG)(HwCompletedFence() - g_DeferFence) < 0)
                LogPrint("DEFER_TIMEOUT fence=%u done=%u\n", g_DeferFence, HwCompletedFence());
            InterlockedExchange(&g_Deferred, 0);
            if (!DirectSelect(g_DeferAl)) {
                InterlockedExchange(&g_ScanDirty, 1);
                KeInsertQueueDpc(&g_CopyDpc, NULL, NULL);
            }
        }
    }
    if (g_FlipPending && !g_Deferred) {
        if (g_DirectActive && g_Mdp != NULL &&
            (READ_REGISTER_ULONG((volatile ULONG *)(g_Mdp + MDP_CTL0 + CTL_FLUSH)) & (CTL_FLUSH_VIG0 | CTL_FLUSH_VIG1)) &&
            now - g_LastFlipDone < 4 * VSYNC_PERIOD) {      /* not latched yet (bounded: never stall DWM) */
            if (periodicTick || now >= g_NextVsync) {
                g_FlipWaits++;
            }
        } else if (!g_DirectActive && g_CopiedSeq != g_FlipSeq) {
            /* copy mode: the frame is not on the panel yet */
        } else if (now - g_LastFlipDone < VSYNC_PERIOD / 2) {
            if (!g_HeldThis) {                   /* latched, but the previous flip completed less than a period ago */
                g_HeldThis = TRUE;
                g_FlipHeld++;
            }
        } else {
            InterlockedExchange(&g_FlipPending, 0);
            if (g_ShownPa.QuadPart != g_ScanPa.QuadPart) {
                g_Shown++;
            }
            g_Done++;
            g_ShownPa = g_ScanPa;
            if (g_PresT != 0) {
                LONG64 lat = now - g_PresT;
                g_LatSum += lat; g_LatN++;
                if (lat > g_LatMax) g_LatMax = lat;
            }
            if (g_DoneLast != 0 && now - g_DoneLast < 2000000) { g_DoneIntSum += now - g_DoneLast; g_DoneN++; }
            g_DoneLast = now;
            g_LastFlipDone = now;
            flip = TRUE;
            InterlockedIncrement64(&g_TotFlipDone);
            g_HeldThis = FALSE;
            if (g_DirectActive) {
                g_NextVsync = now + VSYNC_PERIOD;        /* the latch happened at the panel vsync: lock phase */
            }
        }
    }
    if (periodicTick || now + slack >= g_NextVsync) {
        tick = TRUE;
        g_Ticks++;
        g_TickN++;
        if (!periodicTick) {
            g_NextVsync += VSYNC_PERIOD;
            if (g_NextVsync <= now) {
                g_NextVsync = now + VSYNC_PERIOD;
            }
        } else {
            g_NextVsync = now + VSYNC_PERIOD;            /* keep the phase for a later switch to fast polling */
        }
        g_LastVsync = now;
        if (InterlockedExchange(&g_ScanDirty, 0)) {
            EngKickScanout();
        }
    }
    if (flip || tick) {
        g_Notifies++;
        VsyncNotify(flip);
    }
    if (!g_FlipPending && g_QValid && InterlockedExchange(&g_QValid, 0)) {
        KeMemoryBarrier();
        InterlockedIncrement64(&g_QPromoted);
        FlipProgram(g_QAl, g_QPa);                       /* the queued flip goes to the MDP right after the latch */
    }
    if (g_StatStart == 0) {
        g_StatStart = now;
    } else if (now - g_StatStart >= 10000000LL) {
        LONG f = InterlockedExchange(&g_FlipCount, 0);
        if (f != 0) {
            LogPrint("fps: %u shown/s, %ld flips/s, %u done, %u held, %ld overrun, %ld immediate | vsync notifies %u "
                     "(%u timer ticks) in %lld ms | timer cb %lld..%lld avg %lld us (%s, %u waits for the MDP latch, "
                     "%u deferred to the GPU fence)\n", g_Shown, f, g_Done, g_FlipHeld,
                     InterlockedExchange(&g_FlipOverrun, 0), InterlockedExchange(&g_FlipImm, 0), g_Notifies, g_Ticks,
                     (now - g_StatStart) / 10000, g_CbMin / 10, g_CbMax / 10, g_CbAvg / 10,
                     g_DirectActive ? "direct" : "copy", g_FlipWaits, g_DeferCount);
        }
        g_StatStart = now;
        g_Ticks = 0;
        g_Shown = 0;
        g_Done = 0;
        g_Notifies = 0;
        g_FlipHeld = 0;
        g_CbMin = 0;
        g_CbMax = 0;
    }
}

static KDEFERRED_ROUTINE VsyncDpc;
static VOID VsyncDpc(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(A1);
    UNREFERENCED_PARAMETER(A2);
    VsyncWork(TRUE);                             /* fallback KTIMER path: one call per ~16 ms */
}

/* Power: the vsync timer runs at 60 Hz only while there is display work (DWM has the vsync interrupt
 * enabled, a flip is pending/deferred, or the scanout copy is dirty) and stops after ~0.5 s idle.
 * Before, a 1 ms high-resolution timer plus a global 1 ms timer resolution woke a CPU 1000x/s forever. */
static volatile LONG g_TimerRunning;
/* v0.51 pacing: the timer ran once per period, so a flip the MDP latched on a (120 Hz) panel TE was noticed up to a
   period late and, if held, another period later: DWM averaged 25.8 ms per frame at "60 Hz". While a flip is
   pending or deferred the timer now polls every 1 ms (VsyncWork non-periodic path: the flip completes the moment the
   latch is seen and the vsync phase locks to it); once nothing is pending it returns to one tick per period,
   phase-aligned to g_NextVsync. */
static volatile LONG g_FastPoll, g_WantFast;
static volatile LONG g_Stopping;                 /* DispStop in progress: nothing may re-arm g_HrTimer */
static volatile LONG64 g_FastSwitches;
static KSPIN_LOCK g_TimerLock;
static KDPC g_KickDpc;
static ULONG g_IdleTicks;
static volatile LONG64 g_TimerStarts, g_TimerStops;

static BOOLEAN DispBusy(VOID)
{
    return g_VsyncOn || g_FlipPending || g_Deferred || g_ScanDirty || g_QValid;
}

static VOID TimerEnsure(VOID)
{
    KIRQL irql;
    if (g_HrTimer == NULL || g_TimerRunning || g_Stopping) {
        return;
    }
    KeAcquireSpinLock(&g_TimerLock, &irql);
    if (!g_TimerRunning && g_HrTimer != NULL && !g_Stopping) {
        g_IdleTicks = 0;
        InterlockedExchange(&g_TimerRunning, 1);
        ExSetTimer(g_HrTimer, -VSYNC_PERIOD, VSYNC_PERIOD, NULL);
        InterlockedIncrement64(&g_TimerStarts);
    }
    KeReleaseSpinLock(&g_TimerLock, irql);
}

/* DISPATCH: switch the high-resolution timer between 1 ms flip polling and one tick per vsync period */
static VOID TimerFast(BOOLEAN On)
{
    KIRQL irql;
    if (g_HrTimer == NULL || g_Stopping) {
        return;
    }
    KeAcquireSpinLock(&g_TimerLock, &irql);
    if (g_HrTimer == NULL || g_Stopping) {
        KeReleaseSpinLock(&g_TimerLock, irql);
        return;
    }
    if (On && !g_FastPoll) {
        InterlockedExchange(&g_FastPoll, 1);
        InterlockedExchange(&g_TimerRunning, 1);
        g_IdleTicks = 0;
        g_CbLast = 0;
        ExSetTimer(g_HrTimer, -5000LL, 5000LL, NULL);
        InterlockedIncrement64(&g_FastSwitches);
    } else if (!On && g_FastPoll) {
        LONG64 due = g_NextVsync - (LONG64)KeQueryInterruptTime();
        if (due < 10000LL || due > VSYNC_PERIOD) {
            due = VSYNC_PERIOD;
        }
        InterlockedExchange(&g_FastPoll, 0);
        ExSetTimer(g_HrTimer, -due, VSYNC_PERIOD, NULL);
    }
    KeReleaseSpinLock(&g_TimerLock, irql);
}

static KDEFERRED_ROUTINE KickDpc;
static VOID KickDpc(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc); UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(A1); UNREFERENCED_PARAMETER(A2);
    if (InterlockedExchange(&g_WantFast, 0) && g_DirectActive) {
        TimerFast(TRUE);                         /* direct scanout: poll the MDP latch every 1 ms */
    } else {
        TimerEnsure();
    }
}

/* any IRQL (SetVidPnSourceAddress may run at DIRQL): set the work flag first, then call this */
static VOID TimerKick(VOID)
{
    if (g_HrTimer == NULL || g_Stopping) {
        return;
    }
    if ((g_FlipPending || g_QValid) && !g_FastPoll) {
        InterlockedExchange(&g_WantFast, 1);
        KeInsertQueueDpc(&g_KickDpc, NULL, NULL);
    } else if (!g_TimerRunning) {
        KeInsertQueueDpc(&g_KickDpc, NULL, NULL);
    }
}

static VOID TimerMaybeStop(VOID)
{
    KIRQL irql;
    if (DispBusy()) {
        g_IdleTicks = 0;
        return;
    }
    if (++g_IdleTicks < 30) {
        return;
    }
    KeAcquireSpinLock(&g_TimerLock, &irql);
    if (!DispBusy() && g_HrTimer != NULL) {
        InterlockedExchange(&g_TimerRunning, 0);
        ExCancelTimer(g_HrTimer, NULL);
        InterlockedIncrement64(&g_TimerStops);
        if (DispBusy() && !g_Stopping) {         /* work raced in after the check: keep ticking */
            InterlockedExchange(&g_TimerRunning, 1);
            ExSetTimer(g_HrTimer, -VSYNC_PERIOD, VSYNC_PERIOD, NULL);
        }
    }
    KeReleaseSpinLock(&g_TimerLock, irql);
}

static EXT_CALLBACK HrTimerCb;
static VOID HrTimerCb(PEX_TIMER Timer, PVOID Ctx)
{
    UNREFERENCED_PARAMETER(Timer);
    UNREFERENCED_PARAMETER(Ctx);
    if (g_FastPoll) {
        VsyncWork(FALSE);                        /* 1 ms: complete the flip at the MDP latch */
        if (!g_FlipPending && !g_Deferred && !g_QValid) {
            TimerFast(FALSE);
        }
        return;
    }
    VsyncWork(TRUE);                             /* one call per vsync period */
    TimerMaybeStop();
}

/* PASSIVE: one line of display/vsync state for the heartbeat in ddi.c */
VOID DispLogStats(VOID)
{
    LogPrint("DISP cb %lld notify %lld flipsDone %lld flipsReq %ld | vsyncOn %ld flipPending %ld deferred %ld held %u "
             "| sync st %08x ret %ld | scanPa %llx shownPa %llx | timer %s starts %lld stops %lld\n",
             g_TotCb, g_TotNotify, g_TotFlipDone, g_FlipCount, g_VsyncOn, g_FlipPending, g_Deferred, g_FlipHeld,
             g_LastSyncSt, g_LastSyncRet, g_ScanPa.QuadPart, g_ShownPa.QuadPart,
             g_TimerRunning ? "on" : "off", g_TimerStarts, g_TimerStops);
    LogPrint("PACE %u Hz fast %ld switches %lld waits %u | presents %ld avg %lld us | done %ld avg %lld us | present->done avg %lld "
             "max %lld us | vsync ticks %ld | queue %lld promoted %lld replaced %lld\n", REFRESH, g_FastPoll, g_FastSwitches, g_FlipWaits,
             g_PresN, g_PresN ? g_PresIntSum / g_PresN / 10 : 0, g_DoneN, g_DoneN ? g_DoneIntSum / g_DoneN / 10 : 0,
             g_LatN ? g_LatSum / g_LatN / 10 : 0, g_LatMax / 10, g_TickN, g_QFlips, g_QPromoted, g_QReplaced);
    g_PresN = 0; g_PresIntSum = 0; g_LatN = 0; g_LatSum = 0; g_LatMax = 0; g_DoneN = 0; g_DoneIntSum = 0; g_TickN = 0;
    {
        ULONG fsr = g_Cb4On ? CbRd(CB_FSR) : 0;
        LogPrint("FRAME flipsReq %lld flipsDone %lld copies %lld copyUs %lld copyMaxUs %lld copyMB %lld | direct %u active %d "
                 "cb4 fsr %08x pt %u\n", g_StFlipReq, g_TotFlipDone, g_StCopies, g_StCopyUs, g_StCopyMaxUs,
                 g_StCopyBytes >> 20, g_DirectFlips, g_DirectActive, fsr, g_PtN);
        if (fsr & 0x400001FEu) {                         /* runtime fault: fall back to the copy path for good */
            LogPrint("cb4: fault FAR %08x%08x FSYNR0 %08x - direct scanout off\n", CbRd(CB_FAR + 4), CbRd(CB_FAR),
                     CbRd(0x68));
            g_DirectOk = FALSE;
            InterlockedExchange(&g_DirectActive, 0);
            MdpScanFrom(g_FbAddr, g_FbStride);
            CbWr(CB_FSR, fsr);
            InterlockedExchange(&g_ScanDirty, 1);
            KeInsertQueueDpc(&g_CopyDpc, NULL, NULL);
        }
    }
}

VOID DispVsyncEnable(BOOLEAN Enable)
{
    InterlockedExchange(&g_VsyncOn, Enable ? 1 : 0);
    if (Enable) {
        TimerKick();
    }
}

NTSTATUS DispGetScanLine(DXGKARG_GETSCANLINE *A)
{
    LONG64 since = (LONG64)KeQueryInterruptTime() - g_LastVsync;     /* 100 ns */
    LONG64 frame = 10000000LL / REFRESH;
    ULONG line;

    if (since < 0 || since >= frame) {
        since = 0;
    }
    line = (ULONG)(since * V_TOTAL / frame);
    A->InVerticalBlank = line >= V_ACTIVE;
    A->ScanLine = line;
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- scanout */

static VOID CopyRectToFb(PUCHAR Src, ULONG SrcPitch, ULONG SrcW, ULONG SrcH, const RECT *R)
{
    LONG l = R->left, t = R->top, r = R->right, b = R->bottom, y;

    if (l < 0) l = 0;
    if (t < 0) t = 0;
    if (r > (LONG)SrcW) r = SrcW;
    if (b > (LONG)SrcH) b = SrcH;
    if (r > (LONG)g_Post.Width) r = g_Post.Width;
    if (b > (LONG)g_Post.Height) b = g_Post.Height;
    if (r <= l || b <= t) {
        return;
    }
    for (y = t; y < b; y++) {
        RtlCopyMemory(g_Fb + (SIZE_T)y * g_Post.Pitch + (SIZE_T)l * 4, Src + (SIZE_T)y * SrcPitch + (SIZE_T)l * 4,
                      (SIZE_T)(r - l) * 4);
    }
}


static KDEFERRED_ROUTINE CopyDpc;
static VOID CopyDpc(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc); UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(A1); UNREFERENCED_PARAMETER(A2);
    if (InterlockedExchange(&g_ScanDirty, 0)) {
        EngKickScanout();
    }
}

/* Parallel copy: reads from the write-combined BO mapping are latency bound per core, so the frame is
 * split by rows across workers pinned to the performance cores (CPU 4..7). */
#define COPY_WORKERS 4
typedef struct _COPY_JOB { PUCHAR Src; ULONG SrcPitch; ULONG Rows; ULONG RowBytes; } COPY_JOB;
static COPY_JOB g_Job;
static KEVENT g_CopyGo[COPY_WORKERS], g_CopyDone, g_CopyStop;
static volatile LONG g_CopyLeft;
static PKTHREAD g_CopyThr[COPY_WORKERS];
static BOOLEAN g_CopyPool;

static VOID CopyRows(ULONG W)
{
    ULONG y0 = g_Job.Rows * W / COPY_WORKERS, y1 = g_Job.Rows * (W + 1) / COPY_WORKERS, y;
    for (y = y0; y < y1; y++) {
        RtlCopyMemory(g_Fb + (SIZE_T)y * g_Post.Pitch, g_Job.Src + (SIZE_T)y * g_Job.SrcPitch, g_Job.RowBytes);
    }
}

static KSTART_ROUTINE CopyWorker;
static VOID CopyWorker(PVOID Ctx)
{
    ULONG w = (ULONG)(ULONG_PTR)Ctx;
    PVOID objs[2] = { &g_CopyGo[w], &g_CopyStop };
    KAFFINITY aff = (KAFFINITY)1 << (4 + w);
    KeSetSystemAffinityThreadEx(aff);
    for (;;) {
        if (KeWaitForMultipleObjects(2, objs, WaitAny, Executive, KernelMode, FALSE, NULL, NULL) != STATUS_WAIT_0) {
            break;
        }
        CopyRows(w);
        if (InterlockedDecrement(&g_CopyLeft) == 0) {
            KeSetEvent(&g_CopyDone, IO_NO_INCREMENT, FALSE);
        }
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID CopyPoolStart(VOID)
{
    ULONG i;
    HANDLE th;
    if (g_CopyPool) {
        return;
    }
    KeInitializeEvent(&g_CopyDone, SynchronizationEvent, FALSE);
    KeInitializeEvent(&g_CopyStop, NotificationEvent, FALSE);
    for (i = 0; i < COPY_WORKERS; i++) {
        KeInitializeEvent(&g_CopyGo[i], SynchronizationEvent, FALSE);
        if (NT_SUCCESS(PsCreateSystemThread(&th, THREAD_ALL_ACCESS, NULL, NULL, NULL, CopyWorker, (PVOID)(ULONG_PTR)i))) {
            ObReferenceObjectByHandle(th, SYNCHRONIZE, *PsThreadType, KernelMode, (PVOID *)&g_CopyThr[i], NULL);
            ZwClose(th);
        }
    }
    g_CopyPool = TRUE;
    for (i = 0; i < COPY_WORKERS; i++) {
        if (g_CopyThr[i] == NULL) {
            g_CopyPool = FALSE;                  /* fall back to a single-threaded copy */
        }
    }
    LogPrint("scanout: %u-way parallel copy %s\n", COPY_WORKERS, g_CopyPool ? "ready" : "unavailable");
}

static VOID CopyPoolStop(VOID)
{
    ULONG i;
    if (!g_CopyThr[0] && !g_CopyThr[1] && !g_CopyThr[2] && !g_CopyThr[3]) {
        return;
    }
    KeSetEvent(&g_CopyStop, IO_NO_INCREMENT, FALSE);
    for (i = 0; i < COPY_WORKERS; i++) {
        if (g_CopyThr[i]) {
            KeWaitForSingleObject(g_CopyThr[i], Executive, KernelMode, FALSE, NULL);
            ObDereferenceObject(g_CopyThr[i]);
            g_CopyThr[i] = NULL;
        }
    }
    g_CopyPool = FALSE;
}

static VOID CopyFrameToFb(PUCHAR Src, ULONG SrcPitch, ULONG W, ULONG H)
{
    ULONG i;
    if (W > g_Post.Width) W = g_Post.Width;
    if (H > g_Post.Height) H = g_Post.Height;
    if (!g_CopyPool) {
        RECT all = { 0, 0, (LONG)W, (LONG)H };
        CopyRectToFb(Src, SrcPitch, W, H, &all);
        return;
    }
    g_Job.Src = Src;
    g_Job.SrcPitch = SrcPitch;
    g_Job.Rows = H;
    g_Job.RowBytes = W * 4;
    KeClearEvent(&g_CopyDone);
    InterlockedExchange(&g_CopyLeft, COPY_WORKERS);
    for (i = 0; i < COPY_WORKERS; i++) {
        KeSetEvent(&g_CopyGo[i], IO_NO_INCREMENT, FALSE);
    }
    KeWaitForSingleObject(&g_CopyDone, Executive, KernelMode, FALSE, NULL);
}

static LONG64 NowUs(VOID)
{
    LARGE_INTEGER f, c = KeQueryPerformanceCounter(&f);
    return c.QuadPart * 1000000LL / f.QuadPart;
}

VOID DispScanoutWork(VOID)
{
    TGPU_ALLOCATION *al;
    PUCHAR px;
    RECT all;
    static ULONG count;
    LONG64 t0 = NowUs(), dt;

    LONG seq;
    KeWaitForSingleObject(&g_ScanLock, Executive, KernelMode, FALSE, NULL);
    seq = g_FlipSeq;
    al = g_ScanCur;
    UNREFERENCED_PARAMETER(all);
    if (al != NULL && !g_DirectActive && g_Fb != NULL && g_Visible && (px = AllocPixels(al)) != NULL) {
        if (al->Bo != NULL) {
            HwWaitFence(al->Bo->LastFence, 100);        /* never copy a frame the GPU is still drawing */
        }
        CopyFrameToFb(px, al->Desc.pitch, al->Desc.width, al->Desc.height);
        dt = NowUs() - t0;
        InterlockedIncrement64(&g_StCopies);
        InterlockedAdd64(&g_StCopyUs, dt);
        InterlockedAdd64(&g_StCopyBytes, (LONG64)al->Desc.pitch * al->Desc.height);
        if (dt > g_StCopyMaxUs) g_StCopyMaxUs = dt;
        if (++count <= 5) {
            LogPrint("scanout: %ux%u pitch %u from %p (%s)\n", al->Desc.width, al->Desc.height, al->Desc.pitch, al,
                     al->Bo != NULL ? "bo" : "vidmm");
        }
    }
    InterlockedExchange(&g_CopiedSeq, seq);             /* this flip is on the panel (or nothing to show) */
    KeReleaseMutex(&g_ScanLock, FALSE);
    if (g_FlipPending) {
        TimerKick();                                     /* complete the flip at the next tick */
    }
}

VOID DispPresentRects(TGPU_ALLOCATION *Dst, const RECT *Rects, ULONG Count)
{
    PUCHAR px;
    ULONG i;

    if (Dst != g_ScanCur || g_DirectActive || g_Fb == NULL || !g_Visible) {
        return;
    }
    KeWaitForSingleObject(&g_ScanLock, Executive, KernelMode, FALSE, NULL);
    if (Dst == g_ScanCur && (px = AllocPixels(Dst)) != NULL) {
        for (i = 0; i < Count; i++) {
            CopyRectToFb(px, Dst->Desc.pitch, Dst->Desc.width, Dst->Desc.height, &Rects[i]);
        }
    }
    KeReleaseMutex(&g_ScanLock, FALSE);
}

VOID DispAllocDestroyed(TGPU_ALLOCATION *Al)
{
    KeWaitForSingleObject(&g_ScanLock, Executive, KernelMode, FALSE, NULL);
    if (g_QAl == Al && InterlockedExchange(&g_QValid, 0)) {
        g_QAl = NULL;                                    /* never promote a freed allocation */
    }
    if (g_DeferAl == Al) {                               /* never flip to a freed BO later */
        InterlockedExchange(&g_Deferred, 0);
        g_DeferAl = NULL;
    }
    if (g_ScanCur == Al) {
        DirectSelect(NULL);                              /* never fetch from a freed BO */
        g_ScanCur = NULL;
        LogPrint("scanout: primary %p destroyed while scanned out\n", Al);
    }
    if (g_Cb4On && Al != NULL && Al->Bo != NULL) {
        if (g_DirectActive && g_ScanCur != NULL && g_ScanCur->Bo == Al->Bo) {
            DirectSelect(NULL);
        }
        KeStallExecutionProcessor(20000);                /* let the MDP latch away from it */
        ScanUnmapLocked(Al->Bo);
    }
    KeReleaseMutex(&g_ScanLock, FALSE);
}

/* may run at DIRQL (MMIO-style flip): only plain stores, the vsync DPC does the rest */
NTSTATUS DispSetSourceAddress(const DXGKARG_SETVIDPNSOURCEADDRESS *A)
{
    static ULONG count;
    TGPU_ALLOCATION *al = (TGPU_ALLOCATION *)A->hAllocation;
    BOOLEAN direct;

    if (A->Flags.FlipImmediate) {
        InterlockedIncrement(&g_FlipImm);
    }
    InterlockedIncrement(&g_FlipCount);
    InterlockedIncrement64(&g_StFlipReq);
    {
        LONG64 t = (LONG64)KeQueryInterruptTime();
        if (g_PresLast != 0 && t - g_PresLast < 2000000) { g_PresIntSum += t - g_PresLast; g_PresN++; }
        g_PresLast = t;
    }
    InterlockedExchange(&g_UiFlips, 1);                   /* signalled from the vsync DPC (may be at DIRQL here) */
    if (g_FlipQueueDepth > 1 && g_FlipPending && g_DirectActive && !A->Flags.FlipImmediate) {
        if (InterlockedExchange(&g_QValid, 0)) {
            InterlockedIncrement64(&g_QReplaced);        /* more than one queued: the newest wins */
        }
        g_QAl = al;
        g_QPa = A->PrimaryAddress;
        KeMemoryBarrier();
        InterlockedExchange(&g_QValid, 1);
        InterlockedIncrement64(&g_QFlips);
        TimerKick();
        return STATUS_SUCCESS;
    }
    if (g_FlipPending) {
        InterlockedIncrement(&g_FlipOverrun);
    }
    InterlockedExchange(&g_QValid, 0);
    direct = FlipProgram(al, A->PrimaryAddress);
    if (++count <= 60) {
        LogPrint("SetVidPnSourceAddress: src %u alloc %p seg %u pa %llx flags %x%s\n", A->VidPnSourceId, A->hAllocation,
                 A->PrimarySegment, A->PrimaryAddress.QuadPart, A->Flags.Value, direct ? " (direct scanout)" : "");
    }
    return STATUS_SUCCESS;
}

static VOID BlPanel(BOOLEAN On);

NTSTATUS DispSetVisibility(const DXGKARG_SETVIDPNSOURCEVISIBILITY *A)
{
    BOOLEAN visible = A->Visible ? TRUE : FALSE;

    static BOOLEAN fbCleared;

    LogPrint("SetVidPnSourceVisibility: src %u visible %u\n", A->VidPnSourceId, A->Visible);
    /* v0.45.8: the boot framebuffer still held the last boot picture (spinner) and showed up for a moment
       whenever the scanout fell back to it around a screen-off. Clear it once (PASSIVE here). */
    if (!fbCleared && g_Fb != NULL && g_DirectActive) {
        RtlZeroMemory(g_Fb, (SIZE_T)g_Post.Pitch * g_Post.Height);
        fbCleared = TRUE;
        LogPrint("boot framebuffer cleared\n");
    }
    if (visible != g_Visible) {
        BlPanel(visible);                                /* v0.45.6: screen off = backlight off */
    }
    g_Visible = visible;
    if (g_Visible) {
        InterlockedExchange(&g_ScanDirty, 1);
    }
    return STATUS_SUCCESS;
}

VOID DispSystemWrite(PVOID Src, UINT W, UINT H, UINT Stride, UINT X, UINT Y)
{
    UINT y;

    if (g_Fb == NULL && g_Post.PhysicAddress.QuadPart != 0) {
        return;
    }
    if (g_DirectOk && g_DirectActive) {                  /* bugcheck screen: back to the framebuffer */
        g_DirectActive = 0;
        MdpScanFrom(g_FbAddr, g_FbStride);
    }
    for (y = 0; y < H && Y + y < g_Post.Height; y++) {
        UINT w = (X + W > g_Post.Width) ? (X < g_Post.Width ? g_Post.Width - X : 0) : W;
        RtlCopyMemory(g_Fb + (SIZE_T)(Y + y) * g_Post.Pitch + (SIZE_T)X * 4, (PUCHAR)Src + (SIZE_T)y * Stride,
                      (SIZE_T)w * 4);
    }
}

/* ---------------------------------------------------------------- start / stop */

static VOID InitBrightness(VOID);

NTSTATUS DispStart(PDXGKRNL_INTERFACE Dxgk)
{
    NTSTATUS st;
    LARGE_INTEGER due;

    g_Dxgk = Dxgk;
    InterlockedExchange(&g_Stopping, 0);
    g_FlipQueueDepth = FileExists(L"\\??\\C:\\topaz\\flipq2") ? 2 : 1;   /* DWM never queued: opt-in only */
    InterlockedExchange(&g_QValid, 0);
    KeInitializeMutex(&g_ScanLock, 0);
    RtlZeroMemory(&g_Post, sizeof(g_Post));
    st = Dxgk->DxgkCbAcquirePostDisplayOwnership(Dxgk->DeviceHandle, &g_Post);
    LogPrint("AcquirePostDisplayOwnership: %08x %ux%u pitch %u fmt %u pa %llx target %u acpi %u\n", st, g_Post.Width,
             g_Post.Height, g_Post.Pitch, g_Post.ColorFormat, g_Post.PhysicAddress.QuadPart, g_Post.TargetId, g_Post.AcpiId);
    if (!NT_SUCCESS(st) || g_Post.Width == 0 || g_Post.PhysicAddress.QuadPart == 0) {
        /* same fallback as TopazDisplay: the GOP framebuffer the bootloader left running */
        g_Post.Width = TGPU_FB_WIDTH;
        g_Post.Height = TGPU_FB_HEIGHT;
        g_Post.Pitch = TGPU_FB_PITCH;
        g_Post.ColorFormat = D3DDDIFMT_X8R8G8B8;
        g_Post.PhysicAddress.QuadPart = (LONGLONG)TGPU_FB_PA;
        g_Post.TargetId = 0;
        LogPrint("POST info empty: using the fixed framebuffer %llx\n", TGPU_FB_PA);
    }
    if (g_Fb == NULL && g_Post.PhysicAddress.QuadPart != 0) {
        g_Fb = (PUCHAR)MmMapIoSpaceEx(g_Post.PhysicAddress, (SIZE_T)g_Post.Pitch * g_Post.Height,
                                      PAGE_READWRITE | PAGE_WRITECOMBINE);
    }
    LogPrint("framebuffer mapped at %p\n", g_Fb);
    InitBrightness();                                    /* SM8550 DSI0 DCS 0x51 */
    /* SM8550: skip SM6225 MDP survey */
    if (g_UiEv == NULL) {
        UNICODE_STRING en = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\OpenUiActivity");
        g_UiEv = IoCreateNotificationEvent(&en, &g_UiEvH);
    }
    if (g_Mdp == NULL) {
        PHYSICAL_ADDRESS mpa;
        UNICODE_STRING nd = RTL_CONSTANT_STRING(L"\\??\\C:\\topaz\\gpuw.nodirect");
        OBJECT_ATTRIBUTES oa;
        IO_STATUS_BLOCK iosb;
        HANDLE h;
        BOOLEAN off = FALSE;

        InitializeObjectAttributes(&oa, &nd, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        if (NT_SUCCESS(ZwCreateFile(&h, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                                    FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0))) {
            ZwClose(h);
            off = TRUE;
        }
        mpa.QuadPart = (LONGLONG)MDSS_PA;
        g_Mdp = (volatile UCHAR *)MmMapIoSpaceEx(mpa, MDSS_LEN, PAGE_READWRITE | PAGE_NOCACHE);
        if (g_Mdp != NULL) {
            g_FbAddr = READ_REGISTER_ULONG((volatile ULONG *)(g_Mdp + MDP_VIG0 + SSPP_SRC0_ADDR));
            g_FbStride = READ_REGISTER_ULONG((volatile ULONG *)(g_Mdp + MDP_VIG0 + SSPP_SRC_YSTRIDE0));
            g_DirectOk = !off && g_FbAddr == (ULONG)g_Post.PhysicAddress.QuadPart && g_FbStride == g_Post.Pitch &&
                         READ_REGISTER_ULONG((volatile ULONG *)(g_Mdp + MDP_VIG1 + SSPP_SRC0_ADDR)) == g_FbAddr;
            if (g_DirectOk) {
                g_DirectOk = Cb4Enable();
            }
        }
        LogPrint("direct scanout: %s (VIG0/1 addr %08x stride %u%s)\n", g_DirectOk ? "on" : "off", g_FbAddr, g_FbStride,
                 off ? ", gpuw.nodirect" : "");
    }
    if (g_Mdp != NULL) {
        ULONG f0, f1, x0, x1, hz;
        LARGE_INTEGER dt;
        BOOLEAN force60 = !FileExists(L"\\??\\C:\\topaz\\panel.120hz");
        f0 = READ_REGISTER_ULONG((volatile ULONG *)(g_Mdp + INTF1_FRAME_COUNT));
        x0 = READ_REGISTER_ULONG((volatile ULONG *)(g_Mdp + INTF_XO_COUNTER));
        dt.QuadPart = -2500000LL;                        /* 250 ms */
        KeDelayExecutionThread(KernelMode, FALSE, &dt);
        f1 = READ_REGISTER_ULONG((volatile ULONG *)(g_Mdp + INTF1_FRAME_COUNT));
        x1 = READ_REGISTER_ULONG((volatile ULONG *)(g_Mdp + INTF_XO_COUNTER));
        hz = (x1 - x0) ? (ULONG)((ULONGLONG)(f1 - f0) * 19200000ULL / (ULONG)(x1 - x0)) : 0;
        g_Panel120 = hz >= 100 && g_DirectOk && !force60;
        LogPrint("refresh: panel measured %u Hz (%u frames / %u us) -> offering %s\n", hz, f1 - f0,
                 (ULONG)((ULONGLONG)(x1 - x0) * 1000000ULL / 19200000ULL), g_Panel120 ? "60 + 120 Hz" : "60 Hz",
                 force60 ? " (120 Hz is opt-in: panel.120hz)" : "");
    }

    g_NextVsync = (LONG64)KeQueryInterruptTime() + VSYNC_PERIOD;
    g_HrTimer = ExAllocateTimer(HrTimerCb, NULL, EX_TIMER_HIGH_RESOLUTION);
    if (g_HrTimer != NULL) {
        KeInitializeSpinLock(&g_TimerLock);
        KeInitializeDpc(&g_KickDpc, KickDpc, NULL);
        KeInitializeDpc(&g_CopyDpc, CopyDpc, NULL);
        g_TimerRes = FALSE;
        LogPrint("vsync: on-demand %u Hz high-resolution timer (stops when display is idle)\n", REFRESH);
        TimerEnsure();
    } else {
        KeInitializeTimerEx(&g_VsyncTimer, NotificationTimer);
        KeInitializeDpc(&g_VsyncDpc, VsyncDpc, NULL);
        due.QuadPart = -10000LL * 16;
        KeSetTimerEx(&g_VsyncTimer, due, 1000 / REFRESH, &g_VsyncDpc);
        LogPrint("vsync: ExAllocateTimer failed, 16 ms KTIMER\n");
    }
    g_TimerOn = TRUE;
    CopyPoolStart();
    return STATUS_SUCCESS;
}

VOID DispStop(VOID)
{
    InterlockedExchange(&g_Stopping, 1);
    KeFlushQueuedDpcs();                                 /* kick/copy DPCs queued before the flag see it now */
    CopyPoolStop();
    if (g_DirectOk && InterlockedExchange(&g_DirectActive, 0)) {
        MdpScanFrom(g_FbAddr, g_FbStride);
        KeStallExecutionProcessor(50000);
    }
    Cb4Disable();
    if (g_DirectOk && InterlockedExchange(&g_DirectActive, 0)) {
        MdpScanFrom(g_FbAddr, g_FbStride);               /* hand the panel back on the framebuffer */
        LogPrint("direct scanout: back to the framebuffer (%u direct flips)\n", g_DirectFlips);
    }
    if (g_TimerOn) {
        if (g_HrTimer != NULL) {
            EXT_DELETE_PARAMETERS dp;
            PEX_TIMER t;
            KIRQL irql;
            KeAcquireSpinLock(&g_TimerLock, &irql);
            t = g_HrTimer;
            g_HrTimer = NULL;                            /* no re-arm can reach it from here on */
            InterlockedExchange(&g_TimerRunning, 0);
            InterlockedExchange(&g_FastPoll, 0);
            KeReleaseSpinLock(&g_TimerLock, irql);
            ExInitializeDeleteTimerParameters(&dp);
            ExDeleteTimer(t, TRUE, TRUE, &dp);           /* cancel + wait for a running callback */
            if (g_TimerRes) {
                ExSetTimerResolution(0, FALSE);
                g_TimerRes = FALSE;
            }
        } else {
            KeCancelTimer(&g_VsyncTimer);
        }
        KeFlushQueuedDpcs();
        g_TimerOn = FALSE;
    }
    g_ScanCur = NULL;
    g_Dxgk = NULL;
}

VOID DispGetPostInfo(DXGK_DISPLAY_INFORMATION *Info)
{
    *Info = g_Post;
}

/* ---------------------------------------------------------------- children / EDID */

static LONG ReadCfg(LONG *Vot, LONG *Hpd)
{
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\??\\C:\\topaz\\gpuw.cfg");
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE h;
    CHAR buf[32];
    LONG v[2] = { 0x7FFFFFFF, 0x7FFFFFFF };
    ULONG i, n = 0;
    BOOLEAN neg = FALSE, any = FALSE;
    LONG cur = 0;

    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (NT_SUCCESS(ZwCreateFile(&h, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
                                FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0))) {
        RtlZeroMemory(buf, sizeof(buf));
        if (NT_SUCCESS(ZwReadFile(h, NULL, NULL, NULL, &iosb, buf, sizeof(buf) - 1, NULL, NULL))) {
            for (i = 0; i <= iosb.Information && n < 2; i++) {
                CHAR c = buf[i];
                if (c == '-') {
                    neg = TRUE;
                } else if (c >= '0' && c <= '9') {
                    cur = cur * 10 + (c - '0');
                    any = TRUE;
                } else {
                    if (any) {
                        v[n++] = neg ? -cur : cur;
                    }
                    cur = 0;
                    any = neg = FALSE;
                }
            }
        }
        ZwClose(h);
    }
    *Vot = v[0];
    *Hpd = v[1];
    return (LONG)n;
}

NTSTATUS DispQueryChildRelations(PDXGK_CHILD_DESCRIPTOR Rel, ULONG Size)
{
    LONG vot = (LONG)D3DKMDT_VOT_INTERNAL, hpd = (LONG)HpdAwarenessAlwaysConnected, cv, ch;

    /* POST/ACPI adapter: the panel is the internal display (C:\topaz\gpuw.cfg "<vot> <hpd>" overrides) */
    ReadCfg(&cv, &ch);
    if (cv != 0x7FFFFFFF) vot = cv;
    if (ch != 0x7FFFFFFF) hpd = ch;
    LogPrint("QueryChildRelations: size %u (%u slots) vot %d hpd %d\n", Size, Size / sizeof(*Rel), vot, hpd);
    if (Size < 2 * sizeof(*Rel)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    RtlZeroMemory(Rel, sizeof(*Rel));
    Rel[0].ChildDeviceType = TypeVideoOutput;
    Rel[0].ChildCapabilities.HpdAwareness = (DXGK_CHILD_DEVICE_HPD_AWARENESS)hpd;
    Rel[0].ChildCapabilities.Type.VideoOutput.InterfaceTechnology = (D3DKMDT_VIDEO_OUTPUT_TECHNOLOGY)vot;
    Rel[0].ChildCapabilities.Type.VideoOutput.MonitorOrientationAwareness = D3DKMDT_MOA_NONE;
    Rel[0].ChildCapabilities.Type.VideoOutput.SupportsSdtvModes = FALSE;
    Rel[0].AcpiUid = 0;
    Rel[0].ChildUid = 0;
    return STATUS_SUCCESS;
}

NTSTATUS DispQueryChildStatus(PDXGK_CHILD_STATUS St)
{
    switch (St->Type) {
    case StatusConnection:
        St->HotPlug.Connected = TRUE;
        return STATUS_SUCCESS;
    case StatusRotation:
        St->Rotation.Angle = 0;
        return STATUS_SUCCESS;
    default:
        return STATUS_NOT_SUPPORTED;
    }
}

/* EDID 1.4 of the panel (as drivers/TopazDisplay/topaz_edid.cxx): DSI has no DDC */
static VOID BuildEdid(UCHAR *e)
{
    static const UCHAR header[8] = { 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 };
    static const UCHAR chroma[10] = { 0xEE, 0x91, 0xA3, 0x54, 0x4C, 0x99, 0x26, 0x0F, 0x50, 0x54 };
    static const char name[13] = { 'O','p','e','n',' ','P','a','n','e','l',' ','\n',' ' };
    const ULONG hActive = H_ACTIVE, hFp = 80, hSync = 20, hBp = 60;
    const ULONG vActive = V_ACTIVE, vFp = 16, vSync = 4, vBp = 12;
    const ULONG hBlank = hFp + hSync + hBp, vBlank = vFp + vSync + vBp;
    const ULONG clk10k = (hActive + hBlank) * (vActive + vBlank) * 60 / 10000;   /* DTD stays 60 Hz: 120 Hz exceeds
                                                                                  the 655.35 MHz DTD limit; the
                                                                                  120 Hz mode is added by the driver */
    const ULONG wMm = 70, hMm = 155;
    UCHAR *d;
    ULONG i, sum = 0;

    RtlZeroMemory(e, 128);
    RtlCopyMemory(e, header, sizeof(header));
    e[8] = 0x52; e[9] = 0x1A;                       /* "TPZ" */
    e[10] = 0x25; e[11] = 0x62;                     /* 0x6225 */
    e[16] = 1; e[17] = 2026 - 1990;
    e[18] = 1; e[19] = 4;
    e[20] = 0xA0;
    e[21] = (UCHAR)((wMm + 5) / 10);
    e[22] = (UCHAR)((hMm + 5) / 10);
    e[23] = 0x78;
    e[24] = 0x02;
    RtlCopyMemory(&e[25], chroma, sizeof(chroma));
    for (i = 38; i < 54; i++) {
        e[i] = 0x01;
    }
    d = &e[54];
    d[0] = (UCHAR)(clk10k & 0xFF);
    d[1] = (UCHAR)(clk10k >> 8);
    d[2] = (UCHAR)(hActive & 0xFF);
    d[3] = (UCHAR)(hBlank & 0xFF);
    d[4] = (UCHAR)(((hActive >> 8) << 4) | (hBlank >> 8));
    d[5] = (UCHAR)(vActive & 0xFF);
    d[6] = (UCHAR)(vBlank & 0xFF);
    d[7] = (UCHAR)(((vActive >> 8) << 4) | (vBlank >> 8));
    d[8] = (UCHAR)(hFp & 0xFF);
    d[9] = (UCHAR)(hSync & 0xFF);
    d[10] = (UCHAR)(((vFp & 0xF) << 4) | (vSync & 0xF));
    d[11] = (UCHAR)(((hFp >> 8) << 6) | ((hSync >> 8) << 4) | ((vFp >> 4) << 2) | (vSync >> 4));
    d[12] = (UCHAR)(wMm & 0xFF);
    d[13] = (UCHAR)(hMm & 0xFF);
    d[14] = (UCHAR)(((wMm >> 8) << 4) | (hMm >> 8));
    d[17] = 0x1E;
    d = &e[72];
    d[3] = 0xFC;
    RtlCopyMemory(&d[5], name, sizeof(name));
    e[90 + 3] = 0x10;
    e[108 + 3] = 0x10;
    if (g_Panel120) {
        e[126] = 1;                                   /* one extension: DisplayID with the 120 Hz timing */
    }
    for (i = 0; i < 127; i++) {
        sum += e[i];
    }
    e[127] = (UCHAR)(256 - (sum & 0xFF));
}

/* EDID extension block: DisplayID 1.3 section with one Type I detailed timing (24-bit pixel clock in 10 kHz units,
   so 2440x2268 @ 120 Hz fits; an EDID DTD tops out at 655.35 MHz). Fields are stored minus one. */
static VOID BuildDisplayIdExt(UCHAR *x)
{
    const ULONG hA = H_ACTIVE, vA = V_ACTIVE, hB = 160, vB = 32, hFp = 80, hSw = 20, vFp = 16, vSw = 4;
    const ULONG clk10k = (hA + hB) * (vA + vB) * 120 / 10000;
    UCHAR *t;
    ULONG i, sum = 0;

    RtlZeroMemory(x, 128);
    x[0] = 0x70;                                      /* EDID extension tag: DisplayID */
    x[1] = 0x13;                                      /* DisplayID 1.3 */
    x[2] = 3 + 20;                                    /* section payload: one data block */
    x[3] = 0x00;                                      /* extension section */
    x[4] = 0x00;
    x[5] = 0x03;                                      /* Type I detailed timing block */
    x[6] = 0x00;
    x[7] = 20;
    t = &x[8];
    t[0] = (UCHAR)((clk10k - 1) & 0xFF); t[1] = (UCHAR)((clk10k - 1) >> 8); t[2] = (UCHAR)((clk10k - 1) >> 16);
    t[3] = 0x00;                                      /* not preferred (the base EDID's 60 Hz is), progressive */
    t[4] = (UCHAR)((hA - 1) & 0xFF);  t[5] = (UCHAR)((hA - 1) >> 8);
    t[6] = (UCHAR)((hB - 1) & 0xFF);  t[7] = (UCHAR)((hB - 1) >> 8);
    t[8] = (UCHAR)((hFp - 1) & 0xFF); t[9] = (UCHAR)((hFp - 1) >> 8);       /* +sync polarity bit 15 = 0 */
    t[10] = (UCHAR)((hSw - 1) & 0xFF); t[11] = (UCHAR)((hSw - 1) >> 8);
    t[12] = (UCHAR)((vA - 1) & 0xFF); t[13] = (UCHAR)((vA - 1) >> 8);
    t[14] = (UCHAR)((vB - 1) & 0xFF); t[15] = (UCHAR)((vB - 1) >> 8);
    t[16] = (UCHAR)((vFp - 1) & 0xFF); t[17] = (UCHAR)((vFp - 1) >> 8);
    t[18] = (UCHAR)((vSw - 1) & 0xFF); t[19] = (UCHAR)((vSw - 1) >> 8);
    for (i = 1; i < 28; i++) {                        /* DisplayID section checksum: bytes 1..28 */
        sum += x[i];
    }
    x[28] = (UCHAR)(256 - (sum & 0xFF));
    for (i = 0, sum = 0; i < 127; i++) {
        sum += x[i];
    }
    x[127] = (UCHAR)(256 - (sum & 0xFF));
}

NTSTATUS DispQueryDeviceDescriptor(ULONG Uid, PDXGK_DEVICE_DESCRIPTOR Desc)
{
    UCHAR edid[256];
    ULONG n, len = g_Panel120 ? 256u : 128u;

    if (Uid != 0 || Desc->DescriptorOffset >= len) {
        return STATUS_MONITOR_NO_MORE_DESCRIPTOR_DATA;
    }
    BuildEdid(edid);
    if (g_Panel120) {
        BuildDisplayIdExt(edid + 128);
    }
    n = len - Desc->DescriptorOffset;
    if (n > Desc->DescriptorLength) {
        n = Desc->DescriptorLength;
    }
    RtlCopyMemory(Desc->DescriptorBuffer, edid + Desc->DescriptorOffset, n);
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- VidPN */

static VOID FillSignalHz(D3DKMDT_VIDEO_SIGNAL_INFO *S, ULONG Hz)
{
    S->VideoStandard = D3DKMDT_VSS_OTHER;
    S->TotalSize.cx = H_TOTAL;
    S->TotalSize.cy = V_TOTAL;
    S->ActiveSize.cx = H_ACTIVE;
    S->ActiveSize.cy = V_ACTIVE;
    S->VSyncFreq.Numerator = Hz;
    S->VSyncFreq.Denominator = 1;
    S->HSyncFreq.Numerator = V_TOTAL * Hz;
    S->HSyncFreq.Denominator = 1;
    S->PixelRate = (SIZE_T)H_TOTAL * V_TOTAL * Hz;
    S->ScanLineOrdering = D3DDDI_VSSLO_PROGRESSIVE;
}

static NTSTATUS AddSourceMode(const DXGK_VIDPNSOURCEMODESET_INTERFACE *If, D3DKMDT_HVIDPNSOURCEMODESET Set)
{
    D3DKMDT_VIDPN_SOURCE_MODE *m = NULL;
    NTSTATUS st = If->pfnCreateNewModeInfo(Set, &m);

    if (!NT_SUCCESS(st)) {
        return st;
    }
    m->Type = D3DKMDT_RMT_GRAPHICS;
    m->Format.Graphics.PrimSurfSize.cx = H_ACTIVE;
    m->Format.Graphics.PrimSurfSize.cy = V_ACTIVE;
    m->Format.Graphics.VisibleRegionSize = m->Format.Graphics.PrimSurfSize;
    m->Format.Graphics.Stride = H_ACTIVE * 4;
    m->Format.Graphics.PixelFormat = D3DDDIFMT_X8R8G8B8;
    m->Format.Graphics.ColorBasis = D3DKMDT_CB_SCRGB;
    m->Format.Graphics.PixelValueAccessMode = D3DKMDT_PVAM_DIRECT;
    st = If->pfnAddMode(Set, m);
    if (!NT_SUCCESS(st)) {
        If->pfnReleaseModeInfo(Set, m);
        return st == STATUS_GRAPHICS_MODE_ALREADY_IN_MODESET ? STATUS_SUCCESS : st;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS AddTargetModeHz(const DXGK_VIDPNTARGETMODESET_INTERFACE *If, D3DKMDT_HVIDPNTARGETMODESET Set, ULONG Hz,
                                BOOLEAN Preferred)
{
    D3DKMDT_VIDPN_TARGET_MODE *m = NULL;
    NTSTATUS st = If->pfnCreateNewModeInfo(Set, &m);

    if (!NT_SUCCESS(st)) {
        return st;
    }
    FillSignalHz(&m->VideoSignalInfo, Hz);
    m->Preference = Preferred ? D3DKMDT_MP_PREFERRED : D3DKMDT_MP_NOTPREFERRED;
    st = If->pfnAddMode(Set, m);
    if (!NT_SUCCESS(st)) {
        If->pfnReleaseModeInfo(Set, m);
        return st == STATUS_GRAPHICS_MODE_ALREADY_IN_MODESET ? STATUS_SUCCESS : st;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS AddTargetMode(const DXGK_VIDPNTARGETMODESET_INTERFACE *If, D3DKMDT_HVIDPNTARGETMODESET Set)
{
    NTSTATUS st = AddTargetModeHz(If, Set, 60, TRUE);          /* 60 Hz stays preferred: boots are safe */
    if (NT_SUCCESS(st) && g_Panel120) {
        st = AddTargetModeHz(If, Set, 120, FALSE);
    }
    return st;
}

static NTSTATUS AddMonitorModeHz(const DXGKARG_RECOMMENDMONITORMODES *A, ULONG Hz, BOOLEAN Preferred)
{
    D3DKMDT_MONITOR_SOURCE_MODE *m = NULL;
    NTSTATUS st = A->pMonitorSourceModeSetInterface->pfnCreateNewModeInfo(A->hMonitorSourceModeSet, &m);

    if (!NT_SUCCESS(st)) {
        return st;
    }
    FillSignalHz(&m->VideoSignalInfo, Hz);
    m->Origin = D3DKMDT_MCO_DRIVER;
    m->Preference = Preferred ? D3DKMDT_MP_PREFERRED : D3DKMDT_MP_NOTPREFERRED;
    m->ColorBasis = D3DKMDT_CB_SRGB;
    m->ColorCoeffDynamicRanges.FirstChannel = 8;
    m->ColorCoeffDynamicRanges.SecondChannel = 8;
    m->ColorCoeffDynamicRanges.ThirdChannel = 8;
    m->ColorCoeffDynamicRanges.FourthChannel = 8;
    st = A->pMonitorSourceModeSetInterface->pfnAddMode(A->hMonitorSourceModeSet, m);
    if (!NT_SUCCESS(st)) {
        A->pMonitorSourceModeSetInterface->pfnReleaseModeInfo(A->hMonitorSourceModeSet, m);
        return st == STATUS_GRAPHICS_MODE_ALREADY_IN_MODESET ? STATUS_SUCCESS : st;
    }
    return STATUS_SUCCESS;
}

NTSTATUS DispRecommendMonitorModes(const DXGKARG_RECOMMENDMONITORMODES *A)
{
    NTSTATUS st = AddMonitorModeHz(A, 60, TRUE);
    if (NT_SUCCESS(st) && g_Panel120) {
        st = AddMonitorModeHz(A, 120, FALSE);
    }
    return st;
}

NTSTATUS DispEnumCofuncModality(PDXGKRNL_INTERFACE Dxgk, const DXGKARG_ENUMVIDPNCOFUNCMODALITY *A)
{
    const DXGK_VIDPN_INTERFACE *vi = NULL;
    const DXGK_VIDPNTOPOLOGY_INTERFACE *ti = NULL;
    D3DKMDT_HVIDPNTOPOLOGY topo = 0;
    const D3DKMDT_VIDPN_PRESENT_PATH *path = NULL, *next = NULL;
    NTSTATUS st;

    st = Dxgk->DxgkCbQueryVidPnInterface(A->hConstrainingVidPn, DXGK_VIDPN_INTERFACE_VERSION_V1, &vi);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    st = vi->pfnGetTopology(A->hConstrainingVidPn, &topo, &ti);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    st = ti->pfnAcquireFirstPathInfo(topo, &path);
    if (st == STATUS_GRAPHICS_DATASET_IS_EMPTY) {
        return STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(st)) {
        return st;
    }
    while (path != NULL) {
        D3DKMDT_HVIDPNSOURCEMODESET sset = 0;
        D3DKMDT_HVIDPNTARGETMODESET tset = 0;
        const DXGK_VIDPNSOURCEMODESET_INTERFACE *si = NULL;
        const DXGK_VIDPNTARGETMODESET_INTERFACE *tgi = NULL;
        const D3DKMDT_VIDPN_SOURCE_MODE *spin = NULL;
        const D3DKMDT_VIDPN_TARGET_MODE *tpin = NULL;
        D3DKMDT_VIDPN_PRESENT_PATH local;
        BOOLEAN modified = FALSE;

        /* source modes */
        if (!(A->EnumPivotType == D3DKMDT_EPT_VIDPNSOURCE && A->EnumPivot.VidPnSourceId == path->VidPnSourceId)) {
            st = vi->pfnAcquireSourceModeSet(A->hConstrainingVidPn, path->VidPnSourceId, &sset, &si);
            if (!NT_SUCCESS(st)) {
                break;
            }
            st = si->pfnAcquirePinnedModeInfo(sset, &spin);
            if (NT_SUCCESS(st) && spin == NULL) {
                vi->pfnReleaseSourceModeSet(A->hConstrainingVidPn, sset);
                sset = 0;
                st = vi->pfnCreateNewSourceModeSet(A->hConstrainingVidPn, path->VidPnSourceId, &sset, &si);
                if (NT_SUCCESS(st)) {
                    st = AddSourceMode(si, sset);
                }
                if (NT_SUCCESS(st)) {
                    st = vi->pfnAssignSourceModeSet(A->hConstrainingVidPn, path->VidPnSourceId, sset);
                    if (NT_SUCCESS(st)) {
                        sset = 0;
                    }
                }
            } else if (spin != NULL) {
                si->pfnReleaseModeInfo(sset, spin);
            }
            if (sset != 0) {
                vi->pfnReleaseSourceModeSet(A->hConstrainingVidPn, sset);
            }
            if (!NT_SUCCESS(st)) {
                break;
            }
        }
        /* target modes */
        if (!(A->EnumPivotType == D3DKMDT_EPT_VIDPNTARGET && A->EnumPivot.VidPnTargetId == path->VidPnTargetId)) {
            st = vi->pfnAcquireTargetModeSet(A->hConstrainingVidPn, path->VidPnTargetId, &tset, &tgi);
            if (!NT_SUCCESS(st)) {
                break;
            }
            st = tgi->pfnAcquirePinnedModeInfo(tset, &tpin);
            if (NT_SUCCESS(st) && tpin == NULL) {
                vi->pfnReleaseTargetModeSet(A->hConstrainingVidPn, tset);
                tset = 0;
                st = vi->pfnCreateNewTargetModeSet(A->hConstrainingVidPn, path->VidPnTargetId, &tset, &tgi);
                if (NT_SUCCESS(st)) {
                    st = AddTargetMode(tgi, tset);
                }
                if (NT_SUCCESS(st)) {
                    st = vi->pfnAssignTargetModeSet(A->hConstrainingVidPn, path->VidPnTargetId, tset);
                    if (NT_SUCCESS(st)) {
                        tset = 0;
                    }
                }
            } else if (tpin != NULL) {
                tgi->pfnReleaseModeInfo(tset, tpin);
            }
            if (tset != 0) {
                vi->pfnReleaseTargetModeSet(A->hConstrainingVidPn, tset);
            }
            if (!NT_SUCCESS(st)) {
                break;
            }
        }
        /* scaling / rotation support: identity only */
        local = *path;
        if (!(A->EnumPivotType == D3DKMDT_EPT_SCALING && A->EnumPivot.VidPnSourceId == path->VidPnSourceId &&
              A->EnumPivot.VidPnTargetId == path->VidPnTargetId) &&
            path->ContentTransformation.Scaling == D3DKMDT_VPPS_UNPINNED) {
            RtlZeroMemory(&local.ContentTransformation.ScalingSupport, sizeof(local.ContentTransformation.ScalingSupport));
            local.ContentTransformation.ScalingSupport.Identity = 1;
            modified = TRUE;
        }
        if (!(A->EnumPivotType == D3DKMDT_EPT_ROTATION && A->EnumPivot.VidPnSourceId == path->VidPnSourceId &&
              A->EnumPivot.VidPnTargetId == path->VidPnTargetId) &&
            path->ContentTransformation.Rotation == D3DKMDT_VPPR_UNPINNED) {
            RtlZeroMemory(&local.ContentTransformation.RotationSupport, sizeof(local.ContentTransformation.RotationSupport));
            local.ContentTransformation.RotationSupport.Identity = 1;
            local.ContentTransformation.RotationSupport.Offset0 = 1;
            modified = TRUE;
        }
        if (modified) {
            st = ti->pfnUpdatePathSupportInfo(topo, &local);
            if (!NT_SUCCESS(st)) {
                break;
            }
        }
        st = ti->pfnAcquireNextPathInfo(topo, path, &next);
        ti->pfnReleasePathInfo(topo, path);
        path = NULL;
        if (st == STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET) {
            st = STATUS_SUCCESS;
            break;
        }
        if (!NT_SUCCESS(st)) {
            break;
        }
        path = next;
    }
    if (path != NULL) {
        ti->pfnReleasePathInfo(topo, path);
    }
    if (!NT_SUCCESS(st)) {
        LogPrint("EnumVidPnCofuncModality: %08x\n", st);
    }
    return st;
}

NTSTATUS DispCommitVidPn(PDXGKRNL_INTERFACE Dxgk, const DXGKARG_COMMITVIDPN *A)
{
    const DXGK_VIDPN_INTERFACE *vi = NULL;
    const DXGK_VIDPNTOPOLOGY_INTERFACE *ti = NULL;
    D3DKMDT_HVIDPNTOPOLOGY topo = 0;
    D3DKMDT_HVIDPNSOURCEMODESET sset = 0;
    const DXGK_VIDPNSOURCEMODESET_INTERFACE *si = NULL;
    const D3DKMDT_VIDPN_SOURCE_MODE *pin = NULL;
    SIZE_T paths = 0;
    NTSTATUS st;

    if (A->Flags.PathPoweredOff) {
        return STATUS_SUCCESS;
    }
    st = Dxgk->DxgkCbQueryVidPnInterface(A->hFunctionalVidPn, DXGK_VIDPN_INTERFACE_VERSION_V1, &vi);
    if (NT_SUCCESS(st)) {
        st = vi->pfnGetTopology(A->hFunctionalVidPn, &topo, &ti);
    }
    if (NT_SUCCESS(st)) {
        st = ti->pfnGetNumPaths(topo, &paths);
    }
    if (NT_SUCCESS(st) && paths != 0) {
        st = vi->pfnAcquireSourceModeSet(A->hFunctionalVidPn, A->AffectedVidPnSourceId, &sset, &si);
        if (NT_SUCCESS(st)) {
            st = si->pfnAcquirePinnedModeInfo(sset, &pin);
        }
    }
    if (NT_SUCCESS(st)) {
        g_Committed = pin != NULL;
        LogPrint("CommitVidPn: src %u paths %u mode %ux%u stride %u fmt %u primary %p\n", A->AffectedVidPnSourceId,
                 (ULONG)paths, pin ? pin->Format.Graphics.PrimSurfSize.cx : 0, pin ? pin->Format.Graphics.PrimSurfSize.cy : 0,
                 pin ? pin->Format.Graphics.Stride : 0, pin ? pin->Format.Graphics.PixelFormat : 0, A->hPrimaryAllocation);
        if (!g_Committed) {
            DirectSelect(NULL);
            KeWaitForSingleObject(&g_ScanLock, Executive, KernelMode, FALSE, NULL);
            g_ScanCur = NULL;
            KeReleaseMutex(&g_ScanLock, FALSE);
        } else if (A->hPrimaryAllocation != NULL) {
            g_ScanCur = (TGPU_ALLOCATION *)A->hPrimaryAllocation;
            if (!DirectSelect(g_ScanCur)) {
                InterlockedExchange(&g_ScanDirty, 1);
            }
        }
    } else {
        LogPrint("CommitVidPn: %08x\n", st);
    }
    if (NT_SUCCESS(st) && g_Committed && vi != NULL) {        /* follow the refresh Windows committed */
        D3DKMDT_HVIDPNTARGETMODESET tset = 0;
        const DXGK_VIDPNTARGETMODESET_INTERFACE *tgi = NULL;
        const D3DKMDT_VIDPN_TARGET_MODE *tpin = NULL;
        if (NT_SUCCESS(vi->pfnAcquireTargetModeSet(A->hFunctionalVidPn, 0, &tset, &tgi))) {
            if (NT_SUCCESS(tgi->pfnAcquirePinnedModeInfo(tset, &tpin)) && tpin != NULL) {
                const D3DDDI_RATIONAL *f = &tpin->VideoSignalInfo.VSyncFreq;
                ULONG hz = f->Denominator ? (f->Numerator + f->Denominator / 2) / f->Denominator : 60;
                ULONG want = (hz >= 100 && g_Panel120) ? 120 : 60;
                if (want != g_Refresh) {
                    KIRQL irql;
                    g_Refresh = want;
                    KeAcquireSpinLock(&g_TimerLock, &irql);
                    if (g_TimerRunning && !g_FastPoll && g_HrTimer != NULL && !g_Stopping) {
                        ExSetTimer(g_HrTimer, -VSYNC_PERIOD, VSYNC_PERIOD, NULL);
                    }
                    KeReleaseSpinLock(&g_TimerLock, irql);
                }
                LogPrint("CommitVidPn: target %u Hz -> vsync %u Hz\n", hz, g_Refresh);
                tgi->pfnReleaseModeInfo(tset, tpin);
            }
            vi->pfnReleaseTargetModeSet(A->hFunctionalVidPn, tset);
        }
    }
    if (pin != NULL) {
        si->pfnReleaseModeInfo(sset, pin);
    }
    if (sset != 0) {
        vi->pfnReleaseSourceModeSet(A->hFunctionalVidPn, sset);
    }
    return st;
}

/* ---------------------------------------------------------------- brightness (DCS 0x51 over DSI0) */

#define DSI0_PA             0x0AE94000ULL   /* SM8550 DSI0 (stock DT qcom,mdss_dsi_ctrl0@ae94000, v2.7) */
#define DSI_HW_VERSION      0x000
#define DSI_V27             0x20070000u
/* Inner panel AC052 P 1 A0002 / P 3 A0003: DCS 0x51 big-endian, 1..0xFFE; normal max 0x700 (A0002) /
 * 0xBF3 (A0003). 100% maps to 0x700 so neither variant enters its high-brightness range. */
#define BL_MAX_LEVEL        0x700u
#define DSI_CTRL            0x004
#define DSI_CMD_DMA_CTRL    0x03C
#define DSI_DMA_CMD_OFFSET  0x048
#define DSI_DMA_CMD_LENGTH  0x04C
#define DSI_TRIG_CTRL       0x084
#define DSI_DMA_SW_TRIGGER  0x090
#define DSI_INT_CTRL        0x110
#define DSI_TPG_CTRL        0x15C

static volatile UCHAR *g_Dsi;
static PUCHAR g_BlVa;
static PHYSICAL_ADDRESS g_BlPa;
static UCHAR g_Brightness = 100;
static KMUTEX g_BlLock;

/* perceptual curve: level = 1 + (max-1) * pct^2 / 100^2 (0% -> 1, 50% -> 0x1C0, 100% -> max) */
static ULONG BlLevel(UCHAR Pct)
{
    return 1u + (BL_MAX_LEVEL - 1u) * (ULONG)Pct * (ULONG)Pct / 10000u;
}

static ULONG DsiRd(ULONG Off) { return READ_REGISTER_ULONG((volatile ULONG *)(g_Dsi + Off)); }
static VOID DsiWr(ULONG Off, ULONG V) { WRITE_REGISTER_ULONG((volatile ULONG *)(g_Dsi + Off), V); }

static VOID InitBrightness(VOID)
{
    PHYSICAL_ADDRESS pa, lo, hi, skip;

    if (g_Dsi != NULL) {
        return;
    }
    KeInitializeMutex(&g_BlLock, 0);
    pa.QuadPart = (LONGLONG)DSI0_PA;
    g_Dsi = (volatile UCHAR *)MmMapIoSpaceEx(pa, 0x400, PAGE_READWRITE | PAGE_NOCACHE);
    lo.QuadPart = 0;
    hi.QuadPart = 0xFFFFFFFF;
    skip.QuadPart = 0;
    g_BlVa = (PUCHAR)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, lo, hi, skip, MmNonCached);
    if (g_BlVa != NULL) {
        g_BlPa = MmGetPhysicalAddress(g_BlVa);
    }
    if (g_Dsi != NULL && (DsiRd(DSI_HW_VERSION) & 0xFFFF0000u) != DSI_V27) {
        LogPrint("brightness: unexpected DSI0 version %08x - disabled\n", DsiRd(DSI_HW_VERSION));
        MmUnmapIoSpace((PVOID)g_Dsi, 0x400);
        g_Dsi = NULL;
    }
    LogPrint("brightness: DSI0 %p ver %08x ctrl %08x dmactl %08x, DMA buffer %llx\n", g_Dsi,
             g_Dsi ? DsiRd(DSI_HW_VERSION) : 0, g_Dsi ? DsiRd(DSI_CTRL) : 0, g_Dsi ? DsiRd(DSI_CMD_DMA_CTRL) : 0,
             g_BlPa.QuadPart);
}

static BOOLEAN DsiDcsLong(const UCHAR *Payload, ULONG Len)
{
    ULONG size = (4 + Len + 3) & ~3u, ctrl, dma, trig, i;
    BOOLEAN done = FALSE;

    if (g_Dsi == NULL || g_BlVa == NULL || Len > 60) {
        return FALSE;
    }
    RtlFillMemory(g_BlVa, 64, 0xFF);
    g_BlVa[0] = (UCHAR)Len;
    g_BlVa[1] = (UCHAR)(Len >> 8);
    g_BlVa[2] = 0x39;                           /* DCS long write, VC 0 */
    g_BlVa[3] = 0xC0;                           /* last, long */
    RtlCopyMemory(g_BlVa + 4, Payload, Len);
    KeMemoryBarrier();
    ctrl = DsiRd(DSI_CTRL);
    trig = DsiRd(DSI_TRIG_CTRL);
    if ((trig & 7) != 4) {
        DsiWr(DSI_TRIG_CTRL, (trig & ~7u) | 4);
    }
    DsiWr(DSI_CTRL, ctrl | 4 | 1);
    DsiWr(DSI_INT_CTRL, DsiRd(DSI_INT_CTRL) | 1);
    DsiWr(DSI_TPG_CTRL, 0);
    DsiWr(DSI_DMA_CMD_OFFSET, g_BlPa.LowPart);
    DsiWr(DSI_DMA_CMD_LENGTH, size);
    dma = DsiRd(DSI_CMD_DMA_CTRL);
    /* keep UEFI's CMD_DMA_CTRL: it sends panel commands in low-power mode (bit 26) */
    DsiWr(DSI_DMA_SW_TRIGGER, 1);
    for (i = 0; i < 50; i++) {
        if (DsiRd(DSI_INT_CTRL) & 1) {
            done = TRUE;
            break;
        }
        KeStallExecutionProcessor(1000);
    }
    DsiWr(DSI_INT_CTRL, DsiRd(DSI_INT_CTRL) | 1);
    DsiWr(DSI_CMD_DMA_CTRL, dma);
    DsiWr(DSI_CTRL, ctrl);
    if (trig != DsiRd(DSI_TRIG_CTRL)) {
        DsiWr(DSI_TRIG_CTRL, trig);
    }
    return done;
}

static VOID APIENTRY BlRef(PVOID Ctx) { UNREFERENCED_PARAMETER(Ctx); }
static VOID APIENTRY BlDeref(PVOID Ctx) { UNREFERENCED_PARAMETER(Ctx); }

static NTSTATUS APIENTRY BlGetPossible(HANDLE Ctx, ULONG BufferSize, UCHAR *LevelCount, UCHAR *Levels)
{
    ULONG i, n = BufferSize < 101 ? BufferSize : 101;

    UNREFERENCED_PARAMETER(Ctx);
    if (LevelCount == NULL || Levels == NULL || n == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    for (i = 0; i < n; i++) {
        Levels[i] = (UCHAR)i;
    }
    *LevelCount = (UCHAR)n;
    return STATUS_SUCCESS;
}

static NTSTATUS APIENTRY BlSet(HANDLE Ctx, UCHAR Pct)
{
    UCHAR cmd[3];
    ULONG level;
    BOOLEAN done;

    UNREFERENCED_PARAMETER(Ctx);
    if (Pct > 100) {
        Pct = 100;
    }
    g_Brightness = Pct;
    if (!g_Visible) {                       /* v0.45.7: Windows dims after hiding the source - keep the panel dark */
        LogPrint("brightness %u%% stored (screen off)\n", Pct);
        return STATUS_SUCCESS;
    }
    level = BlLevel(Pct);
    cmd[0] = 0x51;
    cmd[1] = (UCHAR)(level >> 8);
    cmd[2] = (UCHAR)level;
    KeWaitForSingleObject(&g_BlLock, Executive, KernelMode, FALSE, NULL);
    done = DsiDcsLong(cmd, sizeof(cmd));
    KeReleaseMutex(&g_BlLock, FALSE);
    LogPrint("brightness %u%% -> 0x%03x: %s\n", Pct, level, done ? "done" : "NO DONE");
    return done ? STATUS_SUCCESS : STATUS_IO_TIMEOUT;
}

/* v0.45.6: Windows turning the screen off only hides the source; the panel kept its backlight and
   showed the last framebuffer picture (the boot spinner). Backlight 0 on hide, the user level on show. */
static VOID BlPanel(BOOLEAN On)
{
    UCHAR cmd[3];
    ULONG level = BlLevel(g_Brightness);
    BOOLEAN done;

    if (g_Dsi == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }
    if (!On) {
        level = 0;
    } else if (level < 1) {
        level = 1;
    }
    cmd[0] = 0x51;
    cmd[1] = (UCHAR)(level >> 8);
    cmd[2] = (UCHAR)level;
    KeWaitForSingleObject(&g_BlLock, Executive, KernelMode, FALSE, NULL);
    done = DsiDcsLong(cmd, sizeof(cmd));
    KeReleaseMutex(&g_BlLock, FALSE);
    LogPrint("panel %s (backlight 0x%03x): %s\n", On ? "on" : "off", level, done ? "done" : "NO DONE");
}

static NTSTATUS APIENTRY BlGet(HANDLE Ctx, UCHAR *Pct)
{
    UNREFERENCED_PARAMETER(Ctx);
    if (Pct == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *Pct = g_Brightness;
    return STATUS_SUCCESS;
}

NTSTATUS DispBrightnessQueryInterface(PQUERY_INTERFACE Qi)
{
    DXGK_BRIGHTNESS_INTERFACE *b;

    if (Qi == NULL || Qi->InterfaceType == NULL ||
        RtlCompareMemory(Qi->InterfaceType, &g_BrightnessGuid, sizeof(GUID)) != sizeof(GUID)) {
        return STATUS_NOT_SUPPORTED;
    }
    if (g_Dsi == NULL || g_BlVa == NULL || Qi->Size < sizeof(DXGK_BRIGHTNESS_INTERFACE) || Qi->Interface == NULL) {
        LogPrint("QueryInterface brightness v%u size %u: not available\n", Qi->Version, Qi->Size);
        return STATUS_NOT_SUPPORTED;
    }
    b = (DXGK_BRIGHTNESS_INTERFACE *)Qi->Interface;
    RtlZeroMemory(b, sizeof(*b));
    b->Size = sizeof(*b);
    b->Version = DXGK_BRIGHTNESS_INTERFACE_VERSION_1;
    b->InterfaceReference = BlRef;
    b->InterfaceDereference = BlDeref;
    b->GetPossibleBrightness = BlGetPossible;
    b->SetBrightness = BlSet;
    b->GetBrightness = BlGet;
    LogPrint("QueryInterface brightness v%u: provided\n", Qi->Version);
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- v0.37: MDP / SMMU survey (read-only)
 * Goal: scan out the flipped BO directly (SSPP source address) instead of copying it. First learn what
 * the bootloader left running: which SSPP fetches the GOP framebuffer, its stride/format, the CTL/LM
 * routing, and whether the apps SMMU translates the MDP stream (SID 0x420/0x421, stock DT) or
 * bypasses it. Offsets: stock DT sde-sspp-off VIG0 0x5000, DMA0 0x25000, ctl 0x2000, mixer 0x45000. */

#define MDP_PA        0x05E00000ULL
#define MDP_SIZE      0x90000
#define APPS_SMMU_PA  0x0C600000ULL

static ULONG MRd(volatile UCHAR *B, ULONG Off) { return READ_REGISTER_ULONG((volatile ULONG *)(B + Off)); }

static VOID DumpSspp(volatile UCHAR *Mdp, PCSTR Name, ULONG Base)
{
    LogPrint("MDP %s @+%05x: src_size %08x img %08x xy %08x out_size %08x out_xy %08x addr0 %08x addr1 %08x "
             "ystride0 %08x format %08x unpack %08x op %08x\n", Name, Base, MRd(Mdp, Base + 0x00), MRd(Mdp, Base + 0x04),
             MRd(Mdp, Base + 0x08), MRd(Mdp, Base + 0x0C), MRd(Mdp, Base + 0x10), MRd(Mdp, Base + 0x14),
             MRd(Mdp, Base + 0x18), MRd(Mdp, Base + 0x24), MRd(Mdp, Base + 0x30), MRd(Mdp, Base + 0x34),
             MRd(Mdp, Base + 0x38));
}

VOID DispSurveyMdp(VOID)
{
    PHYSICAL_ADDRESS pa;
    volatile UCHAR *mdp, *smmu;
    ULONG idr0, idr1, nsmr, i, pagesz, numpage;

    pa.QuadPart = (LONGLONG)MDP_PA;
    mdp = (volatile UCHAR *)MmMapIoSpaceEx(pa, MDP_SIZE, PAGE_READWRITE | PAGE_NOCACHE);
    if (mdp != NULL) {
        LogPrint("MDP hw rev %08x (top +0x1000: %08x)\n", MRd(mdp, 0x0), MRd(mdp, 0x1000));
        DumpSspp(mdp, "VIG0", 0x5000);
        DumpSspp(mdp, "DMA0", 0x25000);
        LogPrint("MDP CTL0 @+2000: layer0 %08x layer1 %08x top %08x flush %08x start %08x intf_active %08x\n",
                 MRd(mdp, 0x2000), MRd(mdp, 0x2004), MRd(mdp, 0x2014), MRd(mdp, 0x2018), MRd(mdp, 0x201C),
                 MRd(mdp, 0x20F4));
        LogPrint("MDP LM0 @+45000: op %08x out_size %08x border %08x stage0 fg %08x\n", MRd(mdp, 0x45000),
                 MRd(mdp, 0x45004), MRd(mdp, 0x45008), MRd(mdp, 0x45020));
        LogPrint("MDP INTF1 @+6b800: timing_en %08x hsync %08x vsync0 %08x disp_hctl %08x\n", MRd(mdp, 0x6b800),
                 MRd(mdp, 0x6b800 + 0x8), MRd(mdp, 0x6b800 + 0x10), MRd(mdp, 0x6b800 + 0x3C));
        MmUnmapIoSpace((PVOID)mdp, MDP_SIZE);
    }

    pa.QuadPart = (LONGLONG)APPS_SMMU_PA;
    smmu = (volatile UCHAR *)MmMapIoSpaceEx(pa, 0x2000, PAGE_READWRITE | PAGE_NOCACHE);
    if (smmu == NULL) {
        return;
    }
    idr0 = MRd(smmu, 0x20);
    idr1 = MRd(smmu, 0x24);
    nsmr = idr0 & 0xFF;
    pagesz = (idr1 & 0x80000000) ? 0x10000 : 0x1000;
    numpage = 1u << (((idr1 >> 28) & 7) + 1);
    LogPrint("apps SMMU: sCR0 %08x IDR0 %08x IDR1 %08x (%u SMRs, %u CBs, page %x, numpage %u)\n", MRd(smmu, 0),
             idr0, idr1, nsmr, idr1 & 0xFF, pagesz, numpage);
    for (i = 0; i < nsmr && i < 128; i++) {
        ULONG smr = MRd(smmu, 0x800 + 4 * i), s2cr = MRd(smmu, 0xC00 + 4 * i);
        ULONG id = smr & 0xFFFF, mask = (smr >> 16) & 0x7FFF;
        if ((smr & 0x80000000) && ((0x420 & ~mask) == (id & ~mask) || (0x421 & ~mask) == (id & ~mask))) {
            ULONG type = (s2cr >> 16) & 3, cb = s2cr & 0xFF;
            LogPrint("  SMR%u id %04x mask %04x -> S2CR %08x (type %u: %s, cb %u)\n", i, id, mask, s2cr, type,
                     type == 0 ? "translate" : type == 1 ? "bypass" : "fault", cb);
            if (type == 0) {
                volatile UCHAR *cbm;
                pa.QuadPart = (LONGLONG)(APPS_SMMU_PA + (ULONGLONG)numpage * pagesz + (ULONGLONG)cb * pagesz);
                cbm = (volatile UCHAR *)MmMapIoSpaceEx(pa, 0x100, PAGE_READWRITE | PAGE_NOCACHE);
                if (cbm != NULL) {
                    LogPrint("    CB%u: SCTLR %08x TCR %08x TTBR0 %08x%08x CBAR %08x\n", cb, MRd(cbm, 0x0),
                             MRd(cbm, 0x30), MRd(cbm, 0x24), MRd(cbm, 0x20),
                             MRd(smmu, 0x1000 + 4 * cb) /* CBAR in GR1 */);
                    MmUnmapIoSpace((PVOID)cbm, 0x100);
                }
            }
        }
    }
    MmUnmapIoSpace((PVOID)smmu, 0x2000);
}

/* GPU governor UI floor: interrupt time of the last completed flip */
LONG64 DispLastFlipTime(VOID) { return g_LastFlipDone; }
