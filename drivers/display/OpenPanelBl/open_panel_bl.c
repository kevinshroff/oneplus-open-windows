/* SPDX-License-Identifier: MIT
 * OpenPanelBl — inner OLED brightness for the OnePlus Open (SM8550) under Windows.
 *
 * The inner panel ("AC052 P 1 A0002" / "AC052 P 3 A0003", stock DT) is a DSC command-mode AMOLED on
 * DSI0 (0x0AE94000, DSI controller v2.7) with DCS brightness: 0x51 + 2 bytes, big-endian
 * (qcom,mdss-dsi-bl-inverted-dbv), range 1..0xFFE, normal max 0x700 (A0002) / 0xBF3 (A0003).
 * UEFI leaves the panel at full brightness.
 *
 * One-shot driver: reads Parameters from its service key, logs to C:\topaz\panelbl.log, then returns
 * an error so it unloads (sc start again to apply a new level).
 *   Mode  0 = read-only probe (DSI0 registers, apps-SMMU mapping of the MDSS stream 0x1C00)
 *         1 = send DCS 0x51 <Level>, only if the MDSS stream bypasses the SMMU (DMA uses a physical address)
 *   Level DCS brightness value (1..0xFFE)
 */
#include <ntddk.h>
#include <ntstrsafe.h>

#define DSI0_PA            0x0AE94000ULL
#define APPS_SMMU_PA       0x15000000ULL
#define MDSS_SID           0x1C00u

#define DSI_HW_VERSION     0x000
#define DSI_CTRL           0x004
#define DSI_STATUS0        0x008
#define DSI_CMD_DMA_CTRL   0x03C
#define DSI_CMD_MDP_CTRL   0x040
#define DSI_DMA_BASE       0x048
#define DSI_DMA_LEN        0x04C
#define DSI_TRIG_CTRL      0x084
#define DSI_TRIG_DMA       0x090
#define DSI_INTR_CTRL      0x110
#define DSI_TPG_CTRL       0x15C

static HANDLE g_Log;
static ULONG g_Cb = 0xFFFFFFFF;
static ULONG g_CbSctlr, g_CbTcr;
static ULONG64 g_CbTtbr0;

static VOID Log(PCSTR Fmt, ...)
{
    CHAR buf[512];
    va_list ap;
    IO_STATUS_BLOCK iosb;
    size_t len = 0;

    va_start(ap, Fmt);
    if (!NT_SUCCESS(RtlStringCbVPrintfA(buf, sizeof(buf), Fmt, ap))) { va_end(ap); return; }
    va_end(ap);
    DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_INFO_LEVEL, "OpenPanelBl: %s", buf);
    if (g_Log && NT_SUCCESS(RtlStringCbLengthA(buf, sizeof(buf), &len)))
        ZwWriteFile(g_Log, NULL, NULL, NULL, &iosb, buf, (ULONG)len, NULL, NULL);
}

static VOID LogOpen(VOID)
{
    UNICODE_STRING n = RTL_CONSTANT_STRING(L"\\??\\C:\\topaz\\panelbl.log");
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&g_Log, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
                                 FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH, NULL, 0)))
        g_Log = NULL;
}

static ULONG QueryDword(PUNICODE_STRING RegPath, PCWSTR Name, ULONG Default)
{
    OBJECT_ATTRIBUTES oa;
    HANDLE key, sub;
    UNICODE_STRING pn = RTL_CONSTANT_STRING(L"Parameters"), vn;
    UCHAR buf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 8];
    PKEY_VALUE_PARTIAL_INFORMATION v = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
    ULONG got, val = Default;

    InitializeObjectAttributes(&oa, RegPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwOpenKey(&key, KEY_READ, &oa))) return Default;
    InitializeObjectAttributes(&oa, &pn, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, key, NULL);
    if (NT_SUCCESS(ZwOpenKey(&sub, KEY_READ, &oa))) {
        RtlInitUnicodeString(&vn, Name);
        if (NT_SUCCESS(ZwQueryValueKey(sub, &vn, KeyValuePartialInformation, v, sizeof(buf), &got)) &&
            v->Type == REG_DWORD && v->DataLength == 4)
            val = *(ULONG UNALIGNED *)v->Data;
        ZwClose(sub);
    }
    ZwClose(key);
    return val;
}

static ULONG Rd(volatile UCHAR *B, ULONG O) { return READ_REGISTER_ULONG((volatile ULONG *)(B + O)); }
static VOID Wr(volatile UCHAR *B, ULONG O, ULONG V) { WRITE_REGISTER_ULONG((volatile ULONG *)(B + O), V); }

/* returns S2CR type for the MDSS stream: 0 translate, 1 bypass, 2 fault, 3 = no matching SMR (default) */
static ULONG ProbeSmmu(VOID)
{
    PHYSICAL_ADDRESS pa;
    volatile UCHAR *s;
    ULONG idr0, nsmr, i, cr0, type = 3, matches = 0;

    pa.QuadPart = APPS_SMMU_PA;
    s = (volatile UCHAR *)MmMapIoSpaceEx(pa, 0x1000, PAGE_READWRITE | PAGE_NOCACHE);
    if (!s) { Log("smmu: map failed\n"); return 0xFF; }
    cr0 = Rd(s, 0x0);
    idr0 = Rd(s, 0x20);
    nsmr = idr0 & 0xFF;
    Log("smmu: sCR0 %08x IDR0 %08x IDR1 %08x (SMR groups %u, EXIDS %u)\n", cr0, idr0, Rd(s, 0x24), nsmr, (idr0 >> 8) & 1);
    for (i = 0; i < nsmr && i < 256; i++) {
        ULONG smr = Rd(s, 0x800 + 4 * i), s2cr = Rd(s, 0xC00 + 4 * i);
        ULONG id = smr & 0xFFFF, mask = (smr >> 16) & 0xFFFF;
        BOOLEAN valid = (smr & 0x80000000u) || (s2cr & (1u << 10));
        if (valid && ((id & ~mask) & 0x7FFF) == (MDSS_SID & ~mask & 0x7FFF)) {
            Log("smmu: SMR[%u] %08x (id %04x mask %04x) S2CR %08x type %u cb %u\n", i, smr, id, mask, s2cr,
                (s2cr >> 16) & 3, s2cr & 0xFF);
            if (matches++ == 0) {
                type = (s2cr >> 16) & 3;
                g_Cb = s2cr & 0xFF;
            }
        }
    }
    if (!matches) Log("smmu: no SMR matches stream %04x (sCR0.USFCFG %u: unmatched streams %s)\n", MDSS_SID,
                      (cr0 >> 10) & 1, ((cr0 >> 10) & 1) ? "fault" : "bypass");
    if (!matches && !((cr0 >> 10) & 1)) type = 1;
    MmUnmapIoSpace((PVOID)s, 0x1000);
    if (type == 0 && g_Cb < 128) {
        /* context banks start after NUMPAGE global pages: IDR1.NUMPAGENDXB=6 -> 128 x 4 KiB */
        ULONG idr1;
        pa.QuadPart = APPS_SMMU_PA;
        s = (volatile UCHAR *)MmMapIoSpaceEx(pa, 0x2000, PAGE_READWRITE | PAGE_NOCACHE);
        idr1 = Rd(s, 0x24);
        ULONG numpage = 1u << (((idr1 >> 28) & 7) + 1);
        ULONG cba2r = Rd(s, 0x1800 + 4 * g_Cb), cbar = Rd(s, 0x1000 + 4 * g_Cb);
        MmUnmapIoSpace((PVOID)s, 0x2000);
        pa.QuadPart = APPS_SMMU_PA + (ULONG64)numpage * 0x1000 + (ULONG64)g_Cb * 0x1000;
        s = (volatile UCHAR *)MmMapIoSpaceEx(pa, 0x1000, PAGE_READWRITE | PAGE_NOCACHE);
        if (s) {
            g_CbSctlr = Rd(s, 0x0);
            g_CbTcr = Rd(s, 0x30);
            g_CbTtbr0 = ((ULONG64)Rd(s, 0x24) << 32) | Rd(s, 0x20);
            Log("smmu: CB%u @%llx CBAR %08x CBA2R %08x SCTLR %08x (M=%u) TCR %08x TCR2 %08x TTBR0 %016llx MAIR0 %08x FSR %08x FAR %08x%08x\n",
                g_Cb, pa.QuadPart, cbar, cba2r, g_CbSctlr, g_CbSctlr & 1, g_CbTcr, Rd(s, 0x10), g_CbTtbr0, Rd(s, 0x38),
                Rd(s, 0x58), Rd(s, 0x64), Rd(s, 0x60));
            MmUnmapIoSpace((PVOID)s, 0x1000);
            if (!(g_CbSctlr & 1)) type = 1;   /* translation disabled in the bank: effectively bypass */
        }
    }
    return type;
}

static VOID DumpDsi(volatile UCHAR *d, PCSTR Tag)
{
    Log("dsi %s: ver %08x ctrl %08x st0 %08x dmactl %08x mdpctl %08x base %08x len %08x trig %08x intr %08x tpg %08x\n",
        Tag, Rd(d, DSI_HW_VERSION), Rd(d, DSI_CTRL), Rd(d, DSI_STATUS0), Rd(d, DSI_CMD_DMA_CTRL), Rd(d, DSI_CMD_MDP_CTRL),
        Rd(d, DSI_DMA_BASE), Rd(d, DSI_DMA_LEN), Rd(d, DSI_TRIG_CTRL), Rd(d, DSI_INTR_CTRL), Rd(d, DSI_TPG_CTRL));
}

static BOOLEAN DcsLong(volatile UCHAR *d, const UCHAR *Payload, ULONG Len)
{
    PHYSICAL_ADDRESS lo, hi, skip, pa;
    PUCHAR buf;
    ULONG size = (4 + Len + 3) & ~3u, ctrl, trig, dma, i;
    BOOLEAN done = FALSE;

    lo.QuadPart = 0; hi.QuadPart = 0xFFFFFFFF; skip.QuadPart = 0;
    buf = (PUCHAR)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, lo, hi, skip, MmNonCached);
    if (!buf) { Log("dcs: no DMA buffer\n"); return FALSE; }
    pa = MmGetPhysicalAddress(buf);
    RtlFillMemory(buf, 64, 0xFF);
    buf[0] = (UCHAR)Len;            /* word count lo */
    buf[1] = (UCHAR)(Len >> 8);     /* word count hi */
    buf[2] = 0x39;                  /* DCS long write, VC 0 */
    buf[3] = 0xC0;                  /* last packet, long */
    RtlCopyMemory(buf + 4, Payload, Len);
    KeMemoryBarrier();

    ctrl = Rd(d, DSI_CTRL);
    trig = Rd(d, DSI_TRIG_CTRL);
    dma = Rd(d, DSI_CMD_DMA_CTRL);
    if ((trig & 7) != 4) Wr(d, DSI_TRIG_CTRL, (trig & ~7u) | 4);     /* DMA trigger = SW */
    Wr(d, DSI_CTRL, ctrl | 4 | 1);                                     /* CMD_MODE_EN | ENABLE */
    Wr(d, DSI_INTR_CTRL, Rd(d, DSI_INTR_CTRL) | 1);                    /* clear CMD_DMA_DONE */
    Wr(d, DSI_DMA_BASE, pa.LowPart);
    Wr(d, DSI_DMA_LEN, size);
    /* keep UEFI's CMD_DMA_CTRL (it sends panel commands in low-power mode, bit 26) */
    Wr(d, DSI_TRIG_DMA, 1);
    for (i = 0; i < 50; i++) {
        if (Rd(d, DSI_INTR_CTRL) & 1) { done = TRUE; break; }
        KeStallExecutionProcessor(1000);
    }
    Wr(d, DSI_INTR_CTRL, Rd(d, DSI_INTR_CTRL) | 1);
    Wr(d, DSI_CMD_DMA_CTRL, dma);
    Wr(d, DSI_CTRL, ctrl);
    if (Rd(d, DSI_TRIG_CTRL) != trig) Wr(d, DSI_TRIG_CTRL, trig);
    Log("dcs: %u bytes from pa %llx -> %s after %u ms\n", Len, pa.QuadPart, done ? "DMA DONE" : "TIMEOUT", i);
    MmFreeContiguousMemory(buf);
    return done;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    PHYSICAL_ADDRESS pa;
    volatile UCHAR *d;
    ULONG mode, level, smmu;
    LARGE_INTEGER now;

    UNREFERENCED_PARAMETER(DriverObject);
    LogOpen();
    mode = QueryDword(RegistryPath, L"Mode", 0);
    level = QueryDword(RegistryPath, L"Level", 0x200);
    KeQuerySystemTimePrecise(&now);
    Log("---- OpenPanelBl mode %u level 0x%x (t=%lld)\n", mode, level, now.QuadPart);

    smmu = ProbeSmmu();
    pa.QuadPart = DSI0_PA;
    d = (volatile UCHAR *)MmMapIoSpaceEx(pa, 0x1000, PAGE_READWRITE | PAGE_NOCACHE);
    if (!d) { Log("dsi: map failed\n"); goto out; }
    DumpDsi(d, "before");
    if (mode >= 1) {
        UCHAR cmd[3];
        if (smmu != 1 && mode < 2) {
            Log("refusing write: MDSS stream is not in SMMU bypass (type %u)\n", smmu);
        } else if (level < 1 || level > 0xFFE) {
            Log("refusing write: level 0x%x out of range\n", level);
        } else {
            cmd[0] = 0x51;
            cmd[1] = (UCHAR)(level >> 8);
            cmd[2] = (UCHAR)level;
            DcsLong(d, cmd, sizeof(cmd));
            DumpDsi(d, "after");
        }
    }
    MmUnmapIoSpace((PVOID)d, 0x1000);
out:
    if (g_Log) ZwClose(g_Log);
    return STATUS_DEVICE_CONFIGURATION_ERROR;    /* one-shot: unload */
}
