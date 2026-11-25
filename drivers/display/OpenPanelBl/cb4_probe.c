/* SPDX-License-Identifier: MIT */
/* cb4_probe - try turning on stage-1 translation for the MDSS context bank (apps SMMU CB4) with an identity
 * 2..4 GiB table, in several variants, each for ~30 ms; log FSR/FAR/PAR and restore bypass. Logs to
 * C:\topaz\cb4probe.log, then unloads. */
#include <ntddk.h>
#include <ntstrsafe.h>

#define SMMU_PA 0x15000000ULL
#define CB4_OFF (128u * 0x1000u + 4u * 0x1000u)

static HANDLE g_Log;
static VOID Log(PCSTR Fmt, ...)
{
    CHAR b[600]; va_list ap; IO_STATUS_BLOCK io; size_t n = 0;
    va_start(ap, Fmt);
    if (!NT_SUCCESS(RtlStringCbVPrintfA(b, sizeof(b), Fmt, ap))) { va_end(ap); return; }
    va_end(ap);
    if (g_Log && NT_SUCCESS(RtlStringCbLengthA(b, sizeof(b), &n))) ZwWriteFile(g_Log, NULL, NULL, NULL, &io, b, (ULONG)n, NULL, NULL);
}

static volatile UCHAR *g_S, *g_C;
static ULONG Rd(volatile UCHAR *b, ULONG o) { return READ_REGISTER_ULONG((volatile ULONG *)(b + o)); }
static VOID Wr(volatile UCHAR *b, ULONG o, ULONG v) { WRITE_REGISTER_ULONG((volatile ULONG *)(b + o), v); }

static VOID Tlbi(VOID)
{
    ULONG i;
    __dsb(_ARM64_BARRIER_SY);
    Wr(g_C, 0x618, 0);
    Wr(g_C, 0x7F0, 0);
    for (i = 0; i < 1000 && (Rd(g_C, 0x7F4) & 1); i++) KeStallExecutionProcessor(1);
}

static VOID Dump(PCSTR t)
{
    Log("%s: SCTLR %08x TCR2 %08x TTBR0 %08x%08x TCR %08x MAIR0 %08x FSR %08x FAR %08x%08x FSYNR0 %08x PAR %08x%08x\n", t,
        Rd(g_C, 0), Rd(g_C, 0x10), Rd(g_C, 0x24), Rd(g_C, 0x20), Rd(g_C, 0x30), Rd(g_C, 0x38), Rd(g_C, 0x58),
        Rd(g_C, 0x64), Rd(g_C, 0x60), Rd(g_C, 0x68), Rd(g_C, 0x54), Rd(g_C, 0x50));
}

static VOID Ats(ULONGLONG va)
{
    ULONG i;
    Wr(g_C, 0x800, (ULONG)va & ~0xFFFu);
    Wr(g_C, 0x804, (ULONG)(va >> 32));
    for (i = 0; i < 1000 && (Rd(g_C, 0x8F0) & 1); i++) KeStallExecutionProcessor(1);
    Log("  ATS1PR %llx -> PAR %08x%08x (ATSR %08x)\n", va, Rd(g_C, 0x54), Rd(g_C, 0x50), Rd(g_C, 0x8F0));
}

static VOID Try(PCSTR Name, ULONGLONG L1Pa, ULONG Tcr, ULONG Tcr2, ULONG Sctlr, ULONG Orig[8], BOOLEAN Q)
{
    ULONG fsr;
    Wr(g_C, 0, Orig[0]);
    Tlbi();
    Wr(g_C, 0x10, Tcr2);
    Wr(g_C, 0x30, Tcr);
    if (Q) {
        WRITE_REGISTER_ULONG64((volatile ULONG64 *)(g_C + 0x20), L1Pa | (4ULL << 48));
        WRITE_REGISTER_ULONG64((volatile ULONG64 *)(g_C + 0x28), 4ULL << 48);
    } else {
        Wr(g_C, 0x20, (ULONG)L1Pa);
        Wr(g_C, 0x24, (ULONG)(L1Pa >> 32));
    }
    Wr(g_C, 0x38, 0x44);
    Wr(g_C, 0x3C, 0);
    Tlbi();
    Wr(g_C, 0x58, Rd(g_C, 0x58));
    Wr(g_C, 0, Sctlr);
    KeStallExecutionProcessor(30000);
    fsr = Rd(g_C, 0x58);
    Log("%s: L1 %llx tcr %08x tcr2 %08x -> FSR %08x\n", Name, L1Pa, Tcr, Tcr2, fsr);
    Dump("  regs");
    Ats(0xB8000000ULL);
    Wr(g_C, 0, Orig[0]);                                     /* back to bypass at once */
    Tlbi();
    Wr(g_C, 0x58, Rd(g_C, 0x58));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT Drv, PUNICODE_STRING Reg)
{
    UNICODE_STRING n = RTL_CONSTANT_STRING(L"\\??\\C:\\topaz\\cb4probe.log");
    OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; PHYSICAL_ADDRESS pa, lo, hi, sk;
    ULONG orig[8], i;
    ULONGLONG *hiT, *loT, hiPa, loPa;
    UNREFERENCED_PARAMETER(Drv); UNREFERENCED_PARAMETER(Reg);
    InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&g_Log, FILE_WRITE_DATA | SYNCHRONIZE, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
                                 FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0))) g_Log = NULL;
    pa.QuadPart = SMMU_PA;
    g_S = (volatile UCHAR *)MmMapIoSpaceEx(pa, 0x1000, PAGE_READWRITE | PAGE_NOCACHE);
    pa.QuadPart = SMMU_PA + CB4_OFF;
    g_C = (volatile UCHAR *)MmMapIoSpaceEx(pa, 0x1000, PAGE_READWRITE | PAGE_NOCACHE);
    if (!g_S || !g_C) { Log("map failed\n"); goto out; }
    Log("IDR0 %08x IDR1 %08x IDR2 %08x IDR7 %08x sCR0 %08x\n", Rd(g_S, 0x20), Rd(g_S, 0x24), Rd(g_S, 0x28), Rd(g_S, 0x3C), Rd(g_S, 0));
    Log("SMR4 %08x S2CR4 %08x CBAR4 %08x CBA2R4 %08x\n", Rd(g_S, 0x800 + 16), Rd(g_S, 0xC00 + 16),
        g_S ? 0 : 0, 0);
    Dump("orig");
    for (i = 0; i < 8; i++) orig[i] = Rd(g_C, i == 0 ? 0 : i == 1 ? 0x10 : i == 2 ? 0x20 : i == 3 ? 0x24 : i == 4 ? 0x30 : i == 5 ? 0x38 : i == 6 ? 0x3C : 0x8);
    lo.QuadPart = 0; sk.QuadPart = 0;
    hi.QuadPart = 0xFFFFFFFFFULL;
    hiT = (ULONGLONG *)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, lo, hi, sk, MmNonCached);
    hi.QuadPart = 0xFFFFFFFFULL;
    loT = (ULONGLONG *)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, lo, hi, sk, MmNonCached);
    if (!hiT || !loT) { Log("table alloc failed\n"); goto out; }
    RtlZeroMemory(hiT, PAGE_SIZE); RtlZeroMemory(loT, PAGE_SIZE);
    hiT[2] = loT[2] = 0x080000000ULL | 0x441;
    hiT[3] = loT[3] = 0x0C0000000ULL | 0x441;
    __dsb(_ARM64_BARRIER_SY);
    hiPa = (ULONGLONG)MmGetPhysicalAddress(hiT).QuadPart;
    loPa = (ULONGLONG)MmGetPhysicalAddress(loT).QuadPart;
    Log("tables: hi %llx lo %llx, hi[2] readback %llx\n", hiPa, loPa, hiT[2]);
    {
        PHYSICAL_ADDRESS g1; volatile UCHAR *gr1; g1.QuadPart = SMMU_PA + 0x1000;
        gr1 = (volatile UCHAR *)MmMapIoSpaceEx(g1, 0x1000, PAGE_READWRITE | PAGE_NOCACHE);
        if (gr1) { Log("CBAR4 %08x CBA2R4 %08x CBAR0 %08x CBA2R0 %08x\n", Rd(gr1, 0x10), Rd(gr1, 0x810), Rd(gr1, 0), Rd(gr1, 0x800)); MmUnmapIoSpace((PVOID)gr1, 0x1000); }
    }
    Try("E linux-like q", hiPa, 25u | (1u << 23) | (2u << 12), (7u << 15) | (1u << 4) | 1u, 0x61, orig, TRUE);
    Try("F linux-like 32", hiPa, 25u | (1u << 23) | (2u << 12), (7u << 15) | (1u << 4) | 1u, 0x61, orig, FALSE);
    Try("G lo q", loPa, 25u | (1u << 23) | (2u << 12), (7u << 15) | (1u << 4) | 1u, 0x61, orig, TRUE);
    Try("H lo q orig-tcr2", loPa, 25u | (1u << 23), orig[1] | 1u, 0x61, orig, TRUE);
    /* restore everything */
    Wr(g_C, 0, orig[0]);
    Wr(g_C, 0x10, orig[1]); Wr(g_C, 0x20, orig[2]); Wr(g_C, 0x24, orig[3]); Wr(g_C, 0x30, orig[4]);
    Wr(g_C, 0x38, orig[5]); Wr(g_C, 0x3C, orig[6]);
    Tlbi();
    Wr(g_C, 0x58, Rd(g_C, 0x58));
    Dump("restored");
    MmFreeContiguousMemory(hiT); MmFreeContiguousMemory(loT);
out:
    if (g_C) MmUnmapIoSpace((PVOID)g_C, 0x1000);
    if (g_S) MmUnmapIoSpace((PVOID)g_S, 0x1000);
    if (g_Log) ZwClose(g_Log);
    return STATUS_DEVICE_CONFIGURATION_ERROR;
}
