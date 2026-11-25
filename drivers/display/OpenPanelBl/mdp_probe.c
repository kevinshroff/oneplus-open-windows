/* SPDX-License-Identifier: MIT
 * mdp_probe — read-only survey of the SM8550 MDSS/MDP source pipes, CTLs and the DSI interface, to find the
 * pipe UEFI left scanning the GOP framebuffer (zero-copy direct scanout). Only blocks listed in the stock DT
 * (qcom,sde-*-off, relative to 0x0AE00000) are read. Logs to C:\topaz\mdpprobe.log, then unloads.
 */
#include <ntddk.h>
#include <ntstrsafe.h>

#define MDSS_PA   0x0AE00000ULL
#define MDSS_LEN  0x84000u

static HANDLE g_Log;
static VOID Log(PCSTR Fmt, ...)
{
    CHAR b[700]; va_list ap; IO_STATUS_BLOCK io; size_t n = 0;
    va_start(ap, Fmt);
    if (!NT_SUCCESS(RtlStringCbVPrintfA(b, sizeof(b), Fmt, ap))) { va_end(ap); return; }
    va_end(ap);
    if (g_Log && NT_SUCCESS(RtlStringCbLengthA(b, sizeof(b), &n))) ZwWriteFile(g_Log, NULL, NULL, NULL, &io, b, (ULONG)n, NULL, NULL);
}

static VOID Dump(volatile ULONG *m, PCSTR Name, ULONG Off, ULONG Len)
{
    ULONG j;
    Log("%s @+%05x:", Name, Off);
    for (j = 0; j < Len; j += 4) Log(" %08x", m[(Off + j) / 4]);
    Log("\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT Drv, PUNICODE_STRING Reg)
{
    static const ULONG sspp[6] = { 0x5000, 0x7000, 0x25000, 0x27000, 0x29000, 0x2b000 };
    static const ULONG ctl[4] = { 0x16000, 0x17000, 0x18000, 0x19000 };
    static const PCSTR spn[6] = { "vig0", "vig1", "dma0", "dma1", "dma2", "dma3" };
    static const PCSTR ctn[4] = { "ctl0", "ctl1", "ctl2", "ctl3" };
    UNICODE_STRING n = RTL_CONSTANT_STRING(L"\\??\\C:\\topaz\\mdpprobe.log");
    OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK io; PHYSICAL_ADDRESS pa;
    volatile ULONG *m; ULONG hits = 0, fb = 0xB8000000u, k, j;
    UNREFERENCED_PARAMETER(Drv); UNREFERENCED_PARAMETER(Reg);

    InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&g_Log, FILE_WRITE_DATA | SYNCHRONIZE, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL,
                                 FILE_SHARE_READ, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0)))
        g_Log = NULL;
    pa.QuadPart = MDSS_PA;
    m = (volatile ULONG *)MmMapIoSpaceEx(pa, MDSS_LEN, PAGE_READWRITE | PAGE_NOCACHE);
    if (!m) { Log("map failed\n"); goto out; }
    Log("MDSS hw_version %08x\n", m[0]);
    for (k = 0; k < 6; k++) {
        Dump(m, spn[k], sspp[k], 0x80);
        for (j = 0; j < 0x344; j += 4) {
            if (m[(sspp[k] + j) / 4] == fb) { Log("  %s +%03x == framebuffer\n", spn[k], j); hits++; }
        }
    }
    for (k = 0; k < 4; k++) Dump(m, ctn[k], ctl[k], 0x40);
    Dump(m, "intf1-dsi", 0x36000, 0x40);
    Log("hits %u\n", hits);
    MmUnmapIoSpace((PVOID)m, MDSS_LEN);
out:
    if (g_Log) ZwClose(g_Log);
    return STATUS_DEVICE_CONFIGURATION_ERROR;
}
