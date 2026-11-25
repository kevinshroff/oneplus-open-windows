/* SPDX-License-Identifier: MIT
 * OpenCpuPerf — SM8550 (OnePlus Open) CPU frequency domains via EPSS ("qcom,cpufreq-epss", stock DT):
 *   domain 0 @0x17D91000 CPU0-3, domain 1 @0x17D92000 CPU4-6, domain 2 @0x17D93000 CPU7.
 * Register layout as Linux drivers/cpufreq/qcom-cpufreq-hw.c (epss_soc_data):
 *   0x000 enable, 0x020 domain state (current L-value in [7:0]), 0x0B0 DCVS control,
 *   0x100 frequency LUT (4-byte rows: [7:0] L-value x 19.2 MHz, [31:30] source), 0x200 voltage LUT,
 *   0x320 performance-state request (LUT index).
 *
 * One-shot: logs to C:\topaz\cpuperf.log and unloads. Parameters (service key\Parameters):
 *   Mode 0 = read-only probe; Mode 1 = write PerfState0/1/2 (LUT index; 0xFFFFFFFF = leave unchanged).
 */
#include <ntddk.h>
#include <ntstrsafe.h>

#define EPSS0_PA   0x17D91000ULL
#define XO_KHZ     19200u
#define LUT_ROWS   40

#define R_ENABLE   0x000
#define R_STATE    0x020
#define R_DCVS     0x0B0
#define R_FLUT     0x100
#define R_VLUT     0x200
#define R_PERF     0x320

static HANDLE g_Log;

static VOID Log(PCSTR Fmt, ...)
{
    CHAR buf[640];
    va_list ap;
    IO_STATUS_BLOCK iosb;
    size_t len = 0;
    va_start(ap, Fmt);
    if (!NT_SUCCESS(RtlStringCbVPrintfA(buf, sizeof(buf), Fmt, ap))) { va_end(ap); return; }
    va_end(ap);
    if (g_Log && NT_SUCCESS(RtlStringCbLengthA(buf, sizeof(buf), &len)))
        ZwWriteFile(g_Log, NULL, NULL, NULL, &iosb, buf, (ULONG)len, NULL, NULL);
}

static VOID LogOpen(VOID)
{
    UNICODE_STRING n = RTL_CONSTANT_STRING(L"\\??\\C:\\topaz\\cpuperf.log");
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

static ULONG RowKhz(ULONG row)
{
    ULONG src = (row >> 30) & 3, lval = row & 0xFF;
    return src ? lval * XO_KHZ : 300000u;    /* source 0 = GPLL0 alternate (300 MHz) */
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    static const PCWSTR names[3] = { L"PerfState0", L"PerfState1", L"PerfState2" };
    ULONG mode, d, i;
    UNREFERENCED_PARAMETER(DriverObject);

    LogOpen();
    mode = QueryDword(RegistryPath, L"Mode", 0);
    Log("---- OpenCpuPerf mode %u\n", mode);
    for (d = 0; d < 3; d++) {
        PHYSICAL_ADDRESS pa;
        volatile UCHAR *b;
        ULONG want, nrows = 0, state, perf;
        CHAR line[600];
        size_t used = 0;

        pa.QuadPart = EPSS0_PA + 0x1000ULL * d;
        b = (volatile UCHAR *)MmMapIoSpaceEx(pa, 0x1000, PAGE_READWRITE | PAGE_NOCACHE);
        if (!b) { Log("domain %u: map failed\n", d); continue; }
        state = Rd(b, R_STATE);
        perf = Rd(b, R_PERF);
        Log("domain %u @%llx: enable %08x state %08x (cur %u MHz) dcvs %08x perf_state %u\n", d, pa.QuadPart,
            Rd(b, R_ENABLE), state, (state & 0xFF) * XO_KHZ / 1000, Rd(b, R_DCVS), perf);
        line[0] = 0;
        for (i = 0; i < LUT_ROWS; i++) {
            ULONG row = Rd(b, R_FLUT + 4 * i), khz = RowKhz(row);
            if (i > 0 && row == Rd(b, R_FLUT + 4 * (i - 1))) break;   /* repeated row = end of table */
            nrows++;
            RtlStringCbPrintfA(line + used, sizeof(line) - used, " %u:%u", i, khz / 1000);
            RtlStringCbLengthA(line, sizeof(line), &used);
        }
        Log("domain %u LUT (%u rows, idx:MHz):%s\n", d, nrows, line);

        want = QueryDword(RegistryPath, names[d], 0xFFFFFFFFu);
        if (mode == 1 && want != 0xFFFFFFFFu) {
            if (want >= nrows) {
                Log("domain %u: refusing perf state %u (table has %u rows)\n", d, want, nrows);
            } else {
                WRITE_REGISTER_ULONG((volatile ULONG *)(b + R_PERF), want);
                KeStallExecutionProcessor(2000);
                state = Rd(b, R_STATE);
                Log("domain %u: perf_state %u -> %u (%u MHz requested); state now %08x (%u MHz)\n", d, perf, want,
                    RowKhz(Rd(b, R_FLUT + 4 * want)) / 1000, state, (state & 0xFF) * XO_KHZ / 1000);
            }
        }
        MmUnmapIoSpace((PVOID)b, 0x1000);
    }
    if (g_Log) ZwClose(g_Log);
    return STATUS_DEVICE_CONFIGURATION_ERROR;    /* one-shot: unload */
}
