/* SPDX-License-Identifier: MIT
 * OpenCpuGov — load-based CPU frequency governor for the OnePlus Open (SM8550) under Windows.
 *
 * Windows has no driver for the SM8550 EPSS frequency hardware, so UEFI's request stays in place
 * (CPU4-6 ~2.7 GHz, CPU7 ~3.0 GHz) whatever the load. This driver runs a system thread that every
 * 40 ms reads per-processor idle/busy time (SystemProcessorPerformanceInformation), and per cluster
 * requests the lowest LUT step >= 1.25 x current_freq x busy (schedutil-style), jumps to the cap when a
 * CPU of the cluster is >= 85 % busy, steps up at once and down only after 3 consecutive lower targets.
 *
 * v2 (UI smoothness): a high-resolution 20 ms tick (the plain kernel wait quantised 40 ms to ~47 ms), 1.4 x
 * headroom and a 75 % saturation threshold, and a UI boost: the display driver (topazgpu_opt2) signals the
 * named event \BaseNamedObjects\OpenUiActivity on every flip; while frames are being produced (and 200 ms after)
 * the performance clusters stay at >= 1.4 GHz and the efficiency cluster at >= 1.0 GHz. Parameter UiBoost=0
 * turns the boost off.
 *
 * EPSS (stock DT qcom,cpufreq-epss): domain 0 0x17D91000 CPU0-3, domain 1 0x17D92000 CPU4-6,
 * domain 2 0x17D93000 CPU7; 0x020 state, 0x100 frequency LUT, 0x320 perf-state request (Linux
 * qcom-cpufreq-hw epss layout). Windows processor numbers 0..7 follow the MADT order CPU0..CPU7.
 *
 * Parameters (service key\Parameters, read at start): Disable (1 = do nothing), MaxIdx0/1/2 (cap per
 * domain, default = top of table), PeriodMs (default 40). Logs to C:\topaz\cpugov.log every 30 s.
 */
#include <ntddk.h>
#include <ntstrsafe.h>

#define EPSS0_PA   0x17D91000ULL
#define XO_KHZ     19200u
#define LUT_MAX    40
#define NDOM       3
#define NCPU       8

#define R_STATE    0x020
#define R_FLUT     0x100
#define R_PERF     0x320

typedef struct _SPPI {                  /* SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION */
    LARGE_INTEGER IdleTime, KernelTime, UserTime, DpcTime, InterruptTime;
    ULONG InterruptCount;
} SPPI;
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG Class, PVOID Info, ULONG Len, PULONG Ret);
#define SystemProcessorPerformanceInformation 8

typedef struct _DOM {
    volatile UCHAR *Regs;
    ULONG Khz[LUT_MAX];
    ULONG Rows, MaxIdx, Cur, DownVotes;
    ULONG64 Residency[LUT_MAX];         /* samples spent at each index */
    ULONG FirstCpu, LastCpu;
} DOM;

static DOM g_Dom[NDOM];
static HANDLE g_Log;
static KEVENT g_Stop;
static PKTHREAD g_Thread;
static ULONG g_PeriodMs = 20;
static ULONG g_UiBoost = 1;
static PKEVENT g_UiEv;
static HANDLE g_UiEvH;
static PEX_TIMER g_Tick;
static KEVENT g_TickEv;
static const ULONG g_BoostKhz[NDOM] = { 1000000, 1400000, 1400000 };
static ULONG64 g_BoostTicks;

static VOID TickCb(PEX_TIMER Timer, PVOID Ctx)
{
    UNREFERENCED_PARAMETER(Timer); UNREFERENCED_PARAMETER(Ctx);
    KeSetEvent(&g_TickEv, IO_NO_INCREMENT, FALSE);
}

static VOID Log(PCSTR Fmt, ...)
{
    CHAR buf[700];
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
    UNICODE_STRING n = RTL_CONSTANT_STRING(L"\\??\\C:\\topaz\\cpugov.log");
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    InitializeObjectAttributes(&oa, &n, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateFile(&g_Log, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
                                 FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0)))
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
    return ((row >> 30) & 3) ? (row & 0xFF) * XO_KHZ : 300000u;
}

static VOID SetIdx(DOM *d, ULONG idx)
{
    if (idx != d->Cur) {
        WRITE_REGISTER_ULONG((volatile ULONG *)(d->Regs + R_PERF), idx);
        d->Cur = idx;
    }
}

static VOID LogStats(ULONG64 Samples)
{
    ULONG i, k;
    for (k = 0; k < NDOM; k++) {
        DOM *d = &g_Dom[k];
        ULONG64 tot = 0, wsum = 0;
        for (i = 0; i < d->Rows; i++) { tot += d->Residency[i]; wsum += d->Residency[i] * (d->Khz[i] / 1000); }
        Log("dom%u: now %u MHz (idx %u, hw %u MHz), avg %llu MHz over %llu samples, ui-boost samples %llu\n", k,
            d->Khz[d->Cur] / 1000, d->Cur, (Rd(d->Regs, R_STATE) & 0xFF) * XO_KHZ / 1000, tot ? wsum / tot : 0, tot,
            g_BoostTicks);
        RtlZeroMemory(d->Residency, sizeof(d->Residency));
    }
    UNREFERENCED_PARAMETER(Samples);
}

static KSTART_ROUTINE GovThread;
static VOID GovThread(PVOID Ctx)
{
    SPPI prev[NCPU], cur[NCPU];
    ULONG ret, i, k, boostLeft = 0;
    ULONG64 n = 0;
    LARGE_INTEGER dt;
    PVOID objs[2];
    UNREFERENCED_PARAMETER(Ctx);

    RtlZeroMemory(prev, sizeof(prev));
    ZwQuerySystemInformation(SystemProcessorPerformanceInformation, prev, sizeof(prev), &ret);
    dt.QuadPart = -10000LL * g_PeriodMs;
    objs[0] = &g_Stop; objs[1] = &g_TickEv;
    for (;;) {
        if (g_Tick) {
            if (KeWaitForMultipleObjects(2, objs, WaitAny, Executive, KernelMode, FALSE, NULL, NULL) == STATUS_WAIT_0) break;
        } else if (KeWaitForSingleObject(&g_Stop, Executive, KernelMode, FALSE, &dt) == STATUS_SUCCESS) {
            break;
        }
        if (!NT_SUCCESS(ZwQuerySystemInformation(SystemProcessorPerformanceInformation, cur, sizeof(cur), &ret)))
            continue;
        if (g_UiEv && KeReadStateEvent(g_UiEv)) {          /* frames were flipped since the last tick */
            KeClearEvent(g_UiEv);
            boostLeft = 200 / g_PeriodMs;
        } else if (boostLeft) {
            boostLeft--;
        }
        if (boostLeft) g_BoostTicks++;
        for (k = 0; k < NDOM; k++) {
            DOM *d = &g_Dom[k];
            ULONG busyPm = 0, target, idx;   /* busiest CPU of the cluster, per mille */
            for (i = d->FirstCpu; i <= d->LastCpu && i < NCPU; i++) {
                LONG64 tot = (cur[i].KernelTime.QuadPart - prev[i].KernelTime.QuadPart) +
                             (cur[i].UserTime.QuadPart - prev[i].UserTime.QuadPart);
                LONG64 idle = cur[i].IdleTime.QuadPart - prev[i].IdleTime.QuadPart;
                if (tot > 0) {
                    LONG64 b = (tot - idle) * 1000 / tot;
                    if (b > (LONG64)busyPm) busyPm = (ULONG)(b < 0 ? 0 : b);
                }
            }
            target = (ULONG)((ULONG64)d->Khz[d->Cur] * busyPm * 7 / 5000);   /* 1.4 x f_cur x busy */
            if (boostLeft && target < g_BoostKhz[k]) target = g_BoostKhz[k];  /* UI is animating */
            for (idx = 0; idx < d->MaxIdx && d->Khz[idx] < target; idx++) {}
            if (busyPm >= 750) idx = d->MaxIdx;                               /* saturated: go straight to the cap */
            if (idx > d->Cur) {
                d->DownVotes = 0;
                SetIdx(d, idx);
            } else if (idx < d->Cur) {
                if (++d->DownVotes >= 3) { d->DownVotes = 0; SetIdx(d, idx); }
            } else {
                d->DownVotes = 0;
            }
            d->Residency[d->Cur]++;
        }
        RtlCopyMemory(prev, cur, sizeof(prev));
        if (++n % (30000 / g_PeriodMs) == 0) LogStats(n);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID Unload(PDRIVER_OBJECT DriverObject)
{
    ULONG k;
    UNREFERENCED_PARAMETER(DriverObject);
    if (g_Tick) { ExDeleteTimer(g_Tick, TRUE, FALSE, NULL); g_Tick = NULL; }
    if (g_Thread) {
        KeSetEvent(&g_Stop, IO_NO_INCREMENT, FALSE);
        KeWaitForSingleObject(g_Thread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_Thread);
    }
    for (k = 0; k < NDOM; k++) {
        if (g_Dom[k].Regs) {
            SetIdx(&g_Dom[k], g_Dom[k].MaxIdx);        /* hand back a full-speed request */
            MmUnmapIoSpace((PVOID)g_Dom[k].Regs, 0x1000);
        }
    }
    if (g_UiEvH) ZwClose(g_UiEvH);
    Log("unloaded: all domains back at their cap\n");
    if (g_Log) ZwClose(g_Log);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    static const PCWSTR caps[NDOM] = { L"MaxIdx0", L"MaxIdx1", L"MaxIdx2" };
    static const ULONG first[NDOM] = { 0, 4, 7 }, last[NDOM] = { 3, 6, 7 };
    HANDLE th;
    ULONG k, i;
    NTSTATUS st;

    LogOpen();
    if (QueryDword(RegistryPath, L"Disable", 0)) {
        Log("disabled by registry\n");
        if (g_Log) ZwClose(g_Log);
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }
    g_PeriodMs = QueryDword(RegistryPath, L"PeriodMs", 20);
    if (g_PeriodMs < 10 || g_PeriodMs > 1000) g_PeriodMs = 20;
    g_UiBoost = QueryDword(RegistryPath, L"UiBoost", 1);
    if (KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS) != NCPU) {
        Log("unexpected processor count %u - not starting\n", KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS));
        if (g_Log) ZwClose(g_Log);
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }
    for (k = 0; k < NDOM; k++) {
        PHYSICAL_ADDRESS pa;
        DOM *d = &g_Dom[k];
        ULONG perf, cap;
        pa.QuadPart = EPSS0_PA + 0x1000ULL * k;
        d->Regs = (volatile UCHAR *)MmMapIoSpaceEx(pa, 0x1000, PAGE_READWRITE | PAGE_NOCACHE);
        if (!d->Regs) { Log("dom%u: map failed\n", k); goto fail; }
        for (i = 0; i < LUT_MAX; i++) {
            ULONG row = Rd(d->Regs, R_FLUT + 4 * i);
            if (i > 0 && row == Rd(d->Regs, R_FLUT + 4 * (i - 1))) break;
            d->Khz[i] = RowKhz(row);
        }
        d->Rows = i;
        if (d->Rows < 2) { Log("dom%u: LUT has %u rows - not starting\n", k, d->Rows); goto fail; }
        cap = QueryDword(RegistryPath, caps[k], d->Rows - 1);
        d->MaxIdx = cap < d->Rows ? cap : d->Rows - 1;
        perf = Rd(d->Regs, R_PERF);
        d->Cur = perf < d->Rows ? perf : d->MaxIdx;
        d->FirstCpu = first[k];
        d->LastCpu = last[k];
        Log("dom%u: %u steps %u..%u MHz, cap idx %u (%u MHz), UEFI request idx %u\n", k, d->Rows, d->Khz[0] / 1000,
            d->Khz[d->Rows - 1] / 1000, d->MaxIdx, d->Khz[d->MaxIdx] / 1000, perf);
    }
    KeInitializeEvent(&g_Stop, NotificationEvent, FALSE);
    KeInitializeEvent(&g_TickEv, SynchronizationEvent, FALSE);
    if (g_UiBoost) {
        UNICODE_STRING en = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\OpenUiActivity");
        g_UiEv = IoCreateNotificationEvent(&en, &g_UiEvH);   /* opens it if the display driver created it first */
        if (g_UiEv) KeClearEvent(g_UiEv);
    }
    g_Tick = ExAllocateTimer(TickCb, NULL, EX_TIMER_HIGH_RESOLUTION);
    if (g_Tick) ExSetTimer(g_Tick, -10000LL * g_PeriodMs, 10000LL * g_PeriodMs, NULL);
    st = PsCreateSystemThread(&th, THREAD_ALL_ACCESS, NULL, NULL, NULL, GovThread, NULL);
    if (!NT_SUCCESS(st)) goto fail;
    ObReferenceObjectByHandle(th, SYNCHRONIZE, *PsThreadType, KernelMode, (PVOID *)&g_Thread, NULL);
    ZwClose(th);
    DriverObject->DriverUnload = Unload;
    Log("governor v2 running, period %u ms (%s tick), ui boost %s\n", g_PeriodMs, g_Tick ? "high-res" : "kernel-wait",
        g_UiEv ? "on" : "off");
    return STATUS_SUCCESS;
fail:
    if (g_Tick) { ExDeleteTimer(g_Tick, TRUE, FALSE, NULL); g_Tick = NULL; }
    if (g_UiEvH) { ZwClose(g_UiEvH); g_UiEvH = NULL; }
    for (k = 0; k < NDOM; k++) if (g_Dom[k].Regs) MmUnmapIoSpace((PVOID)g_Dom[k].Regs, 0x1000);
    if (g_Log) ZwClose(g_Log);
    return STATUS_DEVICE_CONFIGURATION_ERROR;
}
