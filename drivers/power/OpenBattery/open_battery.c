/* SPDX-License-Identifier: MIT
 * OpenBattery: Windows Battery Class Minidriver (battc.sys) for OnePlus Open (SM8550).
 *
 * Bridges live dual-cell ZY0602 fuel-gauge telemetry and ADSP USB online state from
 * OpenChargerKeeper (\\Device\\OpenChargerKeeper, IOCTL_CK_STATUS) into the native
 * Windows Battery Class driver so Windows 11 displays real battery percentage,
 * charging state, rate, voltage, temperature, and battery reports.
 *
 * Root-enumerated PnP device: ROOT\OPENBATTERY (Class = Battery).
 */
#include <ntddk.h>
#include <batclass.h>
#include <stdint.h>

#define CK_MAGIC            0x4B43504Fu
#define IOCTL_CK_STATUS     0x00226000u
#define OPENBATT_POOL_TAG   'taBO'
#define OPENBATT_TAG_VALUE  1u
#define OPENBATT_NOM_MV     3890u  /* OnePlus Open dual-cell nominal voltage (3.89 V) */
#define OPENBATT_DESIGN_MWH 18690u /* 4805 mAh * 3.89 V = 18.69 Wh */
#define OPENBATT_POLL_MS    3000

/* Must match OpenChargerKeeper protocol.h (v4, 368 bytes) */
typedef struct {
    uint32_t Valid;
    uint32_t UsbOnline;
    uint32_t UsbType;
    uint32_t VoltageMv[2];
    uint32_t TempDeciK[2];
    uint32_t SocPct[2];
    uint32_t RemMah[2];
    uint32_t FullMah[2];
    int32_t  CurrentMa[2];
    uint32_t Flags[2];
} CK_TELEMETRY_WIRE;

typedef struct {
    uint32_t Size;
    uint32_t Version;
    uint32_t Magic;
    uint32_t KernelBuild;
    uint32_t Processors;
    uint32_t Admitted;
    uint32_t AdmissionCode;
    uint32_t GlinkPhase;
    uint32_t GlinkFault;
    uint32_t PolicyState;
    uint32_t SafetyReason;
    uint32_t FvProgrammed;
    uint32_t Paused;
    uint32_t EnableCount;
    uint32_t DisableCount;
    uint32_t SafetyTrips;
    uint32_t GaugeReadsOk;
    uint32_t GaugeReadsFail;
    uint64_t NowUs;
    uint64_t TimerTicks;
    uint64_t GlinkTxFrames;
    uint64_t GlinkRxFrames;
    CK_TELEMETRY_WIRE Telemetry;
    uint32_t UsbVoltNow;
    uint32_t UsbCurrNow;
    uint32_t UsbCurrMax;
    uint32_t UsbInputLimit;
    uint32_t UsbRejectedMask;
    uint32_t GaugeCode, GaugeStage, PreCode, PreReady, PreClock, PrePins;
    uint32_t PreClocks[2][8];
    uint32_t GaugeQueryMask;
    uint32_t GaugeWords[2][10];
} CK_STATUS_WIRE;

typedef struct _OPENBATT_DEVEXT {
    PDEVICE_OBJECT  Fdo;
    PDEVICE_OBJECT  Pdo;
    PDEVICE_OBJECT  LowerDevice;
    PVOID           ClassHandle;

    KSPIN_LOCK      Lock;
    KTIMER          PollTimer;
    KDPC            PollDpc;
    PIO_WORKITEM    PollWorkItem;
    volatile LONG   WorkItemQueued;
    volatile LONG   Stopping;

    /* Cached battery telemetry */
    BOOLEAN         HasValidData;
    ULONG           DesignCapacityMwh;
    ULONG           FullChargedCapacityMwh;
    ULONG           RemainingCapacityMwh;
    ULONG           VoltageMv;
    LONG            RateMw;
    ULONG           TempDeciK;
    ULONG           PowerState;
    ULONG           LastReportedSoc;

    /* Notification thresholds requested by battc.sys */
    BOOLEAN         NotifyEnabled;
    BATTERY_NOTIFY  Notify;
} OPENBATT_DEVEXT, *POPENBATT_DEVEXT;

DRIVER_INITIALIZE DriverEntry;
static DRIVER_ADD_DEVICE OpenBattAddDevice;
static DRIVER_UNLOAD OpenBattUnload;
static DRIVER_DISPATCH OpenBattCreateClose;
static DRIVER_DISPATCH OpenBattDeviceControl;
static DRIVER_DISPATCH OpenBattPnp;
static DRIVER_DISPATCH OpenBattPower;
static DRIVER_DISPATCH OpenBattSystemControl;

/* Poll OpenChargerKeeper at PASSIVE_LEVEL */
static VOID OpenBattPollKeeper(POPENBATT_DEVEXT Ext) {
    UNICODE_STRING ckName;
    PFILE_OBJECT fileObj = NULL;
    PDEVICE_OBJECT devObj = NULL;
    CK_STATUS_WIRE *snap = NULL;
    KEVENT event;
    IO_STATUS_BLOCK iosb;
    PIRP irp;
    NTSTATUS status;

    if (InterlockedCompareExchange(&Ext->Stopping, 0, 0)) return;

    RtlInitUnicodeString(&ckName, L"\\Device\\OpenChargerKeeper");
    status = IoGetDeviceObjectPointer(&ckName, FILE_READ_DATA, &fileObj, &devObj);
    if (!NT_SUCCESS(status) || !devObj) return;

    snap = (CK_STATUS_WIRE *)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*snap), OPENBATT_POOL_TAG);
    if (!snap) {
        ObDereferenceObject(fileObj);
        return;
    }

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    RtlZeroMemory(&iosb, sizeof(iosb));
    irp = IoBuildDeviceIoControlRequest(
        IOCTL_CK_STATUS, devObj, NULL, 0, snap, sizeof(*snap), FALSE, &event, &iosb);
    if (irp) {
        status = IoCallDriver(devObj, irp);
        if (status == STATUS_PENDING) {
            KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
            status = iosb.Status;
        }
    } else {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }

    ObDereferenceObject(fileObj);

    if (NT_SUCCESS(status) && snap->Magic == CK_MAGIC && snap->Telemetry.Valid) {
        ULONG fullMah = snap->Telemetry.FullMah[0] + snap->Telemetry.FullMah[1];
        ULONG remMah  = snap->Telemetry.RemMah[0]  + snap->Telemetry.RemMah[1];
        ULONG avgMv   = (snap->Telemetry.VoltageMv[0] + snap->Telemetry.VoltageMv[1]) / 2u;
        LONG  totMa   = (LONG)snap->Telemetry.CurrentMa[0] + (LONG)snap->Telemetry.CurrentMa[1];
        ULONG avgTemp = (snap->Telemetry.TempDeciK[0] + snap->Telemetry.TempDeciK[1]) / 2u;
        ULONG minSoc  = snap->Telemetry.SocPct[0] < snap->Telemetry.SocPct[1]
                        ? snap->Telemetry.SocPct[0] : snap->Telemetry.SocPct[1];

        ULONG fullMwh   = (ULONG)(((ULONGLONG)fullMah * OPENBATT_NOM_MV) / 1000ULL);
        ULONG remMwh    = (ULONG)(((ULONGLONG)remMah  * OPENBATT_NOM_MV) / 1000ULL);
        if (fullMwh < 1000u) fullMwh = OPENBATT_DESIGN_MWH;
        if (remMwh > fullMwh) remMwh = fullMwh;
        ULONG designMwh = (fullMwh > OPENBATT_DESIGN_MWH) ? fullMwh : OPENBATT_DESIGN_MWH;
        LONG  rateMw    = (LONG)(((LONGLONG)totMa * (LONGLONG)avgMv) / 1000LL);
        ULONG socPct    = fullMwh ? (ULONG)(((ULONGLONG)remMwh * 100ULL) / fullMwh) : 0u;
        if (socPct > 100u) socPct = 100u;

        ULONG ps = 0;
        if (snap->Telemetry.UsbOnline) ps |= BATTERY_POWER_ON_LINE;
        if (totMa > 15) {
            ps |= BATTERY_CHARGING;
        } else if (totMa < -15) {
            ps |= BATTERY_DISCHARGING;
        } else if (!snap->Telemetry.UsbOnline) {
            ps |= BATTERY_DISCHARGING;
        }
        if (!snap->Telemetry.UsbOnline && minSoc <= 5u) {
            ps |= BATTERY_CRITICAL;
        }

        KIRQL oldIrql;
        BOOLEAN shouldNotify = FALSE;
        KeAcquireSpinLock(&Ext->Lock, &oldIrql);
        BOOLEAN first = !Ext->HasValidData;
        ULONG prevPs = Ext->PowerState;
        ULONG prevSoc = Ext->LastReportedSoc;

        Ext->HasValidData = TRUE;
        Ext->DesignCapacityMwh = designMwh;
        Ext->FullChargedCapacityMwh = fullMwh;
        Ext->RemainingCapacityMwh = remMwh;
        Ext->VoltageMv = avgMv;
        Ext->RateMw = rateMw;
        Ext->TempDeciK = avgTemp;
        Ext->PowerState = ps;
        Ext->LastReportedSoc = socPct;

        if (first || ps != prevPs || socPct != prevSoc) {
            shouldNotify = TRUE;
        } else if (Ext->NotifyEnabled) {
            if (ps != Ext->Notify.PowerState ||
                remMwh <= Ext->Notify.LowCapacity ||
                remMwh >= Ext->Notify.HighCapacity) {
                shouldNotify = TRUE;
            }
        }
        KeReleaseSpinLock(&Ext->Lock, oldIrql);

        if (shouldNotify && Ext->ClassHandle) {
            BatteryClassStatusNotify(Ext->ClassHandle);
        }
    }

    ExFreePoolWithTag(snap, OPENBATT_POOL_TAG);
}

static VOID OpenBattWorkItemRoutine(PDEVICE_OBJECT DeviceObject, PVOID Context) {
    UNREFERENCED_PARAMETER(DeviceObject);
    POPENBATT_DEVEXT ext = (POPENBATT_DEVEXT)Context;
    OpenBattPollKeeper(ext);
    InterlockedExchange(&ext->WorkItemQueued, 0);
}

static VOID OpenBattTimerDpc(PKDPC Dpc, PVOID DeferredContext, PVOID Arg1, PVOID Arg2) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);
    POPENBATT_DEVEXT ext = (POPENBATT_DEVEXT)DeferredContext;
    if (InterlockedCompareExchange(&ext->Stopping, 0, 0)) return;
    if (InterlockedCompareExchange(&ext->WorkItemQueued, 1, 0) == 0) {
        IoQueueWorkItem(ext->PollWorkItem, OpenBattWorkItemRoutine, DelayedWorkQueue, ext);
    }
}

/* ---- Battery Class Minidriver Callbacks ---- */

static NTSTATUS OpenBattQueryTag(PVOID Context, PULONG BatteryTag) {
    POPENBATT_DEVEXT ext = (POPENBATT_DEVEXT)Context;
    if (!BatteryTag) return STATUS_INVALID_PARAMETER;

    KIRQL oldIrql;
    BOOLEAN valid;
    KeAcquireSpinLock(&ext->Lock, &oldIrql);
    valid = ext->HasValidData;
    KeReleaseSpinLock(&ext->Lock, oldIrql);

    if (!valid && KeGetCurrentIrql() == PASSIVE_LEVEL) {
        OpenBattPollKeeper(ext);
        KeAcquireSpinLock(&ext->Lock, &oldIrql);
        valid = ext->HasValidData;
        KeReleaseSpinLock(&ext->Lock, oldIrql);
    }

    *BatteryTag = OPENBATT_TAG_VALUE;
    return STATUS_SUCCESS;
}

static NTSTATUS OpenBattQueryInformation(
    PVOID Context,
    ULONG BatteryTag,
    BATTERY_QUERY_INFORMATION_LEVEL Level,
    LONG AtRate,
    PVOID Buffer,
    ULONG BufferLength,
    PULONG ReturnedLength)
{
    POPENBATT_DEVEXT ext = (POPENBATT_DEVEXT)Context;
    NTSTATUS status = STATUS_SUCCESS;
    PVOID src = NULL;
    ULONG len = 0;

    BATTERY_INFORMATION bi;
    BATTERY_REPORTING_SCALE scale;
    ULONG ulongVal = 0;
    static const WCHAR kDevName[] = L"OnePlus Open Dual-Cell Battery";
    static const WCHAR kMfgName[] = L"OnePlus";
    static const WCHAR kUniqueId[] = L"ONEPLUS-OPEN-ZY0602-DUAL";

    if (BatteryTag != OPENBATT_TAG_VALUE) return STATUS_NO_SUCH_DEVICE;
    if (!ReturnedLength) return STATUS_INVALID_PARAMETER;
    *ReturnedLength = 0;

    KIRQL oldIrql;
    ULONG designMwh, fullMwh, remMwh, tempDk, ps;
    LONG rateMw;
    KeAcquireSpinLock(&ext->Lock, &oldIrql);
    designMwh = ext->HasValidData ? ext->DesignCapacityMwh : OPENBATT_DESIGN_MWH;
    fullMwh   = ext->HasValidData ? ext->FullChargedCapacityMwh : OPENBATT_DESIGN_MWH;
    remMwh    = ext->HasValidData ? ext->RemainingCapacityMwh : (OPENBATT_DESIGN_MWH / 2u);
    tempDk    = ext->HasValidData ? ext->TempDeciK : 2981u;
    rateMw    = ext->HasValidData ? ext->RateMw : 0;
    ps        = ext->HasValidData ? ext->PowerState : BATTERY_POWER_ON_LINE;
    KeReleaseSpinLock(&ext->Lock, oldIrql);

    switch (Level) {
    case BatteryInformation:
        RtlZeroMemory(&bi, sizeof(bi));
        bi.Capabilities = BATTERY_SYSTEM_BATTERY;
        bi.Technology = 1;
        bi.Chemistry[0] = 'L'; bi.Chemistry[1] = 'I'; bi.Chemistry[2] = 'O'; bi.Chemistry[3] = 'N';
        bi.DesignedCapacity = designMwh;
        bi.FullChargedCapacity = fullMwh;
        bi.DefaultAlert1 = (fullMwh * 5u) / 100u;
        bi.DefaultAlert2 = (fullMwh * 10u) / 100u;
        bi.CriticalBias = 0;
        bi.CycleCount = 0;
        src = &bi;
        len = sizeof(bi);
        break;

    case BatteryGranularityInformation:
        scale.Granularity = 10;
        scale.Capacity = fullMwh;
        src = &scale;
        len = sizeof(scale);
        break;

    case BatteryTemperature:
        ulongVal = tempDk; /* tenths of a Kelvin */
        src = &ulongVal;
        len = sizeof(ulongVal);
        break;

    case BatteryEstimatedTime: {
        LONG useRate = (AtRate != 0) ? AtRate : rateMw;
        if ((ps & BATTERY_DISCHARGING) && useRate < -50) {
            ULONG absRate = (ULONG)(-useRate);
            ulongVal = (ULONG)(((ULONGLONG)remMwh * 3600ULL) / absRate);
        } else {
            ulongVal = BATTERY_UNKNOWN_TIME;
        }
        src = &ulongVal;
        len = sizeof(ulongVal);
        break;
    }

    case BatteryDeviceName:
        src = (PVOID)kDevName;
        len = sizeof(kDevName);
        break;

    case BatteryManufactureName:
        src = (PVOID)kMfgName;
        len = sizeof(kMfgName);
        break;

    case BatteryUniqueID:
        src = (PVOID)kUniqueId;
        len = sizeof(kUniqueId);
        break;

    default:
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    *ReturnedLength = len;
    if (BufferLength < len) return STATUS_BUFFER_TOO_SMALL;
    if (src && Buffer && len > 0) {
        RtlCopyMemory(Buffer, src, len);
    }
    return status;
}

static NTSTATUS OpenBattQueryStatus(
    PVOID Context,
    ULONG BatteryTag,
    PBATTERY_STATUS BatteryStatus)
{
    POPENBATT_DEVEXT ext = (POPENBATT_DEVEXT)Context;
    if (BatteryTag != OPENBATT_TAG_VALUE) return STATUS_NO_SUCH_DEVICE;
    if (!BatteryStatus) return STATUS_INVALID_PARAMETER;

    KIRQL oldIrql;
    KeAcquireSpinLock(&ext->Lock, &oldIrql);
    if (ext->HasValidData) {
        BatteryStatus->PowerState = ext->PowerState;
        BatteryStatus->Capacity   = ext->RemainingCapacityMwh;
        BatteryStatus->Voltage    = ext->VoltageMv;
        BatteryStatus->Rate       = ext->RateMw;
    } else {
        BatteryStatus->PowerState = BATTERY_POWER_ON_LINE;
        BatteryStatus->Capacity   = BATTERY_UNKNOWN_CAPACITY;
        BatteryStatus->Voltage    = BATTERY_UNKNOWN_VOLTAGE;
        BatteryStatus->Rate       = BATTERY_UNKNOWN_RATE;
    }
    KeReleaseSpinLock(&ext->Lock, oldIrql);
    return STATUS_SUCCESS;
}

static NTSTATUS OpenBattSetStatusNotify(
    PVOID Context,
    ULONG BatteryTag,
    PBATTERY_NOTIFY BatteryNotify)
{
    POPENBATT_DEVEXT ext = (POPENBATT_DEVEXT)Context;
    if (BatteryTag != OPENBATT_TAG_VALUE) return STATUS_NO_SUCH_DEVICE;
    if (!BatteryNotify) return STATUS_INVALID_PARAMETER;

    KIRQL oldIrql;
    KeAcquireSpinLock(&ext->Lock, &oldIrql);
    ext->Notify = *BatteryNotify;
    ext->NotifyEnabled = TRUE;
    KeReleaseSpinLock(&ext->Lock, oldIrql);
    return STATUS_SUCCESS;
}

static NTSTATUS OpenBattDisableStatusNotify(PVOID Context) {
    POPENBATT_DEVEXT ext = (POPENBATT_DEVEXT)Context;
    KIRQL oldIrql;
    KeAcquireSpinLock(&ext->Lock, &oldIrql);
    ext->NotifyEnabled = FALSE;
    KeReleaseSpinLock(&ext->Lock, oldIrql);
    return STATUS_SUCCESS;
}

static NTSTATUS OpenBattSetInformation(
    PVOID Context,
    ULONG BatteryTag,
    BATTERY_SET_INFORMATION_LEVEL Level,
    PVOID Buffer)
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(BatteryTag);
    UNREFERENCED_PARAMETER(Level);
    UNREFERENCED_PARAMETER(Buffer);
    return STATUS_NOT_SUPPORTED;
}

/* ---- WDM Dispatch ---- */

static NTSTATUS OpenBattSyncComplete(PDEVICE_OBJECT Dev, PIRP Irp, PVOID Ctx) {
    UNREFERENCED_PARAMETER(Dev);
    UNREFERENCED_PARAMETER(Irp);
    KeSetEvent((PKEVENT)Ctx, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS OpenBattForwardSync(POPENBATT_DEVEXT Ext, PIRP Irp) {
    KEVENT ev;
    KeInitializeEvent(&ev, NotificationEvent, FALSE);
    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, OpenBattSyncComplete, &ev, TRUE, TRUE, TRUE);
    NTSTATUS st = IoCallDriver(Ext->LowerDevice, Irp);
    if (st == STATUS_PENDING) {
        KeWaitForSingleObject(&ev, Executive, KernelMode, FALSE, NULL);
        st = Irp->IoStatus.Status;
    }
    return st;
}

static NTSTATUS OpenBattCreateClose(PDEVICE_OBJECT Dev, PIRP Irp) {
    UNREFERENCED_PARAMETER(Dev);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS OpenBattDeviceControl(PDEVICE_OBJECT Dev, PIRP Irp) {
    POPENBATT_DEVEXT ext = (POPENBATT_DEVEXT)Dev->DeviceExtension;
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    if (ext->ClassHandle) {
        status = BatteryClassIoctl(ext->ClassHandle, Irp);
    }
    if (status == STATUS_NOT_SUPPORTED) {
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(ext->LowerDevice, Irp);
    }
    return status;
}

static NTSTATUS OpenBattPnp(PDEVICE_OBJECT Dev, PIRP Irp) {
    POPENBATT_DEVEXT ext = (POPENBATT_DEVEXT)Dev->DeviceExtension;
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status;

    switch (sp->MinorFunction) {
    case IRP_MN_START_DEVICE: {
        status = OpenBattForwardSync(ext, Irp);
        if (NT_SUCCESS(status)) {
            BATTERY_MINIPORT_INFO info;
            RtlZeroMemory(&info, sizeof(info));
            info.MajorVersion = BATTERY_CLASS_MAJOR_VERSION;
            info.MinorVersion = BATTERY_CLASS_MINOR_VERSION;
            info.Context = ext;
            info.QueryTag = OpenBattQueryTag;
            info.QueryInformation = OpenBattQueryInformation;
            info.SetInformation = OpenBattSetInformation;
            info.QueryStatus = OpenBattQueryStatus;
            info.SetStatusNotify = OpenBattSetStatusNotify;
            info.DisableStatusNotify = OpenBattDisableStatusNotify;
            info.Pdo = ext->Pdo;
            info.DeviceName = NULL;

            status = BatteryClassInitializeDevice(&info, &ext->ClassHandle);
            if (NT_SUCCESS(status)) {
                InterlockedExchange(&ext->Stopping, 0);
                OpenBattPollKeeper(ext);
                LARGE_INTEGER due;
                due.QuadPart = -((LONGLONG)OPENBATT_POLL_MS * 10000LL);
                KeSetTimerEx(&ext->PollTimer, due, OPENBATT_POLL_MS, &ext->PollDpc);
            }
        }
        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

    case IRP_MN_QUERY_REMOVE_DEVICE:
    case IRP_MN_CANCEL_REMOVE_DEVICE:
    case IRP_MN_QUERY_STOP_DEVICE:
    case IRP_MN_CANCEL_STOP_DEVICE:
    case IRP_MN_STOP_DEVICE:
        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(ext->LowerDevice, Irp);

    case IRP_MN_SURPRISE_REMOVAL:
        InterlockedExchange(&ext->Stopping, 1);
        KeCancelTimer(&ext->PollTimer);
        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(ext->LowerDevice, Irp);

    case IRP_MN_REMOVE_DEVICE:
        InterlockedExchange(&ext->Stopping, 1);
        KeCancelTimer(&ext->PollTimer);
        KeFlushQueuedDpcs();
        while (InterlockedCompareExchange(&ext->WorkItemQueued, 0, 0) != 0) {
            LARGE_INTEGER wait;
            wait.QuadPart = -100000LL; /* 10 ms */
            KeDelayExecutionThread(KernelMode, FALSE, &wait);
        }
        if (ext->ClassHandle) {
            BatteryClassUnload(ext->ClassHandle);
            ext->ClassHandle = NULL;
        }
        if (ext->PollWorkItem) {
            IoFreeWorkItem(ext->PollWorkItem);
            ext->PollWorkItem = NULL;
        }
        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(ext->LowerDevice, Irp);
        IoDetachDevice(ext->LowerDevice);
        IoDeleteDevice(Dev);
        return status;

    case IRP_MN_QUERY_CAPABILITIES:
        status = OpenBattForwardSync(ext, Irp);
        if (NT_SUCCESS(status) && sp->Parameters.DeviceCapabilities.Capabilities) {
            sp->Parameters.DeviceCapabilities.Capabilities->SilentInstall = TRUE;
            sp->Parameters.DeviceCapabilities.Capabilities->RawDeviceOK = TRUE;
        }
        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;

    default:
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(ext->LowerDevice, Irp);
    }
}

static NTSTATUS OpenBattPower(PDEVICE_OBJECT Dev, PIRP Irp) {
    POPENBATT_DEVEXT ext = (POPENBATT_DEVEXT)Dev->DeviceExtension;
    PoStartNextPowerIrp(Irp);
    IoSkipCurrentIrpStackLocation(Irp);
    return PoCallDriver(ext->LowerDevice, Irp);
}

static NTSTATUS OpenBattSystemControl(PDEVICE_OBJECT Dev, PIRP Irp) {
    POPENBATT_DEVEXT ext = (POPENBATT_DEVEXT)Dev->DeviceExtension;
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->LowerDevice, Irp);
}

static NTSTATUS OpenBattAddDevice(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT Pdo) {
    PDEVICE_OBJECT fdo = NULL;
    NTSTATUS status = IoCreateDevice(
        DriverObject, sizeof(OPENBATT_DEVEXT), NULL, FILE_DEVICE_BATTERY,
        FILE_DEVICE_SECURE_OPEN, FALSE, &fdo);
    if (!NT_SUCCESS(status)) return status;

    POPENBATT_DEVEXT ext = (POPENBATT_DEVEXT)fdo->DeviceExtension;
    RtlZeroMemory(ext, sizeof(*ext));
    ext->Fdo = fdo;
    ext->Pdo = Pdo;
    KeInitializeSpinLock(&ext->Lock);
    KeInitializeTimer(&ext->PollTimer);
    KeInitializeDpc(&ext->PollDpc, OpenBattTimerDpc, ext);
    ext->PollWorkItem = IoAllocateWorkItem(fdo);
    if (!ext->PollWorkItem) {
        IoDeleteDevice(fdo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ext->LowerDevice = IoAttachDeviceToDeviceStack(fdo, Pdo);
    if (!ext->LowerDevice) {
        IoFreeWorkItem(ext->PollWorkItem);
        IoDeleteDevice(fdo);
        return STATUS_NO_SUCH_DEVICE;
    }

    fdo->Flags |= DO_BUFFERED_IO | DO_POWER_PAGABLE;
    fdo->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

static VOID OpenBattUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverExtension->AddDevice = OpenBattAddDevice;
    DriverObject->DriverUnload = OpenBattUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = OpenBattCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = OpenBattCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OpenBattDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_PNP]            = OpenBattPnp;
    DriverObject->MajorFunction[IRP_MJ_POWER]          = OpenBattPower;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = OpenBattSystemControl;
    return STATUS_SUCCESS;
}
