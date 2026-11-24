/* SPDX-License-Identifier: MIT
 * TopazGpuWDM — Pure WDM PnP driver for Adreno 740 on OnePlus Open (SM8550).
 * Brings up Adreno 740 (GMU/HFI, SID0/SID1 SMMU CB0, CP ring) on ACPI\OPEN0515
 * and exposes \\.\TopazGpu (IOCTL_TOPAZ_ESCAPE = 0x222000) to Mesa Turnip
 * without registering a WDDM display adapter, so Microsoft Basic Display Driver
 * and DWM remain 100% undisturbed.
 */
#include <ntddk.h>
#include "topazgpu_escape.h"
extern VOID LogOpen(VOID);
extern VOID LogClose(VOID);
extern VOID LogPrint(const char *Fmt, ...);
extern VOID MsmInit(VOID);
extern VOID MsmCleanup(VOID);
extern NTSTATUS MsmEscape(struct topazgpu_escape *Esc, PVOID Owner);
extern VOID MsmReleaseOwner(PVOID Owner);
extern VOID HwStop(VOID);

#define IOCTL_TOPAZ_ESCAPE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

extern NTSTATUS A740BindDevice(PDEVICE_OBJECT Pdo, PCM_RESOURCE_LIST Translated);

typedef struct _TOPAZ_WDM_EXT {
    PDEVICE_OBJECT Pdo;
    PDEVICE_OBJECT Lower;
    BOOLEAN        Started;
} TOPAZ_WDM_EXT;

static UNICODE_STRING g_DevName = RTL_CONSTANT_STRING(L"\\Device\\TopazGpu");
static UNICODE_STRING g_SymLink = RTL_CONSTANT_STRING(L"\\DosDevices\\TopazGpu");

static NTSTATUS ForwardSyncCompletion(PDEVICE_OBJECT DevObj, PIRP Irp, PVOID Ctx) {
    UNREFERENCED_PARAMETER(DevObj);
    UNREFERENCED_PARAMETER(Irp);
    KeSetEvent((PKEVENT)Ctx, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS ForwardPnpSync(PDEVICE_OBJECT Lower, PIRP Irp) {
    KEVENT ev;
    KeInitializeEvent(&ev, NotificationEvent, FALSE);
    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, ForwardSyncCompletion, &ev, TRUE, TRUE, TRUE);
    NTSTATUS st = IoCallDriver(Lower, Irp);
    if (st == STATUS_PENDING) {
        KeWaitForSingleObject(&ev, Executive, KernelMode, FALSE, NULL);
        st = Irp->IoStatus.Status;
    }
    return st;
}

static NTSTATUS TopazCreate(PDEVICE_OBJECT DevObj, PIRP Irp) {
    UNREFERENCED_PARAMETER(DevObj);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS TopazClose(PDEVICE_OBJECT DevObj, PIRP Irp) {
    UNREFERENCED_PARAMETER(DevObj);
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    if (sp && sp->FileObject) {
        MsmReleaseOwner(sp->FileObject);
    }
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS TopazDeviceControl(PDEVICE_OBJECT DevObj, PIRP Irp) {
    TOPAZ_WDM_EXT *ext = (TOPAZ_WDM_EXT *)DevObj->DeviceExtension;
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;

    if (sp->Parameters.DeviceIoControl.IoControlCode == IOCTL_TOPAZ_ESCAPE) {
        ULONG inLen = sp->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outLen = sp->Parameters.DeviceIoControl.OutputBufferLength;
        if (!ext->Started) {
            st = STATUS_DEVICE_NOT_READY;
        } else if (inLen < sizeof(struct topazgpu_escape) || outLen < sizeof(struct topazgpu_escape) || !Irp->AssociatedIrp.SystemBuffer) {
            st = STATUS_BUFFER_TOO_SMALL;
        } else {
            struct topazgpu_escape *esc = (struct topazgpu_escape *)Irp->AssociatedIrp.SystemBuffer;
            st = MsmEscape(esc, sp->FileObject);
            info = sizeof(struct topazgpu_escape);
        }
    }

    Irp->IoStatus.Status = st;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return st;
}

static NTSTATUS TopazPnp(PDEVICE_OBJECT DevObj, PIRP Irp) {
    TOPAZ_WDM_EXT *ext = (TOPAZ_WDM_EXT *)DevObj->DeviceExtension;
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    UCHAR minor = sp->MinorFunction;
    NTSTATUS st;

    if (minor == IRP_MN_START_DEVICE) {
        st = ForwardPnpSync(ext->Lower, Irp);
        if (NT_SUCCESS(st)) {
            st = A740BindDevice(ext->Pdo, sp->Parameters.StartDevice.AllocatedResourcesTranslated);
            if (NT_SUCCESS(st)) {
                ext->Started = TRUE;
                LogPrint("TopazGpuWDM: START_DEVICE OK -> \\\\.\\TopazGpu ready!\n");
            } else {
                LogPrint("TopazGpuWDM: A740BindDevice failed %08x\n", st);
            }
        }
        Irp->IoStatus.Status = st;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return st;
    }

    if (minor == IRP_MN_REMOVE_DEVICE) {
        ext->Started = FALSE;
        IoDeleteSymbolicLink(&g_SymLink);
        MsmCleanup();
        HwStop();
        IoSkipCurrentIrpStackLocation(Irp);
        st = IoCallDriver(ext->Lower, Irp);
        IoDetachDevice(ext->Lower);
        IoDeleteDevice(DevObj);
        return st;
    }

    if (minor == IRP_MN_QUERY_STOP_DEVICE || minor == IRP_MN_CANCEL_STOP_DEVICE ||
        minor == IRP_MN_QUERY_REMOVE_DEVICE || minor == IRP_MN_CANCEL_REMOVE_DEVICE ||
        minor == IRP_MN_STOP_DEVICE || minor == IRP_MN_SURPRISE_REMOVAL) {
        Irp->IoStatus.Status = STATUS_SUCCESS;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(ext->Lower, Irp);
}

static NTSTATUS TopazPower(PDEVICE_OBJECT DevObj, PIRP Irp) {
    TOPAZ_WDM_EXT *ext = (TOPAZ_WDM_EXT *)DevObj->DeviceExtension;
    PoStartNextPowerIrp(Irp);
    IoSkipCurrentIrpStackLocation(Irp);
    return PoCallDriver(ext->Lower, Irp);
}

static NTSTATUS TopazAddDevice(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT Pdo) {
    PDEVICE_OBJECT fdo = NULL;
    NTSTATUS st = IoCreateDevice(DriverObject, sizeof(TOPAZ_WDM_EXT), &g_DevName,
                                 FILE_DEVICE_UNKNOWN, 0, FALSE, &fdo);
    if (!NT_SUCCESS(st)) {
        LogPrint("TopazGpuWDM: IoCreateDevice failed %08x\n", st);
        return st;
    }
    TOPAZ_WDM_EXT *ext = (TOPAZ_WDM_EXT *)fdo->DeviceExtension;
    RtlZeroMemory(ext, sizeof(*ext));
    ext->Pdo = Pdo;
    ext->Lower = IoAttachDeviceToDeviceStack(fdo, Pdo);
    if (!ext->Lower) {
        IoDeleteDevice(fdo);
        return STATUS_NO_SUCH_DEVICE;
    }
    IoCreateSymbolicLink(&g_SymLink, &g_DevName);
    fdo->Flags |= DO_BUFFERED_IO | DO_POWER_PAGABLE;
    fdo->Flags &= ~DO_DEVICE_INITIALIZING;
    LogPrint("TopazGpuWDM: AddDevice OK\n");
    return STATUS_SUCCESS;
}

static VOID TopazUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    LogClose();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    LogOpen();
    LogPrint("==== TopazGpuWDM (Adreno 740 pure-WDM bridge, BasicDisplay-safe) ====\n");
    MsmInit();

    DriverObject->DriverExtension->AddDevice = TopazAddDevice;
    DriverObject->DriverUnload = TopazUnload;
    DriverObject->MajorFunction[IRP_MJ_PNP] = TopazPnp;
    DriverObject->MajorFunction[IRP_MJ_POWER] = TopazPower;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = TopazCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = TopazClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TopazDeviceControl;
    return STATUS_SUCCESS;
}
