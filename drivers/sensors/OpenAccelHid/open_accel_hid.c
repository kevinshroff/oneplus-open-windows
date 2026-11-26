/* SPDX-License-Identifier: MIT
 * OpenAccelHid: Windows 11 VHF HID 3D Accelerometer driver for OnePlus Open (SM8550).
 *
 * Exposes a standard USB HID Sensor Collection (Usage Page 0x20, Usage 0x73 = 3D Accelerometer)
 * via Windows inbox Virtual HID Framework (VHF), so Windows 11's inbox HID Sensor Collection V2
 * (SensorsHidClassDriver) automatically binds and enables native Auto-Rotate / Rotation Lock.
 *
 * Polls live calibrated (ax, ay, az) milli-G readings from \\Device\\OpenChargerKeeper
 * (IOCTL_CK_ACCEL, backed by ADSP SSC SNS_CLIENT_SVC over SMEM GLINK IPCRTR).
 */
#include <ntifs.h>
#include <wdf.h>
#include <vhf.h>
#include <stdint.h>

#define CK_MAGIC             0x4B43504Fu
#define IOCTL_CK_ACCEL       0x0022600Cu
#define ACCEL_POOL_TAG       'cAHO'
#define ACCEL_REPORT_ID      1u
#define ACCEL_POLL_MS        100u /* 10 Hz */

/* Matches OpenChargerKeeper ipcrtr_sensors.h CK_ACCEL_SNAPSHOT header */
typedef struct {
    uint32_t Size;
    uint32_t Version;
    uint32_t Magic;
    uint32_t OpenAcked;
    uint32_t RemoteOpen;
    uint32_t HelloSent;
    uint32_t SnsFound;
    uint32_t SnsNode;
    uint32_t SnsPort;
    uint32_t SuidSent;
    uint32_t SuidFound;
    uint32_t AccelReqSent;
    uint32_t AccelValid;
    uint32_t AccelSeq;
    int32_t  AxMilliG;
    int32_t  AyMilliG;
    int32_t  AzMilliG;
} CK_ACCEL_HDR;

/*
 * Standard Microsoft HID Sensor 3D Accelerometer Report Descriptor
 * (per Microsoft "HID Sensors Usages" spec for SensorsHidClassDriver.dll)
 *
 * Feature Report (ID 1, 13 bytes payload + 1 byte ID = 14 bytes):
 *   [0]    Report ID = 1
 *   [1]    Connection Type (1=PC Integrated)
 *   [2]    Reporting State (2=All Events)
 *   [3]    Power State (2=D0 Full Power)
 *   [4]    Sensor State (2=Ready)
 *   [5..8] Report Interval (uint32, ms, default 100)
 *   [9..10] Change Sensitivity Abs (uint16, 0.001 G, default 20)
 *   [11..12] Max (int16, 0.001 G, +4000)
 *   [13..14] Min (int16, 0.001 G, -4000)
 *
 * Input Report (ID 1, 8 bytes payload + 1 byte ID = 9 bytes):
 *   [0]    Report ID = 1
 *   [1]    Sensor State (2=Ready)
 *   [2]    Sensor Event (2=State Changed / 3=Data Updated)
 *   [3..4] Accel X (int16, unit exponent -3 => 0.001 G)
 *   [5..6] Accel Y (int16, unit exponent -3 => 0.001 G)
 *   [7..8] Accel Z (int16, unit exponent -3 => 0.001 G)
 */
static const UCHAR g_AccelHidDescriptor[] = {
    0x05, 0x20,             /* Usage Page (Sensor) */
    0x09, 0x73,             /* Usage (Motion: Accelerometer 3D) */
    0xA1, 0x01,             /* Collection (Application) */
    0x85, ACCEL_REPORT_ID,  /*   Report ID (1) */

    /* ---- Feature Report ---- */
    0x05, 0x20,             /*   Usage Page (Sensor) */
    0x0A, 0x09, 0x03,       /*   Usage (Property: Sensor Connection Type) */
    0x15, 0x00,             /*   Logical Minimum (0) */
    0x25, 0x02,             /*   Logical Maximum (2) */
    0x75, 0x08,             /*   Report Size (8) */
    0x95, 0x01,             /*   Report Count (1) */
    0xA1, 0x02,             /*   Collection (Logical) */
    0x0A, 0x30, 0x08,       /*     Usage (Connection Type: PC Integrated) */
    0x0A, 0x31, 0x08,       /*     Usage (Connection Type: PC Attached) */
    0x0A, 0x32, 0x08,       /*     Usage (Connection Type: PC External) */
    0xB1, 0x00,             /*     Feature (Data, Array, Abs) */
    0xC0,                   /*   End Collection */

    0x0A, 0x16, 0x03,       /*   Usage (Property: Reporting State) */
    0x15, 0x00,             /*   Logical Minimum (0) */
    0x25, 0x05,             /*   Logical Maximum (5) */
    0x75, 0x08,             /*   Report Size (8) */
    0x95, 0x01,             /*   Report Count (1) */
    0xA1, 0x02,             /*   Collection (Logical) */
    0x0A, 0x40, 0x08,       /*     Usage (No Events) */
    0x0A, 0x41, 0x08,       /*     Usage (All Events) */
    0x0A, 0x42, 0x08,       /*     Usage (Threshold Events) */
    0x0A, 0x43, 0x08,       /*     Usage (Wake On No Events) */
    0x0A, 0x44, 0x08,       /*     Usage (Wake On All Events) */
    0x0A, 0x45, 0x08,       /*     Usage (Wake On Threshold Events) */
    0xB1, 0x00,             /*     Feature (Data, Array, Abs) */
    0xC0,                   /*   End Collection */

    0x0A, 0x19, 0x03,       /*   Usage (Property: Power State) */
    0x15, 0x00,             /*   Logical Minimum (0) */
    0x25, 0x05,             /*   Logical Maximum (5) */
    0x75, 0x08,             /*   Report Size (8) */
    0x95, 0x01,             /*   Report Count (1) */
    0xA1, 0x02,             /*   Collection (Logical) */
    0x0A, 0x50, 0x08,       /*     Usage (Undefined) */
    0x0A, 0x51, 0x08,       /*     Usage (D0 Full Power) */
    0x0A, 0x52, 0x08,       /*     Usage (D1 Low Power) */
    0x0A, 0x53, 0x08,       /*     Usage (D2 Standby) */
    0x0A, 0x54, 0x08,       /*     Usage (D3 Sleep) */
    0x0A, 0x55, 0x08,       /*     Usage (D4 Power Off) */
    0xB1, 0x00,             /*     Feature (Data, Array, Abs) */
    0xC0,                   /*   End Collection */

    0x0A, 0x01, 0x02,       /*   Usage (Event: Sensor State) */
    0x15, 0x00,             /*   Logical Minimum (0) */
    0x25, 0x06,             /*   Logical Maximum (6) */
    0x75, 0x08,             /*   Report Size (8) */
    0x95, 0x01,             /*   Report Count (1) */
    0xA1, 0x02,             /*   Collection (Logical) */
    0x0A, 0x00, 0x08,       /*     Usage (Undefined) */
    0x0A, 0x01, 0x08,       /*     Usage (Ready) */
    0x0A, 0x02, 0x08,       /*     Usage (Not Available) */
    0x0A, 0x03, 0x08,       /*     Usage (No Data) */
    0x0A, 0x04, 0x08,       /*     Usage (Initializing) */
    0x0A, 0x05, 0x08,       /*     Usage (Access Denied) */
    0x0A, 0x06, 0x08,       /*     Usage (Error) */
    0xB1, 0x00,             /*     Feature (Data, Array, Abs) */
    0xC0,                   /*   End Collection */

    0x0A, 0x0E, 0x03,       /*   Usage (Property: Report Interval, ms) */
    0x15, 0x00,             /*   Logical Minimum (0) */
    0x27, 0xFF, 0xFF, 0xFF, 0x7F, /* Logical Maximum (0x7FFFFFFF) */
    0x75, 0x20,             /*   Report Size (32) */
    0x95, 0x01,             /*   Report Count (1) */
    0x55, 0x00,             /*   Unit Exponent (0) */
    0xB1, 0x02,             /*   Feature (Data, Var, Abs) */

    0x0A, 0x52, 0x14,       /*   Usage (Data Field: Acceleration | Change Sensitivity Abs) */
    0x15, 0x00,             /*   Logical Minimum (0) */
    0x26, 0xFF, 0x7F,       /*   Logical Maximum (32767) */
    0x75, 0x10,             /*   Report Size (16) */
    0x95, 0x01,             /*   Report Count (1) */
    0x55, 0x0D,             /*   Unit Exponent (-3 = 0.001 G) */
    0xB1, 0x02,             /*   Feature (Data, Var, Abs) */

    0x0A, 0x52, 0x24,       /*   Usage (Data Field: Acceleration | Max) */
    0x16, 0x01, 0x80,       /*   Logical Minimum (-32767) */
    0x26, 0xFF, 0x7F,       /*   Logical Maximum (32767) */
    0x75, 0x10,             /*   Report Size (16) */
    0x95, 0x01,             /*   Report Count (1) */
    0x55, 0x0D,             /*   Unit Exponent (-3) */
    0xB1, 0x02,             /*   Feature (Data, Var, Abs) */

    0x0A, 0x52, 0x34,       /*   Usage (Data Field: Acceleration | Min) */
    0x16, 0x01, 0x80,       /*   Logical Minimum (-32767) */
    0x26, 0xFF, 0x7F,       /*   Logical Maximum (32767) */
    0x75, 0x10,             /*   Report Size (16) */
    0x95, 0x01,             /*   Report Count (1) */
    0x55, 0x0D,             /*   Unit Exponent (-3) */
    0xB1, 0x02,             /*   Feature (Data, Var, Abs) */

    /* ---- Input Report ---- */
    0x0A, 0x01, 0x02,       /*   Usage (Event: Sensor State) */
    0x15, 0x00,             /*   Logical Minimum (0) */
    0x25, 0x06,             /*   Logical Maximum (6) */
    0x75, 0x08,             /*   Report Size (8) */
    0x95, 0x01,             /*   Report Count (1) */
    0xA1, 0x02,             /*   Collection (Logical) */
    0x0A, 0x00, 0x08,
    0x0A, 0x01, 0x08,
    0x0A, 0x02, 0x08,
    0x0A, 0x03, 0x08,
    0x0A, 0x04, 0x08,
    0x0A, 0x05, 0x08,
    0x0A, 0x06, 0x08,
    0x81, 0x00,             /*     Input (Data, Array, Abs) */
    0xC0,                   /*   End Collection */

    0x0A, 0x02, 0x02,       /*   Usage (Event: Sensor Event) */
    0x15, 0x00,             /*   Logical Minimum (0) */
    0x25, 0x05,             /*   Logical Maximum (5) */
    0x75, 0x08,             /*   Report Size (8) */
    0x95, 0x01,             /*   Report Count (1) */
    0xA1, 0x02,             /*   Collection (Logical) */
    0x0A, 0x10, 0x08,       /*     Unknown */
    0x0A, 0x11, 0x08,       /*     State Changed */
    0x0A, 0x12, 0x08,       /*     Property Changed */
    0x0A, 0x13, 0x08,       /*     Data Updated */
    0x0A, 0x14, 0x08,       /*     Poll Response */
    0x0A, 0x15, 0x08,       /*     Change Sensitivity */
    0x81, 0x00,             /*     Input (Data, Array, Abs) */
    0xC0,                   /*   End Collection */

    0x0A, 0x53, 0x04,       /*   Usage (Data Field: Acceleration Axis X) */
    0x0A, 0x54, 0x04,       /*   Usage (Data Field: Acceleration Axis Y) */
    0x0A, 0x55, 0x04,       /*   Usage (Data Field: Acceleration Axis Z) */
    0x16, 0x01, 0x80,       /*   Logical Minimum (-32767) */
    0x26, 0xFF, 0x7F,       /*   Logical Maximum (32767) */
    0x75, 0x10,             /*   Report Size (16) */
    0x95, 0x03,             /*   Report Count (3) */
    0x55, 0x0D,             /*   Unit Exponent (-3 = 0.001 G) */
    0x81, 0x02,             /*   Input (Data, Var, Abs) */

    0xC0                    /* End Collection */
};

#pragma pack(push, 1)
typedef struct {
    UCHAR  ReportId;
    UCHAR  ConnType;
    UCHAR  ReportingState;
    UCHAR  PowerState;
    UCHAR  SensorState;
    ULONG  ReportIntervalMs;
    USHORT SensitivityMg;
    SHORT  MaxMg;
    SHORT  MinMg;
} ACCEL_FEATURE_REPORT;

typedef struct {
    UCHAR  ReportId;
    UCHAR  SensorState;
    UCHAR  SensorEvent;
    SHORT  AxMg;
    SHORT  AyMg;
    SHORT  AzMg;
} ACCEL_INPUT_REPORT;
#pragma pack(pop)

typedef struct {
    VHFHANDLE Vhf;
    WDFTIMER  Timer;
    UCHAR     ReportingState;
    UCHAR     PowerState;
    ULONG     ReportIntervalMs;
    USHORT    SensitivityMg;
    SHORT     LastX, LastY, LastZ;
    ULONG     LastSeq;
    BOOLEAN   HasSample;
    BOOLEAN   Stopping;
} ACCEL_CTX;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(ACCEL_CTX, AccelCtx)

DRIVER_INITIALIZE DriverEntry;
static EVT_WDF_DRIVER_DEVICE_ADD AccelAdd;
static EVT_WDF_OBJECT_CONTEXT_CLEANUP AccelCleanup;
static EVT_WDF_DEVICE_SELF_MANAGED_IO_INIT AccelIoInit;
static EVT_WDF_DEVICE_SELF_MANAGED_IO_SUSPEND AccelIoSuspend;
static EVT_WDF_TIMER AccelPollTimer;
static EVT_VHF_ASYNC_OPERATION AccelGetFeature;
static EVT_VHF_ASYNC_OPERATION AccelSetFeature;
static EVT_VHF_ASYNC_OPERATION AccelGetInput;

static SHORT ClampI16(int32_t v) {
    if (v > 32767) return 32767;
    if (v < -32767) return -32767;
    return (SHORT)v;
}

static VOID PollKeeperAccel(ACCEL_CTX *c) {
    UNICODE_STRING ckName;
    PFILE_OBJECT fileObj = NULL;
    PDEVICE_OBJECT devObj = NULL;
    UCHAR *buf = NULL;
    KEVENT ev;
    IO_STATUS_BLOCK iosb;
    PIRP irp;
    NTSTATUS st;

    RtlInitUnicodeString(&ckName, L"\\Device\\OpenChargerKeeper");
    st = IoGetDeviceObjectPointer(&ckName, FILE_READ_DATA, &fileObj, &devObj);
    if (!NT_SUCCESS(st) || !devObj) return;

    buf = (UCHAR *)ExAllocatePool2(POOL_FLAG_NON_PAGED, 512, ACCEL_POOL_TAG);
    if (!buf) { ObDereferenceObject(fileObj); return; }

    KeInitializeEvent(&ev, NotificationEvent, FALSE);
    RtlZeroMemory(&iosb, sizeof(iosb));
    irp = IoBuildDeviceIoControlRequest(IOCTL_CK_ACCEL, devObj, NULL, 0, buf, 512, FALSE, &ev, &iosb);
    if (irp) {
        st = IoCallDriver(devObj, irp);
        if (st == STATUS_PENDING) {
            KeWaitForSingleObject(&ev, Executive, KernelMode, FALSE, NULL);
            st = iosb.Status;
        }
    } else {
        st = STATUS_INSUFFICIENT_RESOURCES;
    }
    ObDereferenceObject(fileObj);

    if (NT_SUCCESS(st)) {
        const CK_ACCEL_HDR *h = (const CK_ACCEL_HDR *)buf;
        if (h->Magic == CK_MAGIC && h->AccelValid && h->AccelSeq != c->LastSeq) {
            c->LastSeq = h->AccelSeq;
            c->LastX = ClampI16(h->AxMilliG);
            c->LastY = ClampI16(h->AyMilliG);
            c->LastZ = ClampI16(h->AzMilliG);
            c->HasSample = TRUE;

            if (c->Vhf && c->ReportingState != 0) {
                ACCEL_INPUT_REPORT rep;
                rep.ReportId    = ACCEL_REPORT_ID;
                rep.SensorState = 1; /* Ready */
                rep.SensorEvent = 3; /* Data Updated */
                rep.AxMg = c->LastX;
                rep.AyMg = c->LastY;
                rep.AzMg = c->LastZ;
                HID_XFER_PACKET pkt;
                RtlZeroMemory(&pkt, sizeof(pkt));
                pkt.reportId = ACCEL_REPORT_ID;
                pkt.reportBuffer = (PUCHAR)&rep;
                pkt.reportBufferLen = sizeof(rep);
                VhfReadReportSubmit(c->Vhf, &pkt);
            }
        }
    }

    ExFreePoolWithTag(buf, ACCEL_POOL_TAG);
}

static VOID AccelPollTimer(WDFTIMER Timer) {
    WDFDEVICE dev = (WDFDEVICE)WdfTimerGetParentObject(Timer);
    ACCEL_CTX *c = AccelCtx(dev);
    PollKeeperAccel(c);
    if (c->Timer && !c->Stopping) {
        ULONG ms = (c->ReportIntervalMs >= 20 && c->ReportIntervalMs <= 5000) ? c->ReportIntervalMs : ACCEL_POLL_MS;
        WdfTimerStart(Timer, WDF_REL_TIMEOUT_IN_MS(ms));
    }
}

static VOID AccelGetFeature(PVOID Ctx, VHFOPERATIONHANDLE Op, PVOID OpCtx, PHID_XFER_PACKET Pkt) {
    UNREFERENCED_PARAMETER(OpCtx);
    ACCEL_CTX *c = (ACCEL_CTX *)Ctx;
    NTSTATUS st = STATUS_BUFFER_TOO_SMALL;
    if (Pkt && Pkt->reportId == ACCEL_REPORT_ID && Pkt->reportBufferLen >= sizeof(ACCEL_FEATURE_REPORT)) {
        ACCEL_FEATURE_REPORT *f = (ACCEL_FEATURE_REPORT *)Pkt->reportBuffer;
        f->ReportId         = ACCEL_REPORT_ID;
        f->ConnType         = 0; /* PC Integrated */
        f->ReportingState   = c->ReportingState;
        f->PowerState       = c->PowerState;
        f->SensorState      = 1; /* Ready */
        f->ReportIntervalMs = c->ReportIntervalMs;
        f->SensitivityMg    = c->SensitivityMg;
        f->MaxMg            = 4000;
        f->MinMg            = -4000;
        Pkt->reportBufferLen = sizeof(ACCEL_FEATURE_REPORT);
        st = STATUS_SUCCESS;
    }
    VhfAsyncOperationComplete(Op, st);
}

static VOID AccelSetFeature(PVOID Ctx, VHFOPERATIONHANDLE Op, PVOID OpCtx, PHID_XFER_PACKET Pkt) {
    UNREFERENCED_PARAMETER(OpCtx);
    ACCEL_CTX *c = (ACCEL_CTX *)Ctx;
    NTSTATUS st = STATUS_INVALID_PARAMETER;
    if (Pkt && Pkt->reportId == ACCEL_REPORT_ID && Pkt->reportBufferLen >= sizeof(ACCEL_FEATURE_REPORT)) {
        const ACCEL_FEATURE_REPORT *f = (const ACCEL_FEATURE_REPORT *)Pkt->reportBuffer;
        c->ReportingState   = f->ReportingState;
        c->PowerState       = f->PowerState;
        c->ReportIntervalMs = (f->ReportIntervalMs >= 20 && f->ReportIntervalMs <= 5000) ? f->ReportIntervalMs : ACCEL_POLL_MS;
        c->SensitivityMg    = f->SensitivityMg;
        st = STATUS_SUCCESS;
    }
    VhfAsyncOperationComplete(Op, st);
}

static VOID AccelGetInput(PVOID Ctx, VHFOPERATIONHANDLE Op, PVOID OpCtx, PHID_XFER_PACKET Pkt) {
    UNREFERENCED_PARAMETER(OpCtx);
    ACCEL_CTX *c = (ACCEL_CTX *)Ctx;
    NTSTATUS st = STATUS_BUFFER_TOO_SMALL;
    if (Pkt && Pkt->reportId == ACCEL_REPORT_ID && Pkt->reportBufferLen >= sizeof(ACCEL_INPUT_REPORT)) {
        ACCEL_INPUT_REPORT *r = (ACCEL_INPUT_REPORT *)Pkt->reportBuffer;
        r->ReportId    = ACCEL_REPORT_ID;
        r->SensorState = 1; /* Ready */
        r->SensorEvent = 4; /* Poll Response */
        r->AxMg = c->HasSample ? c->LastX : 0;
        r->AyMg = c->HasSample ? c->LastY : 0;
        r->AzMg = c->HasSample ? c->LastZ : -1000; /* default 1G portrait/flat until SSC streams */
        Pkt->reportBufferLen = sizeof(ACCEL_INPUT_REPORT);
        st = STATUS_SUCCESS;
    }
    VhfAsyncOperationComplete(Op, st);
}

static NTSTATUS AccelIoInit(WDFDEVICE Dev) {
    ACCEL_CTX *c = AccelCtx(Dev);
    c->Stopping = FALSE;
    NTSTATUS st = VhfStart(c->Vhf);
    if (NT_SUCCESS(st)) {
        WdfTimerStart(c->Timer, WDF_REL_TIMEOUT_IN_MS(ACCEL_POLL_MS));
    }
    return st;
}

static NTSTATUS AccelIoSuspend(WDFDEVICE Dev) {
    ACCEL_CTX *c = AccelCtx(Dev);
    c->Stopping = TRUE;
    if (c->Timer) WdfTimerStop(c->Timer, TRUE);
    return STATUS_SUCCESS;
}

static VOID AccelCleanup(WDFOBJECT Obj) {
    ACCEL_CTX *c = AccelCtx((WDFDEVICE)Obj);
    c->Stopping = TRUE;
    if (c->Timer) { WdfTimerStop(c->Timer, TRUE); c->Timer = NULL; }
    if (c->Vhf)   { VhfDelete(c->Vhf, TRUE); c->Vhf = NULL; }
}

static NTSTATUS AccelAdd(WDFDRIVER Drv, PWDFDEVICE_INIT Init) {
    UNREFERENCED_PARAMETER(Drv);
    WDF_PNPPOWER_EVENT_CALLBACKS pnp;
    WDF_OBJECT_ATTRIBUTES attr;
    WDF_TIMER_CONFIG tcfg;
    VHF_CONFIG vcfg;
    WDFDEVICE dev;
    NTSTATUS st;

    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnp);
    pnp.EvtDeviceSelfManagedIoInit    = AccelIoInit;
    pnp.EvtDeviceSelfManagedIoSuspend = AccelIoSuspend;
    WdfDeviceInitSetPnpPowerEventCallbacks(Init, &pnp);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attr, ACCEL_CTX);
    attr.EvtCleanupCallback = AccelCleanup;
    attr.ExecutionLevel = WdfExecutionLevelPassive;
    st = WdfDeviceCreate(&Init, &attr, &dev);
    if (!NT_SUCCESS(st)) return st;

    ACCEL_CTX *c = AccelCtx(dev);
    RtlZeroMemory(c, sizeof(*c));
    c->ReportingState   = 1; /* All Events */
    c->PowerState       = 1; /* D0 Full Power */
    c->ReportIntervalMs = ACCEL_POLL_MS;
    c->SensitivityMg    = 20;

    WDF_TIMER_CONFIG_INIT(&tcfg, AccelPollTimer);
    WDF_OBJECT_ATTRIBUTES_INIT(&attr);
    attr.ParentObject = dev;
    attr.ExecutionLevel = WdfExecutionLevelPassive;
    st = WdfTimerCreate(&tcfg, &attr, &c->Timer);
    if (!NT_SUCCESS(st)) return st;

    VHF_CONFIG_INIT(&vcfg, WdfDeviceWdmGetDeviceObject(dev),
                    (USHORT)sizeof(g_AccelHidDescriptor), (PUCHAR)g_AccelHidDescriptor);
    vcfg.VendorID  = 0x2A70; /* OnePlus */
    vcfg.ProductID = 0x8550;
    vcfg.VersionNumber = 0x0001;
    vcfg.VhfClientContext = c;
    vcfg.EvtVhfAsyncOperationGetFeature     = AccelGetFeature;
    vcfg.EvtVhfAsyncOperationSetFeature     = AccelSetFeature;
    vcfg.EvtVhfAsyncOperationGetInputReport = AccelGetInput;

    st = VhfCreate(&vcfg, &c->Vhf);
    return st;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    WDF_DRIVER_CONFIG cfg;
    WDF_DRIVER_CONFIG_INIT(&cfg, AccelAdd);
    return WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &cfg, WDF_NO_HANDLE);
}
