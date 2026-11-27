/* SPDX-License-Identifier: MIT
 * OpenChargerKeeper: Always-on WinPE + Windows 11 charging watchdog for OnePlus Open (SM8550).
 * Reuses proven G155 ADSP GLINK (0x81e9f000 + 0x408000) and G104 dual ZY0602 I2C gauges.
 * Zero hardware overlap with G379 touch, G746 clock parent, abi7 Wi-Fi, or GPU drivers.
 */
#include <ntifs.h>
#include <wdf.h>
#include "glink_core.h"
#include "keeper_policy.h"
#include "g104_core.h"
#include "slots.h"
#include "smem-select.h"
#include "protocol.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD CkUnload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL CkControl;
EVT_WDF_DEVICE_FILE_CREATE CkFileCreate;
EVT_WDF_TIMER CkTimer;

/* 12 fixed MMIO pages for G104 dual ZY0602 I2C gauge reader */
typedef struct { ULONGLONG Phys; ULONG Write; } CK_MMIO_SPEC;
static const CK_MMIO_SPEC GaugePages[12] = {
    { 0x00880000ULL, 1u }, /* QUP I2C 0 (RW) */
    { 0x0098c000ULL, 1u }, /* QUP I2C 1 (RW) */
    { 0x008c0000ULL, 0u }, /* QUP wrapper 0 (RO) */
    { 0x009c0000ULL, 0u }, /* QUP wrapper 1 (RO) */
    { 0x00117000ULL, 0u }, /* GCC I2C1 clock (RO) */
    { 0x0011e000ULL, 0u }, /* GCC I2C0 clock (RO) */
    { 0x00123000ULL, 0u }, /* GCC CBCR (RO) */
    { 0x00152000ULL, 0u }, /* GCC vote (RO) */
    { 0x0f100000ULL, 0u }, /* TLMM GPIO 0 (RO) */
    { 0x0f101000ULL, 0u }, /* TLMM GPIO 1 (RO) */
    { 0x0f116000ULL, 0u }, /* TLMM GPIO 22 (RO) */
    { 0x0f117000ULL, 0u }  /* TLMM GPIO 23 (RO) */
};

typedef struct {
    CK_GL_STATE  Glink;
    CK_POLICY    Policy;
    G104_RESULT  GaugeScratch;
    PVOID        Part;
    PVOID        Irq;
    PVOID        GaugeMap[12];
    PVOID        FrpcBuf;
    uint64_t     FrpcPhys;
    uint32_t     FrpcBufSize;
    uint8_t     *SmmuPt;
    uint64_t     SmmuPtPhys;
    volatile ULONG *Descriptor;
    volatile ULONG *Doorbell;
    volatile UCHAR *Tx;
    volatile UCHAR *Rx;
    uint32_t     KernelBuild;
    uint32_t     Processors;
    uint32_t     Admitted;
    uint32_t     AdmissionCode;
    uint32_t     Running;
    uint32_t     Stopped;
    uint32_t     GaugeReadsOk;
    uint32_t     GaugeReadsFail;
    uint64_t     TimerTicks;
    uint64_t     NextSampleUs;
} CK_OWNER;

static CK_OWNER *Owner;
static WDFTIMER  Timer;
static WDFDEVICE Device;

static uint64_t NowUs(void){ return KeQueryInterruptTime() / 10ULL; }

static int ReservedRamOk(void){
    const ULONGLONG bases[]   = { 0x400000ULL, 0x81a00000ULL, 0x81d00000ULL };
    const ULONGLONG lengths[] = { 0x100000ULL, 0x300000ULL,   0x200000ULL };
    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRangesEx2(NULL, 0);
    int valid = 0;
    if(!ranges) return 0;
    for(ULONG i=0;i<512;i++){
        ULONGLONG start = (ULONGLONG)ranges[i].BaseAddress.QuadPart;
        ULONGLONG n     = (ULONGLONG)ranges[i].NumberOfBytes.QuadPart;
        if(!n){ valid = 1; break; }
        if(n > MAXULONGLONG - start) break;
        for(ULONG j=0;j<3;j++){
            if(start < bases[j]+lengths[j] && bases[j] < start+n) goto done;
        }
    }
done:
    ExFreePool(ranges);
    return valid;
}

static PVOID MapPhys(ULONGLONG phys, SIZE_T bytes, ULONG prot){
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)phys;
    return MmMapIoSpaceEx(pa, bytes, prot);
}

static void UnmapAll(void){
    if(!Owner) return;
    if(Owner->Irq){ MmUnmapIoSpace(Owner->Irq, 0x1000); Owner->Irq = NULL; }
    if(Owner->Part){ MmUnmapIoSpace(Owner->Part, 0x60000); Owner->Part = NULL; }
    for(ULONG i=0;i<12;i++){
        if(Owner->GaugeMap[i]){ MmUnmapIoSpace(Owner->GaugeMap[i], 0x1000); Owner->GaugeMap[i] = NULL; }
    }
    Owner->Descriptor = Owner->Doorbell = NULL;
    Owner->Tx = Owner->Rx = NULL;
}

/* ---- GLINK IO callbacks ---- */
static void GlBarrier(void *c){ UNREFERENCED_PARAMETER(c); KeMemoryBarrier(); }
static int GlReadDesc(void *c, uint32_t d[8]){
    CK_OWNER *o = (CK_OWNER*)c;
    if(!o->Descriptor || o->Stopped) return 0;
    KeMemoryBarrier();
    for(ULONG i=0;i<8;i++) d[i] = o->Descriptor[i];
    KeMemoryBarrier();
    return 1;
}
static int GlReadRx(void *c, uint32_t at, uint8_t *b, uint32_t n){
    CK_OWNER *o = (CK_OWNER*)c;
    if(!o->Rx || o->Stopped || at >= CK_FIFO_BYTES || (at & 7u) || !n || n > CK_FRAME_BYTES) return 0;
    KeMemoryBarrier();
    for(uint32_t i=0;i<n;i++) b[i] = o->Rx[(at + i) & CK_FIFO_MASK];
    KeMemoryBarrier();
    return 1;
}
static int GlWriteTx(void *c, uint32_t at, const uint8_t *b, uint32_t n){
    CK_OWNER *o = (CK_OWNER*)c;
    if(!o->Tx || o->Stopped || at >= CK_FIFO_BYTES || (at & 7u) || !n || n > CK_FRAME_BYTES) return 0;
    for(uint32_t i=0;i<n;i++) o->Tx[(at + i) & CK_FIFO_MASK] = b[i];
    KeMemoryBarrier();
    return 1;
}
static int GlPublish(void *c, uint32_t word, uint32_t value){
    CK_OWNER *o = (CK_OWNER*)c;
    if(!o->Descriptor || o->Stopped || (word != 1u && word != 2u) || value >= CK_FIFO_BYTES || (value & 7u)) return 0;
    KeMemoryBarrier();
    o->Descriptor[word] = value;
    KeMemoryBarrier();
    return o->Descriptor[word] == value;
}
static int GlKick(void *c){
    CK_OWNER *o = (CK_OWNER*)c;
    if(!o->Doorbell || o->Stopped) return 0;
    KeMemoryBarrier();
    *o->Doorbell = 0x30000u; /* IPCC AP->ADSP GLINK doorbell */
    KeMemoryBarrier();
    return 1;
}

/* ---- G104 Gauge I2C IO callbacks ---- */
static volatile ULONG *GaugePtr(CK_OWNER *o, uint32_t addr, ULONG want_write){
    if(addr & 3u) return NULL;
    ULONGLONG page = (ULONGLONG)(addr & ~0xFFFu);
    ULONG off = addr & 0xFFFu;
    for(ULONG i=0;i<12;i++){
        if(GaugePages[i].Phys == page){
            if(want_write && !GaugePages[i].Write) return NULL;
            if(!o->GaugeMap[i]) return NULL;
            return (volatile ULONG*)((UCHAR*)o->GaugeMap[i] + off);
        }
    }
    return NULL;
}
static int G104Read(void *c, uint32_t addr, uint32_t *v){
    volatile ULONG *p = GaugePtr((CK_OWNER*)c, addr, 0u);
    if(!p || !v) return 0;
    KeMemoryBarrier(); *v = *p; KeMemoryBarrier();
    return 1;
}
static int G104Write(void *c, uint32_t addr, uint32_t v){
    volatile ULONG *p = GaugePtr((CK_OWNER*)c, addr, 1u);
    if(!p) return 0;
    KeMemoryBarrier(); *p = v; KeMemoryBarrier();
    return 1;
}
static int G104Avail(void *c){ CK_OWNER *o=(CK_OWNER*)c; return (o && o->GaugeMap[0]) ? 1 : 0; }
static uint64_t G104Now(void *c){ UNREFERENCED_PARAMETER(c); return NowUs(); }
static void G104Delay(void *c, uint32_t us){ UNREFERENCED_PARAMETER(c); if(us > 1000u) us = 1000u; KeStallExecutionProcessor(us); }

static int ReadPhysicalGauges(CK_OWNER *o, CK_TELEMETRY *t){
    G104_IO gio = { o, G104Read, G104Write, G104Avail, G104Now, G104Delay };
    RtlZeroMemory(&o->GaugeScratch, sizeof(o->GaugeScratch));
    G104Identify(&gio, &o->GaugeScratch);
    if(o->GaugeScratch.Code != G104_OK || o->GaugeScratch.QueryMask != 0xfffffu){
        o->GaugeReadsFail++;
        t->Valid = 0;
        return 0;
    }
    for(unsigned i=0;i<2;i++){
        const uint32_t *w = o->GaugeScratch.Values[i];
        /* w[0] is the control-status word: bits 13-14 (0x6000) are fixed, the low bits are live status
         * flags (seen 0x6002 and 0x6000), so only the fixed part identifies the gauge. */
        if((w[0] & 0xFFF0u) != 0x6000u || w[1] != 0x0602u || w[2] != 0x0200u || !w[7] || w[6] > w[7] || w[9] > 100u){
            o->GaugeReadsFail++;
            t->Valid = 0;
            return 0;
        }
        t->TempDeciK[i] = w[3];
        t->VoltageMv[i] = w[4];
        t->Flags[i]     = w[5];
        t->RemMah[i]    = w[6];
        t->FullMah[i]   = w[7];
        t->CurrentMa[i] = (int32_t)(int16_t)(w[8] & 0xFFFFu);
        t->SocPct[i]    = w[9];
    }
    o->GaugeReadsOk++;
    t->Valid = 1u;
    return 1;
}


static int ReadAdspFallback(const CK_OWNER *o, CK_TELEMETRY *t){
    const CL_BATTERY *b = &o->Glink.LastBattery;
    uint32_t mv = 0, temp_dk = 0, soc = 0;
    if(b->VoltageNow >= 2800000u && b->VoltageNow <= 4600000u) mv = b->VoltageNow / 1000u;
    else if(b->OpenCircuitVoltage >= 2800000u && b->OpenCircuitVoltage <= 4600000u) mv = b->OpenCircuitVoltage / 1000u;
    else if(b->Voltage >= 2800u && b->Voltage <= 4600u) mv = b->Voltage;
    if(!mv) return 0;

    /* ADSP TemperatureProperty (0x30/12) is in 0.01 degC (e.g. 2500 = 25.00 C). */
    if(b->TemperatureProperty >= 1000u && b->TemperatureProperty <= 6000u) temp_dk = 2731u + (b->TemperatureProperty / 10u);
    else if(b->TemperatureProperty >= 100u && b->TemperatureProperty <= 600u) temp_dk = 2731u + b->TemperatureProperty;
    else if(b->TemperatureRaw >= 2500u && b->TemperatureRaw <= 3500u) temp_dk = b->TemperatureRaw;
    else if(b->TemperatureRaw >= 100u && b->TemperatureRaw <= 600u) temp_dk = 2731u + b->TemperatureRaw;
    else return 0;

    if(b->CapacityProperty <= 100u) soc = b->CapacityProperty;
    else if(b->CapacityProperty <= 10000u) soc = b->CapacityProperty / 100u;
    else soc = 50u;

    for(unsigned i = 0; i < 2; i++){
        t->VoltageMv[i] = mv;
        t->TempDeciK[i] = temp_dk;
        t->SocPct[i]    = soc;
        t->Flags[i]     = 0xAD5Bu;
        t->CurrentMa[i] = (int32_t)b->CurrentNow / 1000;
        t->RemMah[i]    = b->RemainingCapacity;
        t->FullMah[i]   = 0;
    }
    t->Valid = 1u;
    return 1;
}

static void DispatchPolicyAction(CK_OWNER *o, uint32_t act, uint64_t now){
    if(act == CK_ACT_SET_FV)       CkGlRequest(&o->Glink, CK_OP_SET_FV, now);
    else if(act == CK_ACT_DISABLE) CkGlRequest(&o->Glink, CK_OP_DISABLE, now);
    else if(act == CK_ACT_ENABLE)  CkGlRequest(&o->Glink, CK_OP_ENABLE, now);
}

static int Admit(void){
    RTL_OSVERSIONINFOW ver = {0};
    PVOID toc = NULL;
    G135_PART parts[2];
    uint32_t count = 0;
    G158_SLOTS s1, s2;

    Owner->Processors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    ver.dwOSVersionInfoSize = sizeof(ver);
    if(NT_SUCCESS(RtlGetVersion(&ver))) Owner->KernelBuild = ver.dwBuildNumber;

    if(KeGetCurrentIrql() != PASSIVE_LEVEL || Owner->Processors != 8u || Owner->KernelBuild < 22000u){
        Owner->AdmissionCode = 1001u; goto fail;
    }
    for(ULONG i=0;i<12;i++){
        ULONG prot = GaugePages[i].Write ? (PAGE_READWRITE | PAGE_NOCACHE) : (PAGE_READONLY | PAGE_NOCACHE);
        Owner->GaugeMap[i] = MapPhys(GaugePages[i].Phys, 0x1000, prot);
        if(!Owner->GaugeMap[i]){ Owner->AdmissionCode = 1009u + i; goto fail; }
    }
    if(!ReservedRamOk()){ Owner->AdmissionCode = 1002u; goto fail; }

    toc = MapPhys(0x81eff000ULL, 0x1000, PAGE_READONLY | PAGE_NOCACHE);
    if(!toc){ Owner->AdmissionCode = 1003u; goto fail; }
    if(G135Select(toc, 4096u, parts, &count) || count != 2u){ Owner->AdmissionCode = 1004u; goto fail; }
    ULONG sel = 2u;
    for(ULONG i=0;i<count;i++){ if(parts[i].Host0 == 0u && parts[i].Host1 == 2u) sel = i; }
    if(sel == 2u || parts[sel].Offset != 0x19f000u || parts[sel].Bytes != 0x60000u){
        Owner->AdmissionCode = 1005u; goto fail;
    }
    MmUnmapIoSpace(toc, 0x1000); toc = NULL;

    Owner->Part = MapPhys(0x81e9f000ULL, 0x60000, PAGE_READWRITE | PAGE_NOCACHE);
    if(!Owner->Part){ Owner->AdmissionCode = 1006u; goto fail; }
    if(!G135PartHeader(Owner->Part, parts + sel) || !G158FindSlots(Owner->Part, 0x60000u, &s1)){
        Owner->AdmissionCode = 1007u; goto fail;
    }
    KeMemoryBarrier();
    if(!G135PartHeader(Owner->Part, parts + sel) || !G158FindSlots(Owner->Part, 0x60000u, &s2) ||
       RtlCompareMemory(&s1, &s2, sizeof(s1)) != sizeof(s1)){
        Owner->AdmissionCode = 1007u; goto fail;
    }
    Owner->Descriptor = (volatile ULONG*)((UCHAR*)Owner->Part + s1.Descriptor);
    Owner->Tx = (volatile UCHAR*)Owner->Part + s1.Tx;
    Owner->Rx = (volatile UCHAR*)Owner->Part + s1.Rx;

    Owner->Irq = MapPhys(0x00408000ULL, 0x1000, PAGE_READWRITE | PAGE_NOCACHE);
    if(!Owner->Irq){ Owner->AdmissionCode = 1008u; goto fail; }
    Owner->Doorbell = (volatile ULONG*)((UCHAR*)Owner->Irq + 0x0c);

    Owner->Admitted = 1u;
    Owner->Running = 1u;
    Owner->AdmissionCode = 0u;
    return 1;
fail:
    if(toc) MmUnmapIoSpace(toc, 0x1000);
    if(Owner->Irq){ MmUnmapIoSpace((PVOID)Owner->Irq, 0x1000); Owner->Irq = NULL; }
    if(Owner->Part){ MmUnmapIoSpace((PVOID)Owner->Part, 0x60000); Owner->Part = NULL; }
    if(Owner->GaugeMap[0]){
        CK_TELEMETRY t = {0};
        ReadPhysicalGauges(Owner, &t);
        if(t.Valid) Owner->Policy.LastGood = t;
    }
    Owner->Stopped = 1u;
    return 0;
}

static void Pump(void){
    CK_GL_IO io = { GlReadDesc, GlReadRx, GlWriteTx, GlPublish, GlBarrier, GlKick, Owner };
    uint64_t now = NowUs();
    if(!Owner->Running || Owner->Stopped) return;

    uint32_t prev_active = Owner->Glink.OpActive;
    for(ULONG n=0;n<16;n++){
        int r = CkGlPoll(&Owner->Glink, &io, NowUs());
        if(r == CK_GL_POLL_CLOSED || r == CK_GL_POLL_FAULT){
            Owner->Running = 0; Owner->Stopped = 1;
            return;
        }
        if(r == CK_GL_POLL_IDLE) break;
    }

    now = NowUs();
    if(prev_active && !Owner->Glink.OpActive){
        uint32_t op = Owner->Glink.LastCompletedOp;
        uint32_t ok = Owner->Glink.LastOpOk;
        if(op == CK_OP_SAMPLE){
            CK_TELEMETRY t = {0};
            if(ok){
                t.UsbOnline = Owner->Glink.LastBattery.UsbOnline;
                t.UsbType   = Owner->Glink.LastBattery.UsbType;
                if(!ReadPhysicalGauges(Owner, &t)){
                    ReadAdspFallback(Owner, &t);
                }
            }
            uint32_t act = CkPolicyOnSample(&Owner->Policy, &t, now);
            DispatchPolicyAction(Owner, act, now);
            Owner->NextSampleUs = now + CK_POLL_INTERVAL_US;
        } else if(op == CK_OP_SET_FV || op == CK_OP_DISABLE || op == CK_OP_ENABLE){
            uint32_t act = CkPolicyOnOpDone(&Owner->Policy, op, ok, now);
            DispatchPolicyAction(Owner, act, now);
        }
    }

    if(Owner->Glink.Phase == CK_GL_READY && !Owner->Glink.OpActive){
        uint32_t act = CkPolicyTick(&Owner->Policy, now);
        if(act != CK_ACT_NONE){
            DispatchPolicyAction(Owner, act, now);
        } else if(now >= Owner->NextSampleUs){
            CkGlRequest(&Owner->Glink, CK_OP_SAMPLE, now);
        }
    }

    if(Owner->Running && !Owner->Stopped){
        LONG ms = (Owner->Glink.OpActive || Owner->Glink.Phase != CK_GL_READY ||
                   Owner->Glink.Ipc.TxHead != Owner->Glink.Ipc.TxTail ||
                   Owner->Glink.Aud.TxHead != Owner->Glink.Aud.TxTail ||
                   Owner->Glink.Frpc.TxPending) ? 10 :
                  (Owner->Policy.State == CK_ST_GAP_WAIT || Owner->Glink.Ipc.OpenAcked) ? 50 : 500;
        WdfTimerStart(Timer, WDF_REL_TIMEOUT_IN_MS(ms));
    }
}

VOID CkTimer(WDFTIMER timer){
    UNREFERENCED_PARAMETER(timer);
    if(!Owner) return;
    Owner->TimerTicks++;
    if(!Owner->Admitted && !Owner->Stopped){
        if(!Admit()) return;
    }
    Pump();
}

VOID CkControl(WDFQUEUE queue, WDFREQUEST request, size_t outBytes, size_t inBytes, ULONG code){
    UNREFERENCED_PARAMETER(queue);
    UNREFERENCED_PARAMETER(inBytes);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;

    if(code == IOCTL_CK_PAUSE){
        if(Owner){
            CkPolicySetPaused(&Owner->Policy, 1u);
            if(Owner->Glink.Phase == CK_GL_READY && !Owner->Glink.OpActive){
                CkGlRequest(&Owner->Glink, CK_OP_DISABLE, NowUs());
                Pump();
            }
        }
    } else if(code == IOCTL_CK_RESUME){
        if(Owner){
            CkPolicySetPaused(&Owner->Policy, 0u);
            Owner->NextSampleUs = 0;
            Pump();
        }
    } else if(code == IOCTL_CK_ACCEL){
        if(outBytes >= sizeof(CK_ACCEL_SNAPSHOT)){
            CK_ACCEL_SNAPSHOT *aout = NULL;
            status = WdfRequestRetrieveOutputBuffer(request, sizeof(*aout), (PVOID*)&aout, NULL);
            if(NT_SUCCESS(status) && aout && Owner){
                const CK_IPC_STATE *ipc = &Owner->Glink.Ipc;
                RtlZeroMemory(aout, sizeof(*aout));
                aout->Size          = sizeof(*aout);
                aout->Version       = CK_ABI_VER;
                aout->Magic         = CK_MAGIC;
                aout->OpenAcked     = ipc->OpenAcked;
                aout->RemoteOpen    = ipc->RemoteOpen;
                aout->HelloSent     = ipc->HelloSent;
                aout->SnsFound      = ipc->SnsFound;
                aout->SnsNode       = ipc->SnsNode;
                aout->SnsPort       = ipc->SnsPort;
                aout->SuidSent      = ipc->SuidSent;
                aout->SuidFound     = ipc->SuidFound;
                aout->AccelReqSent  = ipc->AccelReqSent;
                aout->AccelValid    = ipc->AccelValid;
                aout->AccelSeq      = ipc->AccelSeq;
                aout->AxMilliG      = ipc->AxMilliG;
                aout->AyMilliG      = ipc->AyMilliG;
                aout->AzMilliG      = ipc->AzMilliG;
                aout->TxPackets     = ipc->TxPackets;
                aout->RxPackets     = ipc->RxPackets;
                aout->IndPackets    = ipc->IndPackets;
                aout->LastIndMsgId  = ipc->LastIndMsgId;
                aout->ServicesCount = ipc->ServicesCount;
                aout->SuidLow       = ipc->SuidLow;
                aout->SuidHigh      = ipc->SuidHigh;
                RtlCopyMemory(aout->Services, ipc->Services, sizeof(aout->Services));
                info = sizeof(*aout);
            }
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        goto done;
    } else if(code == IOCTL_CK_QRTR_SEND){
        if(Owner && inBytes >= 32u && inBytes <= CK_IPC_TXQ_MAX){
            PVOID inBuf = NULL;
            status = WdfRequestRetrieveInputBuffer(request, inBytes, &inBuf, NULL);
            if(NT_SUCCESS(status) && inBuf){
                if(CkIpcEnqueueRawTx(&Owner->Glink.Ipc, (const uint8_t*)inBuf, (uint32_t)inBytes)){
                    Pump();
                } else {
                    status = STATUS_DEVICE_BUSY;
                }
            }
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        goto done;
    } else if(code == IOCTL_CK_QRTR_RECV){
        if(Owner && outBytes >= 32u){
            PVOID outBuf = NULL;
            status = WdfRequestRetrieveOutputBuffer(request, outBytes, &outBuf, NULL);
            if(NT_SUCCESS(status) && outBuf){
                uint32_t got = 0;
                Pump();
                if(CkIpcPopRx(&Owner->Glink.Ipc, (uint8_t*)outBuf, (uint32_t)outBytes, &got)){
                    info = got;
                } else {
                    info = 0;
                }
            }
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        goto done;
    } else if(code == IOCTL_CK_AUDIO){
        if(Owner && outBytes >= sizeof(CK_AUDIO_SNAPSHOT)){
            CK_AUDIO_SNAPSHOT *aout = NULL;
            status = WdfRequestRetrieveOutputBuffer(request, sizeof(*aout), (PVOID*)&aout, NULL);
            if(NT_SUCCESS(status) && aout){
                const CK_AUD_STATE *aud = &Owner->Glink.Aud;
                RtlZeroMemory(aout, sizeof(*aout));
                aout->Size           = sizeof(*aout);
                aout->Version        = CK_ABI_VER;
                aout->Magic          = CK_MAGIC;
                aout->OpenAcked      = aud->OpenAcked;
                aout->RemoteOpen     = aud->RemoteOpen;
                aout->SpfQuerySent   = aud->SpfQuerySent;
                aout->SpfRspReceived = aud->SpfRspReceived;
                aout->SpfRspOpcode   = aud->SpfRspOpcode;
                aout->SpfState       = aud->SpfState;
                aout->SpfRspLen      = aud->SpfRspLen;
                RtlCopyMemory(aout->SpfRaw, aud->SpfRaw, sizeof(aout->SpfRaw));
                {
                    uint32_t maxSz = 0, cnt = 0;
                    for(uint32_t i=0;i<CK_AUD_INTENTS;i++){
                        if(Owner->Glink.Aud.Remote[i].State == 1){
                            cnt++;
                            if(Owner->Glink.Aud.Remote[i].Bytes > maxSz) maxSz = Owner->Glink.Aud.Remote[i].Bytes;
                        }
                    }
                    uint32_t *dbg = (uint32_t*)(aout->SpfRaw + 32);
                    dbg[0] = Owner->Glink.Aud.RemoteCid;
                    dbg[1] = Owner->Glink.Aud.IntentReqPending;
                    dbg[2] = cnt;
                    dbg[3] = maxSz;
                    dbg[4] = Owner->Glink.Aud.TxHead;
                    dbg[5] = Owner->Glink.Aud.TxTail;
                    dbg[6] = Owner->Glink.Aud.Remote[0].Bytes;
                    dbg[7] = Owner->Glink.Aud.Remote[1].Bytes;
                }
                aout->ChanCount      = Owner->Glink.ChanCount;
                RtlCopyMemory(aout->ChanNames, Owner->Glink.ChanNames, sizeof(aout->ChanNames));
                info = sizeof(*aout);
            }
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        goto done;
    } else if(code == IOCTL_CK_FRPC_INFO){
        if(Owner && outBytes >= sizeof(CK_FRPC_SNAPSHOT)){
            CK_FRPC_SNAPSHOT *fout = NULL;
            status = WdfRequestRetrieveOutputBuffer(request, sizeof(*fout), (PVOID*)&fout, NULL);
            if(NT_SUCCESS(status) && fout){
                Pump();
                const CK_FRPC_STATE *fr = &Owner->Glink.Frpc;
                RtlZeroMemory(fout, sizeof(*fout));
                fout->Size          = sizeof(*fout);
                fout->Version       = CK_ABI_VER;
                fout->Magic         = CK_MAGIC;
                fout->OpenAcked     = fr->OpenAcked;
                fout->RemoteOpen    = fr->RemoteOpen;
                fout->RspCount      = fr->RspCount;
                fout->RspLen        = fr->RspLen;
                fout->LastRspRetval = fr->LastRspRetval;
                fout->LastRspCtx    = fr->LastRspCtx;
                fout->BufPhys       = Owner->FrpcPhys;
                fout->BufSize       = Owner->FrpcBufSize;
                fout->TxPending     = fr->TxPending;
                RtlCopyMemory(fout->LastRspRaw, fr->LastRspRaw, sizeof(fout->LastRspRaw));
                info = sizeof(*fout);
            }
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        goto done;
    } else if(code == IOCTL_CK_FRPC_SEND){
        if(Owner && Owner->FrpcBuf && inBytes >= 40u){
            PVOID inBuf = NULL;
            status = WdfRequestRetrieveInputBuffer(request, inBytes, &inBuf, NULL);
            if(NT_SUCCESS(status) && inBuf){
                const uint8_t *ib = (const uint8_t*)inBuf;
                uint32_t payLen = (uint32_t)(inBytes - 40u);
                if(payLen > Owner->FrpcBufSize) payLen = Owner->FrpcBufSize;
                if(payLen > 0u){
                    RtlCopyMemory(Owner->FrpcBuf, ib + 40u, payLen);
                    KeMemoryBarrier();
                }
                if(!Owner->Glink.Frpc.TxPending){
                    RtlCopyMemory(Owner->Glink.Frpc.TxBuf, ib, 40u);
                    Owner->Glink.Frpc.TxLen = 40u;
                    Owner->Glink.Frpc.TxPending = 1u;
                    Pump();
                } else {
                    status = STATUS_DEVICE_BUSY;
                }
            }
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        goto done;
    } else if(code == IOCTL_CK_FRPC_READ){
        if(Owner && Owner->FrpcBuf && outBytes > 0u){
            PVOID outBuf = NULL;
            status = WdfRequestRetrieveOutputBuffer(request, outBytes, &outBuf, NULL);
            if(NT_SUCCESS(status) && outBuf){
                uint32_t cp = (outBytes < Owner->FrpcBufSize) ? (uint32_t)outBytes : Owner->FrpcBufSize;
                KeMemoryBarrier();
                RtlCopyMemory(outBuf, Owner->FrpcBuf, cp);
                info = cp;
            }
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        goto done;
    } else if(code == IOCTL_CK_GPR_SEND){
        if(Owner && inBytes >= 24u && inBytes <= CK_AUD_BUF){
            PVOID inBuf = NULL;
            status = WdfRequestRetrieveInputBuffer(request, inBytes, &inBuf, NULL);
            if(NT_SUCCESS(status) && inBuf){
                if(CkAudEnqueueTx(&Owner->Glink.Aud, (const uint8_t*)inBuf, (uint32_t)inBytes)){
                    Pump();
                } else {
                    status = STATUS_DEVICE_BUSY;
                }
            }
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        goto done;
    } else if(code == IOCTL_CK_GPR_RECV){
        if(Owner && outBytes >= 24u){
            PVOID outBuf = NULL;
            status = WdfRequestRetrieveOutputBuffer(request, outBytes, &outBuf, NULL);
            if(NT_SUCCESS(status) && outBuf){
                uint32_t got = 0;
                Pump();
                if(CkAudPopRx(&Owner->Glink.Aud, (uint8_t*)outBuf, (uint32_t)outBytes, &got)){
                    info = got;
                } else {
                    info = 0;
                }
            }
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        goto done;
    } else if(code == IOCTL_CK_SHM_WRITE){
        /* Input: [0..3] offset, [4..end] data -> writes into Owner->FrpcBuf (non-cached physical SHMEM) */
        if(Owner && Owner->FrpcBuf && inBytes >= 4u){
            PVOID inBuf = NULL;
            status = WdfRequestRetrieveInputBuffer(request, inBytes, &inBuf, NULL);
            if(NT_SUCCESS(status) && inBuf){
                const uint8_t *ib = (const uint8_t*)inBuf;
                uint32_t off = *(const uint32_t*)ib;
                uint32_t dlen = (uint32_t)(inBytes - 4u);
                if(off <= Owner->FrpcBufSize && dlen <= Owner->FrpcBufSize - off){
                    if(dlen > 0u){
                        RtlCopyMemory((uint8_t*)Owner->FrpcBuf + off, ib + 4u, dlen);
                        KeMemoryBarrier();
                    }
                    info = dlen;
                } else {
                    status = STATUS_INVALID_PARAMETER;
                }
            }
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        goto done;
    } else if(code == IOCTL_CK_TFA_I2C){
        /* Safe QUPv3 SE6 I2C (0x00A98000) + 3x NXP TFA9874 (0x34, 0x35, 0x36) helper */
        if(inBytes >= sizeof(CK_TFA_REQ) && outBytes >= sizeof(CK_TFA_RSP)){
            CK_TFA_REQ *req = NULL;
            CK_TFA_RSP *rsp = NULL;
            status = WdfRequestRetrieveInputBuffer(request, sizeof(*req), (PVOID*)&req, NULL);
            if(NT_SUCCESS(status)) status = WdfRequestRetrieveOutputBuffer(request, sizeof(*rsp), (PVOID*)&rsp, NULL);
            if(NT_SUCCESS(status) && req && rsp){
                CK_TFA_REQ rcopy = *req;
                RtlZeroMemory(rsp, sizeof(*rsp));
                PVOID pGccS6   = MapPhys(0x00118000ULL, 0x1000, PAGE_READWRITE | PAGE_NOCACHE);
                PVOID pGccCbcr = MapPhys(0x00123000ULL, 0x1000, PAGE_READWRITE | PAGE_NOCACHE);
                PVOID pGccVote = MapPhys(0x00152000ULL, 0x1000, PAGE_READWRITE | PAGE_NOCACHE);
                PVOID pG48     = MapPhys(0x0F130000ULL, 0x1000, PAGE_READWRITE | PAGE_NOCACHE);
                PVOID pG49     = MapPhys(0x0F131000ULL, 0x1000, PAGE_READWRITE | PAGE_NOCACHE);
                PVOID pG50     = MapPhys(0x0F132000ULL, 0x1000, PAGE_READWRITE | PAGE_NOCACHE);
                PVOID pG56     = MapPhys(0x0F138000ULL, 0x1000, PAGE_READWRITE | PAGE_NOCACHE);
                PVOID pG173    = MapPhys(0x0F1AD000ULL, 0x1000, PAGE_READWRITE | PAGE_NOCACHE);
                if(pGccS6 && pGccCbcr && pGccVote && pG48 && pG49 && pG50 && pG56 && pG173){
                    volatile ULONG *cbS6   = (volatile ULONG*)((UCHAR*)pGccS6 + 0x754);
                    volatile ULONG *cbMAhb = (volatile ULONG*)((UCHAR*)pGccCbcr + 0x27C);
                    volatile ULONG *cbSAhb = (volatile ULONG*)((UCHAR*)pGccCbcr + 0x280);
                    volatile ULONG *cbCore = (volatile ULONG*)((UCHAR*)pGccCbcr + 0x284);
                    volatile ULONG *vote   = (volatile ULONG*)((UCHAR*)pGccVote + 0x008);
                    volatile ULONG *g48    = (volatile ULONG*)pG48;
                    volatile ULONG *g49    = (volatile ULONG*)pG49;
                    volatile ULONG *g50    = (volatile ULONG*)pG50;
                    volatile ULONG *g56    = (volatile ULONG*)pG56;
                    volatile ULONG *g173   = (volatile ULONG*)pG173;
                    if(rcopy.Op >= 1u){
                        /* Vote WRAP1 core(19), m_ahb(20), s_ahb(21), s6(28) ON */
                        ULONG v = READ_REGISTER_ULONG(vote);
                        WRITE_REGISTER_ULONG(vote, v | (1u<<19) | (1u<<20) | (1u<<21) | (1u<<28));
                        for(int t=0; t<200; t++){
                            if(!((READ_REGISTER_ULONG(cbS6) | READ_REGISTER_ULONG(cbMAhb) |
                                  READ_REGISTER_ULONG(cbCore)) & 0x80000000u))
                                break;
                            KeStallExecutionProcessor(10);
                        }
                    }
                    rsp->Cbcr[0] = READ_REGISTER_ULONG(cbS6);
                    rsp->Cbcr[1] = READ_REGISTER_ULONG(cbMAhb);
                    rsp->Cbcr[2] = READ_REGISTER_ULONG(cbSAhb);
                    rsp->Cbcr[3] = READ_REGISTER_ULONG(cbCore);
                    rsp->Gpio[0] = READ_REGISTER_ULONG(g48);
                    rsp->Gpio[1] = READ_REGISTER_ULONG(g49);
                    rsp->Gpio[2] = READ_REGISTER_ULONG(g50);
                    rsp->Gpio[3] = READ_REGISTER_ULONG(g56);
                    rsp->Gpio[4] = READ_REGISTER_ULONG(g173);
                    if(rcopy.Op >= 1u){
                        /* cbSAhb (0x123280) is HWCG-controlled (bit 1=HW_CTL), so CLK_OFF=1 when idle is normal */
                        ULONG clkOff = (rsp->Cbcr[0] | rsp->Cbcr[1] | rsp->Cbcr[3]) & 0x80000000u;
                        if(clkOff){
                            rsp->Status = 10u; /* Clocks still off; do not touch QUP MMIO */
                        } else {
                            if(rcopy.Op == 1u){
                                /* Configure GPIO 48 (SDA=func 2, PU) & GPIO 49 (SCL=func 1, PU) */
                                WRITE_REGISTER_ULONG(g48, 0x0Bu);
                                WRITE_REGISTER_ULONG(g49, 0x07u);
                                /* Reset pulse (HIGH 5ms -> LOW 5ms) on TFA9874 reset GPIOs 50, 56, 173 */
                                WRITE_REGISTER_ULONG(g50 + 1, 2u);  WRITE_REGISTER_ULONG(g50, 0x200u);
                                WRITE_REGISTER_ULONG(g56 + 1, 2u);  WRITE_REGISTER_ULONG(g56, 0x200u);
                                WRITE_REGISTER_ULONG(g173 + 1, 2u); WRITE_REGISTER_ULONG(g173, 0x200u);
                                KeStallExecutionProcessor(5000);
                                WRITE_REGISTER_ULONG(g50 + 1, 0u);
                                WRITE_REGISTER_ULONG(g56 + 1, 0u);
                                WRITE_REGISTER_ULONG(g173 + 1, 0u);
                                /* Also configure Secondary TDM1 / i2s1 GPIOs 121..124 (func 1, 8mA) */
                                for(ULONG g = 121; g <= 124; g++){
                                    PVOID pg = MapPhys(0x0F100000ULL + (ULONGLONG)g * 0x1000ULL, 0x1000, PAGE_READWRITE | PAGE_NOCACHE);
                                    if(pg){
                                        WRITE_REGISTER_ULONG((volatile ULONG*)pg, 0xC4u);
                                        MmUnmapIoSpace(pg, 0x1000);
                                    }
                                }
                                KeStallExecutionProcessor(5000);
                            }
                            PVOID pQup = MapPhys(0x00A98000ULL, 0x4000, PAGE_READWRITE | PAGE_NOCACHE);
                            if(pQup){
                                volatile ULONG *q = (volatile ULONG*)pQup;
                                rsp->GeniRev = READ_REGISTER_ULONG(q + (0x20/4));
                                rsp->GeniIos = READ_REGISTER_ULONG(q + (0x908/4));
                                if(rcopy.Op == 1u){
                                    /* Initialize GENI SE6 I2C packing & 400kHz SCL counters (same proven values as g104) */
                                    WRITE_REGISTER_ULONG(q + (0x48/4),  0x71u);
                                    WRITE_REGISTER_ULONG(q + (0x68/4),  0x303u);
                                    WRITE_REGISTER_ULONG(q + (0x6C/4),  0x303u);
                                    WRITE_REGISTER_ULONG(q + (0x254/4), 0u);
                                    WRITE_REGISTER_ULONG(q + (0x260/4), 0x7F8FEu);
                                    WRITE_REGISTER_ULONG(q + (0x264/4), 0xFFEFEu);
                                    WRITE_REGISTER_ULONG(q + (0x284/4), 0x7F8FEu);
                                    WRITE_REGISTER_ULONG(q + (0x288/4), 0xFFEFEu);
                                    WRITE_REGISTER_ULONG(q + (0x278/4), 0x00A02C1Au);
                                    WRITE_REGISTER_ULONG(q + (0x614/4), 0x33C0007Eu);
                                    WRITE_REGISTER_ULONG(q + (0x618/4), 0xFFFFFFFFu);
                                    rsp->GeniIos = READ_REGISTER_ULONG(q + (0x908/4));
                                }
                                if(rcopy.Op == 2u || rcopy.Op == 3u){
                                    /* Ensure 400kHz SCL counters & clear stale IRQs */
                                    ULONG st = READ_REGISTER_ULONG(q + (0x610/4));
                                    if(st) WRITE_REGISTER_ULONG(q + (0x618/4), st);
                                    if(rcopy.Op == 2u){
                                        /* 1-byte reg write (stretch) + 2-byte big-endian read */
                                        WRITE_REGISTER_ULONG(q + (0x26C/4), 1u);
                                        WRITE_REGISTER_ULONG(q + (0x600/4), (1u << 27) | ((rcopy.Addr7 & 0x7Fu) << 9) | 4u);
                                        WRITE_REGISTER_ULONG(q + (0x80C/4), 1u);
                                        int ok1 = 0, fed = 0;
                                        for(int j=0; j<500; j++){
                                            ULONG m = READ_REGISTER_ULONG(q + (0x610/4));
                                            if(m & 0x3C0Cu){ rsp->Status = 21u; rsp->Data = m; WRITE_REGISTER_ULONG(q + (0x618/4), m); break; }
                                            if(!fed && (m & 0x40000000u)){ WRITE_REGISTER_ULONG(q + (0x700/4), rcopy.Reg & 0xFFu); WRITE_REGISTER_ULONG(q + (0x80C/4), 0u); fed = 1; }
                                            if(m & 1u){ WRITE_REGISTER_ULONG(q + (0x618/4), m); ok1 = 1; break; }
                                            if(m) WRITE_REGISTER_ULONG(q + (0x618/4), m);
                                            KeStallExecutionProcessor(20);
                                        }
                                        if(ok1){
                                            WRITE_REGISTER_ULONG(q + (0x270/4), 2u);
                                            WRITE_REGISTER_ULONG(q + (0x600/4), (2u << 27) | ((rcopy.Addr7 & 0x7Fu) << 9));
                                            ULONG word = 0; int gotRx = 0, ok2 = 0;
                                            for(int j=0; j<500; j++){
                                                ULONG m = READ_REGISTER_ULONG(q + (0x610/4));
                                                ULONG rxs = READ_REGISTER_ULONG(q + (0x804/4));
                                                if(m & 0x3C0Cu){ rsp->Status = 22u; rsp->Data = m; WRITE_REGISTER_ULONG(q + (0x618/4), m); break; }
                                                if(!gotRx && (rxs & 0x1FFFFFFu)){ word = READ_REGISTER_ULONG(q + (0x780/4)); gotRx = 1; }
                                                if(m & 1u){ WRITE_REGISTER_ULONG(q + (0x618/4), m); ok2 = 1; break; }
                                                if(m) WRITE_REGISTER_ULONG(q + (0x618/4), m);
                                                KeStallExecutionProcessor(20);
                                            }
                                            if(ok2 && gotRx){
                                                /* TFA9874 is big-endian 16-bit: byte0=MSB, byte1=LSB */
                                                rsp->Data = ((word & 0xFFu) << 8) | ((word >> 8) & 0xFFu);
                                                rsp->Status = 0u;
                                            } else if(!rsp->Status){
                                                rsp->Status = 23u;
                                            }
                                        } else if(!rsp->Status){
                                            rsp->Status = 20u;
                                        }
                                    } else {
                                        /* 3-byte write: [reg, val_hi, val_lo] */
                                        ULONG txw = (rcopy.Reg & 0xFFu) | (((rcopy.Val >> 8) & 0xFFu) << 8) | ((rcopy.Val & 0xFFu) << 16);
                                        WRITE_REGISTER_ULONG(q + (0x26C/4), 3u);
                                        WRITE_REGISTER_ULONG(q + (0x600/4), (1u << 27) | ((rcopy.Addr7 & 0x7Fu) << 9));
                                        WRITE_REGISTER_ULONG(q + (0x80C/4), 1u);
                                        int okw = 0, fed = 0;
                                        for(int j=0; j<500; j++){
                                            ULONG m = READ_REGISTER_ULONG(q + (0x610/4));
                                            if(m & 0x3C0Cu){ rsp->Status = 31u; rsp->Data = m; WRITE_REGISTER_ULONG(q + (0x618/4), m); break; }
                                            if(!fed && (m & 0x40000000u)){ WRITE_REGISTER_ULONG(q + (0x700/4), txw); WRITE_REGISTER_ULONG(q + (0x80C/4), 0u); fed = 1; }
                                            if(m & 1u){ WRITE_REGISTER_ULONG(q + (0x618/4), m); okw = 1; break; }
                                            if(m) WRITE_REGISTER_ULONG(q + (0x618/4), m);
                                            KeStallExecutionProcessor(20);
                                        }
                                        if(okw) rsp->Status = 0u;
                                        else if(!rsp->Status) rsp->Status = 30u;
                                    }
                                }
                                MmUnmapIoSpace(pQup, 0x4000);
                            } else {
                                rsp->Status = 11u;
                            }
                        }
                    }
                } else {
                    rsp->Status = 1u;
                }
                if(pG173)    MmUnmapIoSpace(pG173, 0x1000);
                if(pG56)     MmUnmapIoSpace(pG56, 0x1000);
                if(pG50)     MmUnmapIoSpace(pG50, 0x1000);
                if(pG49)     MmUnmapIoSpace(pG49, 0x1000);
                if(pG48)     MmUnmapIoSpace(pG48, 0x1000);
                if(pGccVote) MmUnmapIoSpace(pGccVote, 0x1000);
                if(pGccCbcr) MmUnmapIoSpace(pGccCbcr, 0x1000);
                if(pGccS6)   MmUnmapIoSpace(pGccS6, 0x1000);
                info = sizeof(*rsp);
            }
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        goto done;
    } else if(code == IOCTL_CK_SMMU_ADSP){
        /* Safe G735-style apps_smmu (0x15000000) inspector & identity-bypass programmer for ADSP SIDs */
        if(inBytes >= sizeof(CK_SMMU_REQ) && outBytes >= sizeof(CK_SMMU_RSP)){
            CK_SMMU_REQ *req = NULL;
            CK_SMMU_RSP *rsp = NULL;
            status = WdfRequestRetrieveInputBuffer(request, sizeof(*req), (PVOID*)&req, NULL);
            if(NT_SUCCESS(status)) status = WdfRequestRetrieveOutputBuffer(request, sizeof(*rsp), (PVOID*)&rsp, NULL);
            if(NT_SUCCESS(status) && req && rsp){
                CK_SMMU_REQ rc = *req;
                RtlZeroMemory(rsp, sizeof(*rsp));
                PVOID pSmmu = MapPhys(0x15000000ULL, 0x100000, PAGE_READWRITE | PAGE_NOCACHE);
                if(!pSmmu){
                    rsp->Status = 1u;
                } else {
                    volatile ULONG *base = (volatile ULONG*)pSmmu;
                    rsp->Cr0     = READ_REGISTER_ULONG(base + (0x00/4));
                    rsp->Id0     = READ_REGISTER_ULONG(base + (0x20/4));
                    rsp->Id1     = READ_REGISTER_ULONG(base + (0x24/4));
                    rsp->Gfsr    = READ_REGISTER_ULONG(base + (0x48/4));
                    rsp->Gfsynr0 = READ_REGISTER_ULONG(base + (0x50/4));
                    rsp->Gfsynr1 = READ_REGISTER_ULONG(base + (0x54/4));
                    uint32_t numSmr = rsp->Id0 & 0xFFu;
                    uint32_t numCb  = rsp->Id1 & 0xFFu;
                    if(numSmr > 128u) numSmr = 128u;
                    if(numCb > 128u)  numCb  = 128u;
                    uint8_t usedCb[128];
                    RtlZeroMemory(usedCb, sizeof(usedCb));
                    uint32_t freeSlot = 0xFFFFFFFFu;
                    int overlap = 0;
                    for(uint32_t i=0; i<numSmr; i++){
                        ULONG smr  = READ_REGISTER_ULONG(base + ((0x800 + 4*i)/4));
                        ULONG s2cr = READ_REGISTER_ULONG(base + ((0xC00 + 4*i)/4));
                        if(smr & 0x80000000u){
                            if(rsp->ActiveCount < 24u){
                                rsp->ActiveSmr[rsp->ActiveCount]  = smr;
                                rsp->ActiveS2cr[rsp->ActiveCount] = s2cr;
                            }
                            rsp->ActiveCount++;
                            if(((s2cr >> 16) & 3u) == 0u && (s2cr & 0xFFu) < 128u) usedCb[s2cr & 0xFFu] = 1u;
                            uint32_t m = ((smr >> 16) & 0x7FFFu) | (rc.Mask & 0x7FFFu);
                            if((((smr ^ rc.Sid) & ~m) & 0x7FFFu) == 0u){
                                overlap = 1;
                                rsp->Slot = i;
                                rsp->ReadbackSmr = smr;
                                rsp->ReadbackS2cr = s2cr;
                            }
                        } else if(freeSlot == 0xFFFFFFFFu){
                            freeSlot = i;
                        }
                    }
                    if(rc.Op == 1u || rc.Op == 2u){
                        if(rsp->Id0 != 0x4C017E69u || rsp->Id1 != 0x60000046u){
                            rsp->Status = 2u; /* Unexpected SMMU geometry */
                        } else if(overlap){
                            rsp->Status = 3u; /* Already mapped / overlapping */
                        } else if(freeSlot == 0xFFFFFFFFu){
                            rsp->Status = 4u; /* No free SMR slot */
                        } else {
                            /* Find inactive context bank per G735 policy (CbBase = +0x80000, stride 0x1000) */
                            uint32_t freeCb = 0xFFFFFFFFu;
                            uint32_t maxSafeCb = (numCb < 14u) ? numCb : 14u; for(uint32_t cb=0; cb<maxSafeCb; cb++){
                                if(usedCb[cb]) continue;
                                volatile ULONG *cbar  = base + ((0x1000 + 4*cb)/4);
                                volatile ULONG *cba2r = base + ((0x1800 + 4*cb)/4);
                                volatile ULONG *cbr   = base + ((0x80000 + 0x1000*cb)/4);
                                ULONG sctlr = READ_REGISTER_ULONG(cbr + (0x00/4));
                                ULONG actlr = READ_REGISTER_ULONG(cbr + (0x04/4));
                                ULONG fsr   = READ_REGISTER_ULONG(cbr + (0x58/4));
                                if(!(sctlr & 0x61u) && actlr == 3u && !fsr && !READ_REGISTER_ULONG(cbar) && !READ_REGISTER_ULONG(cba2r)){
                                    freeCb = cb;
                                    break;
                                }
                            }
                            if(freeCb == 0xFFFFFFFFu){
                                rsp->Status = 5u; /* No inactive CB */
                            } else {
                                volatile ULONG *cbar  = base + ((0x1000 + 4*freeCb)/4);
                                volatile ULONG *cba2r = base + ((0x1800 + 4*freeCb)/4);
                                volatile ULONG *cbr   = base + ((0x80000 + 0x1000*freeCb)/4);
                                volatile ULONG *smrp  = base + ((0x800 + 4*freeSlot)/4);
                                volatile ULONG *s2crp = base + ((0xC00 + 4*freeSlot)/4);
                                if(rc.Op == 2u && Owner && Owner->FrpcBuf){
                                    /* Stage-1 39-bit 4KB page table mapping IOVA 0x10000000 (64KB) -> Owner->FrpcPhys */
                                    if(!Owner->SmmuPt){
                                        PHYSICAL_ADDRESS lo, hi, bnd;
                                        lo.QuadPart = 0; hi.QuadPart = 0xFFFFFFFFLL; bnd.QuadPart = 0;
                                        Owner->SmmuPt = (uint8_t*)MmAllocateContiguousMemorySpecifyCache(12288, lo, hi, bnd, MmNonCached);
                                        if(Owner->SmmuPt){
                                            RtlZeroMemory(Owner->SmmuPt, 12288);
                                            Owner->SmmuPtPhys = (uint64_t)MmGetPhysicalAddress(Owner->SmmuPt).QuadPart;
                                            uint64_t l2p = Owner->SmmuPtPhys + 4096ULL;
                                            uint64_t l3p = Owner->SmmuPtPhys + 8192ULL;
                                            uint64_t *l1 = (uint64_t*)(Owner->SmmuPt + 0);
                                            uint64_t *l2 = (uint64_t*)(Owner->SmmuPt + 4096);
                                            uint64_t *l3 = (uint64_t*)(Owner->SmmuPt + 8192);
                                            l1[0]   = l2p | 3ULL; /* VA 0x00000000..0x3FFFFFFF */
                                            l2[128] = l3p | 3ULL; /* VA 0x10000000..0x101FFFFF */
                                            for(uint32_t pg = 0; pg < 16u; pg++){
                                                /* AF=1(0x400), SH=IS(0x300), AP=01 RW any EL(0x40), AttrIndx=0(NC), Page=3 -> 0x743 */
                                                l3[pg] = (Owner->FrpcPhys + (uint64_t)pg * 4096ULL) | 0x743ULL; /* v24: AP=01 (RW at any EL): SMMU DMA is unprivileged; 0x703 (EL1-only) permission-faulted the ADSP's first PCM read */
                                            }
                                            KeMemoryBarrier();
                                        }
                                    }
                                    if(!Owner->SmmuPt){
                                        rsp->Status = 6u;
                                    } else {
                                        WRITE_REGISTER_ULONG(cbar,  0x0001F300u);
                                        WRITE_REGISTER_ULONG(cba2r, 1u);
                                        WRITE_REGISTER_ULONG(cbr + (0x10/4), 0x00000002u); /* TCR2: PASize=2 (40-bit), SEP=0 */
                                        WRITE_REGISTER_ULONG(cbr + (0x20/4), (ULONG)(Owner->SmmuPtPhys & 0xFFFFFFFFULL));
                                        WRITE_REGISTER_ULONG(cbr + (0x24/4), (ULONG)(Owner->SmmuPtPhys >> 32));
                                        WRITE_REGISTER_ULONG(cbr + (0x28/4), 0u);
                                        WRITE_REGISTER_ULONG(cbr + (0x2C/4), 0u);
                                        WRITE_REGISTER_ULONG(cbr + (0x30/4), 0x00803019u); /* TCR: T0SZ=25(39b), TG0=4K, SH0=IS, NC, EPD1=1 */
                                        WRITE_REGISTER_ULONG(cbr + (0x34/4), 0u);
                                        WRITE_REGISTER_ULONG(cbr + (0x38/4), 0x00000044u); /* MAIR0: Attr0=Normal NC */
                                        WRITE_REGISTER_ULONG(cbr + (0x3C/4), 0u);
                                        WRITE_REGISTER_ULONG(cbr + (0x618/4), 0u);         /* TLBIALL */
                                        KeMemoryBarrier();
                                        WRITE_REGISTER_ULONG(cbr + (0x00/4), 0xE1u);       /* SCTLR: M=1 Stage-1 enabled! */
                                    }
                                } else {
                                    /* Exact G735 identity-bypass sequence (M=0, VA64, Stage-1/Stage-2 bypass) */
                                    WRITE_REGISTER_ULONG(cbar,  0x0001F300u);
                                    WRITE_REGISTER_ULONG(cba2r, 1u);
                                    WRITE_REGISTER_ULONG(cbr + (0x10/4), 0x60u);       /* TCR2 */
                                    WRITE_REGISTER_ULONG(cbr + (0x20/4), 0u);          /* TTBR0_LO */
                                    WRITE_REGISTER_ULONG(cbr + (0x24/4), 0u);          /* TTBR0_HI */
                                    WRITE_REGISTER_ULONG(cbr + (0x28/4), 0u);          /* TTBR1_LO */
                                    WRITE_REGISTER_ULONG(cbr + (0x2C/4), 0u);          /* TTBR1_HI */
                                    WRITE_REGISTER_ULONG(cbr + (0x30/4), 0x80A000A0u); /* TCR */
                                    WRITE_REGISTER_ULONG(cbr + (0x34/4), 0u);          /* CONTEXTIDR */
                                    WRITE_REGISTER_ULONG(cbr + (0x38/4), 0u);          /* MAIR0 */
                                    WRITE_REGISTER_ULONG(cbr + (0x3C/4), 0u);          /* MAIR1 */
                                    WRITE_REGISTER_ULONG(cbr + (0x00/4), 0xE0u);       /* SCTLR: M=0 bypass */
                                }
                                KeMemoryBarrier();
                                WRITE_REGISTER_ULONG(s2crp, freeCb);
                                KeMemoryBarrier();
                                ULONG smrVal = 0x80000000u | ((rc.Mask & 0x7FFFu) << 16) | (rc.Sid & 0x7FFFu);
                                WRITE_REGISTER_ULONG(smrp, smrVal);
                                KeMemoryBarrier();
                                rsp->Slot          = freeSlot;
                                rsp->Cb            = freeCb;
                                rsp->ReadbackSmr   = READ_REGISTER_ULONG(smrp);
                                rsp->ReadbackS2cr  = READ_REGISTER_ULONG(s2crp);
                                rsp->ReadbackCbar  = READ_REGISTER_ULONG(cbar);
                                rsp->ReadbackSctlr = READ_REGISTER_ULONG(cbr + (0x00/4));
                                rsp->Gfsr          = READ_REGISTER_ULONG(base + (0x48/4));
                                rsp->Status        = (rsp->ReadbackSmr == smrVal && rsp->ReadbackS2cr == freeCb) ? 0u : 6u;
                            }
                        }
                    }
                    MmUnmapIoSpace(pSmmu, 0x100000);
                }
                info = sizeof(*rsp);
            }
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        goto done;
    } else if(code == IOCTL_CK_HYP_ASSIGN){
        /* Qualcomm SCM MEM_PROT_ASSIGN (0x42000C16) to share Owner->FrpcBuf with ADSP/LPASS/SSC */
        if(Owner && Owner->FrpcBuf && inBytes >= sizeof(CK_HYP_REQ) && outBytes >= sizeof(CK_HYP_RSP)){
            CK_HYP_REQ *req = NULL;
            CK_HYP_RSP *rsp = NULL;
            status = WdfRequestRetrieveInputBuffer(request, sizeof(*req), (PVOID*)&req, NULL);
            if(NT_SUCCESS(status)) status = WdfRequestRetrieveOutputBuffer(request, sizeof(*rsp), (PVOID*)&rsp, NULL);
            if(NT_SUCCESS(status) && req && rsp){
                CK_HYP_REQ rq = *req;
                RtlZeroMemory(rsp, sizeof(*rsp));
                rsp->BufPhys = Owner->FrpcPhys;
                rsp->BufSize = Owner->FrpcBufSize;
                PHYSICAL_ADDRESS lo, hi, bnd;
                lo.QuadPart = 0; hi.QuadPart = 0xFFFFFFFFLL; bnd.QuadPart = 0;
                uint8_t *db = (uint8_t*)MmAllocateContiguousMemorySpecifyCache(4096, lo, hi, bnd, MmNonCached);
                if(!db){
                    rsp->R0 = -12;
                } else {
                    RtlZeroMemory(db, 4096);
                    uint64_t dp = (uint64_t)MmGetPhysicalAddress(db).QuadPart;
                    /* +0x00: src[1] = { 3 (VMID_HLOS) } */
                    *(uint32_t*)(db + 0x00) = 3u;
                    uint8_t *probeBuf = NULL;
                    uint64_t tgtPhys = Owner->FrpcPhys;
                    uint64_t tgtSize = (uint64_t)Owner->FrpcBufSize;
                    int isProbe = (rq.DestVmid2 & 0x80000000u) ? 1 : 0;
                    rq.DestVmid2 &= 0x7FFFFFFFu;
                    if(isProbe){
                        probeBuf = (uint8_t*)MmAllocateContiguousMemorySpecifyCache(4096, lo, hi, bnd, MmNonCached);
                        if(probeBuf){ tgtPhys = (uint64_t)MmGetPhysicalAddress(probeBuf).QuadPart; tgtSize = 4096ULL; }
                    }
                    rsp->BufPhys = tgtPhys; rsp->BufSize = (uint32_t)tgtSize;
                    /* +0x40: mem_to_map = { mem_addr, mem_size } */
                    *(uint64_t*)(db + 0x40) = tgtPhys;
                    *(uint64_t*)(db + 0x48) = tgtSize;
                    /* +0x80: dest[] = struct qcom_scm_current_perm_info { u32 vmid, u32 perm, u64 ctx, u32 ctx_size, u32 pad } = 24B each */
                    uint32_t dcnt = 1u;
                    *(uint32_t*)(db + 0x80 + 0) = 3u; /* VMID_HLOS */
                    *(uint32_t*)(db + 0x80 + 4) = 7u; /* RWX */
                    if(rq.DestVmid1){
                        *(uint32_t*)(db + 0x80 + dcnt*24 + 0) = rq.DestVmid1;
                        *(uint32_t*)(db + 0x80 + dcnt*24 + 4) = 6u; /* RW */
                        dcnt++;
                    }
                    if(rq.DestVmid2){
                        *(uint32_t*)(db + 0x80 + dcnt*24 + 0) = rq.DestVmid2;
                        *(uint32_t*)(db + 0x80 + dcnt*24 + 4) = 6u; /* RW */
                        dcnt++;
                    }
                    /* +0x100: ext_args[4] = { src_sz=4, dest_phys, dest_sz, spare=0 } */
                    *(uint64_t*)(db + 0x100) = 4ULL;
                    *(uint64_t*)(db + 0x108) = dp + 0x80ULL;
                    *(uint64_t*)(db + 0x110) = (uint64_t)(dcnt * 24u);
                    *(uint64_t*)(db + 0x118) = 0ULL;
                    KeMemoryBarrier();

                    register uint64_t x0 __asm__("x0") = 0x42000C16ULL;
                    register uint64_t x1 __asm__("x1") = 0x00001117ULL;
                    register uint64_t x2 __asm__("x2") = dp + 0x40ULL;
                    register uint64_t x3 __asm__("x3") = 16ULL;
                    register uint64_t x4 __asm__("x4") = dp + 0x00ULL;
                    register uint64_t x5 __asm__("x5") = dp + 0x100ULL;
                    register uint64_t x6 __asm__("x6") = 0ULL;
                    for(uint32_t tries = 0; tries < 20; tries++){
                        __asm__ volatile("smc #0"
                            : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4), "+r"(x5), "+r"(x6)
                            :
                            : "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "memory");
                        rsp->Retries = tries;
                        if((int64_t)x0 != 1LL) break; /* 1 == QCOM_SCM_INTERRUPTED */
                        x0 = 0x42000C16ULL;
                    }
                    rsp->R0 = (int64_t)x0;
                    rsp->R1 = (int64_t)x1;
                    rsp->R2 = (int64_t)x2;
                    rsp->R3 = (int64_t)x3;
                    if(probeBuf){
                        if(rsp->R0 == 0 && rsp->R1 == 0){
                            /* Restore {3, v1} -> {3} so page is safely owned by HLOS before freeing */
                            *(uint32_t*)(db + 0x00) = 3u;
                            *(uint32_t*)(db + 0x04) = rq.DestVmid1;
                            *(uint32_t*)(db + 0x80 + 0) = 3u;
                            *(uint32_t*)(db + 0x80 + 4) = 7u;
                            *(uint64_t*)(db + 0x100) = 8ULL;
                            *(uint64_t*)(db + 0x108) = dp + 0x80ULL;
                            *(uint64_t*)(db + 0x110) = 24ULL;
                            *(uint64_t*)(db + 0x118) = 0ULL;
                            KeMemoryBarrier();
                            register uint64_t rx0 __asm__("x0") = 0x42000C16ULL;
                            register uint64_t rx1 __asm__("x1") = 0x00001117ULL;
                            register uint64_t rx2 __asm__("x2") = dp + 0x40ULL;
                            register uint64_t rx3 __asm__("x3") = 16ULL;
                            register uint64_t rx4 __asm__("x4") = dp + 0x00ULL;
                            register uint64_t rx5 __asm__("x5") = dp + 0x100ULL;
                            register uint64_t rx6 __asm__("x6") = 0ULL;
                            __asm__ volatile("smc #0" : "+r"(rx0), "+r"(rx1), "+r"(rx2), "+r"(rx3), "+r"(rx4), "+r"(rx5), "+r"(rx6) : : "x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","memory");
                        }
                        MmFreeContiguousMemorySpecifyCache(probeBuf, 4096, MmNonCached);
                    }
                    MmFreeContiguousMemorySpecifyCache(db, 4096, MmNonCached);
                }
                info = sizeof(*rsp);
            }
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        goto done;
    } else if(code != IOCTL_CK_STATUS){
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto done;
    }

    if(outBytes >= sizeof(CK_STATUS_SNAPSHOT)){
        CK_STATUS_SNAPSHOT *out = NULL;
        status = WdfRequestRetrieveOutputBuffer(request, sizeof(*out), (PVOID*)&out, NULL);
        if(NT_SUCCESS(status) && out && Owner){
            RtlZeroMemory(out, sizeof(*out));
            out->Size           = sizeof(*out);
            out->Version        = CK_ABI_VER;
            out->Magic          = CK_MAGIC;
            out->KernelBuild    = Owner->KernelBuild;
            out->Processors     = Owner->Processors;
            out->Admitted       = Owner->Admitted;
            out->AdmissionCode  = Owner->AdmissionCode;
            out->GlinkPhase     = Owner->Glink.Phase;
            out->GlinkFault     = Owner->Glink.Fault;
            out->PolicyState    = Owner->Policy.State;
            out->SafetyReason   = Owner->Policy.SafetyReason;
            out->FvProgrammed   = Owner->Policy.FvProgrammed;
            out->Paused         = Owner->Policy.Paused;
            out->EnableCount    = Owner->Policy.EnableCount;
            out->DisableCount   = Owner->Policy.DisableCount;
            out->SafetyTrips    = Owner->Policy.SafetyTrips;
            out->GaugeReadsOk   = Owner->GaugeReadsOk;
            out->GaugeReadsFail = Owner->GaugeReadsFail;
            out->UsbVoltNow     = Owner->Glink.LastBattery.UsbVoltNow;
            out->UsbCurrNow     = Owner->Glink.LastBattery.UsbCurrNow;
            out->UsbCurrMax     = Owner->Glink.LastBattery.UsbCurrMax;
            out->UsbInputLimit  = Owner->Glink.LastBattery.UsbInputLimit;
            out->UsbRejectedMask = (Owner->Glink.LastBattery.ServiceRejectedMask >> CL_USB_GET_FIRST) & 0xFu;
            out->GaugeCode  = Owner->GaugeScratch.Code;
            out->GaugeStage = Owner->GaugeScratch.Stage;
            out->PreCode    = Owner->GaugeScratch.Before.Code;
            out->PreReady   = Owner->GaugeScratch.Before.ReadyMask;
            out->PreClock   = Owner->GaugeScratch.Before.PostClockMask;
            out->PrePins    = Owner->GaugeScratch.Before.PinStableMask;
            RtlCopyMemory(out->PreClocks, Owner->GaugeScratch.Before.Before, sizeof(out->PreClocks));
            out->GaugeQueryMask = Owner->GaugeScratch.QueryMask;
            RtlCopyMemory(out->GaugeWords, Owner->GaugeScratch.Values, sizeof(out->GaugeWords));
            out->NowUs          = NowUs();
            out->TimerTicks     = Owner->TimerTicks;
            out->GlinkTxFrames  = Owner->Glink.TxFrames;
            out->GlinkRxFrames  = Owner->Glink.RxFrames;
            if(!Owner->Admitted && Owner->GaugeMap[0]){
                CK_TELEMETRY t = {0};
                ReadPhysicalGauges(Owner, &t);
                if(t.Valid) Owner->Policy.LastGood = t;
            }
            out->Telemetry      = Owner->Policy.LastGood;
            info = sizeof(*out);
        }
    } else if(code == IOCTL_CK_STATUS){
        status = STATUS_BUFFER_TOO_SMALL;
    }
done:
    WdfRequestCompleteWithInformation(request, status, info);
}

VOID CkFileCreate(WDFDEVICE device, WDFREQUEST request, WDFFILEOBJECT file){
    UNREFERENCED_PARAMETER(device);
    PUNICODE_STRING name = WdfFileObjectGetFileName(file);
    WdfRequestComplete(request, (name && name->Length) ? STATUS_OBJECT_NAME_INVALID : STATUS_SUCCESS);
}

VOID CkUnload(WDFDRIVER driver){
    UNREFERENCED_PARAMETER(driver);
    if(Device){
        WdfObjectAcquireLock(Device);
        if(Owner){ Owner->Stopped = 1u; Owner->Running = 0u; }
        WdfObjectReleaseLock(Device);
    }
    if(Timer){ WdfTimerStop(Timer, TRUE); Timer = NULL; }
    if(Owner){
        if(Owner->FrpcBuf){
            MmFreeContiguousMemorySpecifyCache(Owner->FrpcBuf, Owner->FrpcBufSize, MmNonCached);
            Owner->FrpcBuf = NULL;
        }
        UnmapAll();
        ExFreePoolWithTag(Owner, 'KCP0');
        Owner = NULL;
    }
    Device = NULL;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT object, PUNICODE_STRING path){
    WDF_DRIVER_CONFIG config;
    WDFDRIVER driver;
    PWDFDEVICE_INIT init = NULL;
    WDFDEVICE device;
    WDF_OBJECT_ATTRIBUTES attr;
    WDF_IO_QUEUE_CONFIG queue;
    WDF_FILEOBJECT_CONFIG file;
    WDF_TIMER_CONFIG timer;
    NTSTATUS status;
    DECLARE_CONST_UNICODE_STRING(sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    DECLARE_CONST_UNICODE_STRING(nt_name, L"\\Device\\OpenChargerKeeper");
    DECLARE_CONST_UNICODE_STRING(dos_name, L"\\DosDevices\\OpenChargerKeeper");

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags = WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = CkUnload;
    status = WdfDriverCreate(object, path, WDF_NO_OBJECT_ATTRIBUTES, &config, &driver);
    if(!NT_SUCCESS(status)) return status;

    Owner = (CK_OWNER*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*Owner), 'KCP0');
    if(!Owner) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(Owner, sizeof(*Owner));
    CkGlInit(&Owner->Glink);
    CkPolicyInit(&Owner->Policy);
    {
        PHYSICAL_ADDRESS lo, hi, bnd;
        lo.QuadPart  = 0x80000000LL;
        hi.QuadPart  = 0xFFFFFFFFLL;
        bnd.QuadPart = 0;
        Owner->FrpcBufSize = 65536u;
        Owner->FrpcBuf = MmAllocateContiguousMemorySpecifyCache(Owner->FrpcBufSize, lo, hi, bnd, MmNonCached);
        if(!Owner->FrpcBuf){
            lo.QuadPart = 0;
            hi.QuadPart = 0xFFFFFFFFFFFFFFFFLL;
            Owner->FrpcBuf = MmAllocateContiguousMemorySpecifyCache(Owner->FrpcBufSize, lo, hi, bnd, MmNonCached);
        }
        if(Owner->FrpcBuf){
            RtlZeroMemory(Owner->FrpcBuf, Owner->FrpcBufSize);
            Owner->FrpcPhys = (uint64_t)MmGetPhysicalAddress(Owner->FrpcBuf).QuadPart;
        } else {
            Owner->FrpcBufSize = 0;
        }
    }

    init = WdfControlDeviceInitAllocate(driver, &sddl);
    if(!init){ status = STATUS_INSUFFICIENT_RESOURCES; goto fail; }
    WdfDeviceInitSetDeviceType(init, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetIoType(init, WdfDeviceIoBuffered);
    status = WdfDeviceInitAssignName(init, &nt_name);
    if(!NT_SUCCESS(status)) goto fail;

    WDF_FILEOBJECT_CONFIG_INIT(&file, CkFileCreate, WDF_NO_EVENT_CALLBACK, WDF_NO_EVENT_CALLBACK);
    WdfDeviceInitSetFileObjectConfig(init, &file, WDF_NO_OBJECT_ATTRIBUTES);

    WDF_OBJECT_ATTRIBUTES_INIT(&attr);
    attr.SynchronizationScope = WdfSynchronizationScopeDevice;
    attr.ExecutionLevel = WdfExecutionLevelPassive;
    status = WdfDeviceCreate(&init, &attr, &device);
    if(!NT_SUCCESS(status)) goto fail;
    Device = device;

    status = WdfDeviceCreateSymbolicLink(device, &dos_name);
    if(!NT_SUCCESS(status)) goto fail;

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue, WdfIoQueueDispatchSequential);
    queue.EvtIoDeviceControl = CkControl;
    status = WdfIoQueueCreate(device, &queue, WDF_NO_OBJECT_ATTRIBUTES, NULL);
    if(!NT_SUCCESS(status)) goto fail;

    WDF_TIMER_CONFIG_INIT(&timer, CkTimer);
    WDF_OBJECT_ATTRIBUTES_INIT(&attr);
    attr.ParentObject = device;
    attr.ExecutionLevel = WdfExecutionLevelPassive;
    status = WdfTimerCreate(&timer, &attr, &Timer);
    if(!NT_SUCCESS(status)) goto fail;

    WdfControlFinishInitializing(device);
    /* Auto-start watchdog 100ms after boot */
    WdfTimerStart(Timer, WDF_REL_TIMEOUT_IN_MS(100));
    return STATUS_SUCCESS;

fail:
    if(init) WdfDeviceInitFree(init);
    CkUnload(driver);
    return status;
}
