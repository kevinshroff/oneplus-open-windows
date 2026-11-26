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
                   Owner->Glink.Ipc.TxHead != Owner->Glink.Ipc.TxTail) ? 10 :
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
                aout->ChanCount      = Owner->Glink.ChanCount;
                RtlCopyMemory(aout->ChanNames, Owner->Glink.ChanNames, sizeof(aout->ChanNames));
                info = sizeof(*aout);
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
