/* SPDX-License-Identifier: MIT
 * Control-device IOCTL ABI for OpenChargerKeeper (\\.\OpenChargerKeeper).
 */
#ifndef OPEN_CK_PROTOCOL_H
#define OPEN_CK_PROTOCOL_H
#include <stdint.h>
#include "keeper_policy.h"
#include "ipcrtr_sensors.h"

#define CK_MAGIC    0x4B43504Fu /* "OPCK" */
#define CK_ABI_VER  1u

#define IOCTL_CK_STATUS    0x00226000u /* METHOD_BUFFERED, FILE_READ_ACCESS */
#define IOCTL_CK_PAUSE     0x0022A004u /* METHOD_BUFFERED, FILE_WRITE_ACCESS */
#define IOCTL_CK_RESUME    0x0022A008u /* METHOD_BUFFERED, FILE_WRITE_ACCESS */
#define IOCTL_CK_ACCEL     0x0022600Cu /* METHOD_BUFFERED, FILE_READ_ACCESS */
#define IOCTL_CK_QRTR_SEND 0x0022A010u /* METHOD_BUFFERED, FILE_WRITE_ACCESS */
#define IOCTL_CK_QRTR_RECV 0x00226014u /* METHOD_BUFFERED, FILE_READ_ACCESS */
#define IOCTL_CK_AUDIO     0x00226018u /* METHOD_BUFFERED, FILE_READ_ACCESS */
#define IOCTL_CK_FRPC_INFO 0x0022601Cu /* METHOD_BUFFERED, FILE_READ_ACCESS */
#define IOCTL_CK_FRPC_SEND 0x0022A020u /* METHOD_BUFFERED, FILE_WRITE_ACCESS */
#define IOCTL_CK_FRPC_READ 0x00226024u /* METHOD_BUFFERED, FILE_READ_ACCESS */
#define IOCTL_CK_GPR_SEND  0x0022A028u /* METHOD_BUFFERED, FILE_WRITE_ACCESS */
#define IOCTL_CK_GPR_RECV  0x0022602Cu /* METHOD_BUFFERED, FILE_READ_ACCESS */
#define IOCTL_CK_TFA_I2C   0x0022E030u /* METHOD_BUFFERED, FILE_READ_ACCESS|FILE_WRITE_ACCESS */
#define IOCTL_CK_SHM_WRITE  0x0022A034u /* METHOD_BUFFERED, FILE_WRITE_ACCESS */
#define IOCTL_CK_SMMU_ADSP  0x0022E038u /* METHOD_BUFFERED, FILE_READ_ACCESS|FILE_WRITE_ACCESS */
#define IOCTL_CK_HYP_ASSIGN 0x0022E03Cu /* METHOD_BUFFERED, FILE_READ_ACCESS|FILE_WRITE_ACCESS */

typedef struct {
    uint32_t DestVmid1; /* e.g. 0x16 (LPASS/ADSP) */
    uint32_t DestVmid2; /* optional, e.g. 0x05 (SSC_Q6) or 0 */
} CK_HYP_REQ;

typedef struct {
    int64_t  R0, R1, R2, R3;
    uint64_t BufPhys;
    uint32_t BufSize;
    uint32_t Retries;
} CK_HYP_RSP;

typedef struct {
    uint32_t Op;   /* 0=inspect(RO), 1=program identity bypass for (Sid, Mask) */
    uint32_t Sid;  /* e.g. 0x1001, 0x1061, 0x1003, 0x1063 */
    uint32_t Mask; /* e.g. 0x0080 or 0 */
} CK_SMMU_REQ;

typedef struct {
    uint32_t Status;   /* 0=OK */
    uint32_t Id0, Id1, Cr0, Gfsr, Gfsynr0, Gfsynr1;
    uint32_t ActiveCount;
    uint32_t Slot, Cb;
    uint32_t ReadbackSmr, ReadbackS2cr, ReadbackCbar, ReadbackSctlr;
    uint32_t ActiveSmr[24];
    uint32_t ActiveS2cr[24];
} CK_SMMU_RSP;

typedef struct {
    uint32_t Op;    /* 0=status(RO), 1=clk+gpio+init, 2=i2c_read16, 3=i2c_write16 */
    uint32_t Addr7; /* 0x34, 0x35, 0x36 */
    uint32_t Reg;   /* 8-bit register address */
    uint32_t Val;   /* 16-bit value for write */
} CK_TFA_REQ;

typedef struct {
    uint32_t Status;   /* 0=OK */
    uint32_t Data;     /* 16-bit read value or GENI_IOS/IRQ error */
    uint32_t Cbcr[4];  /* s6, wrap1_m_ahb, wrap1_s_ahb, wrap1_core */
    uint32_t Gpio[5];  /* gpio 48, 49, 50, 56, 173 CFG */
    uint32_t GeniRev;  /* GENI_FW_REVISION_RO */
    uint32_t GeniIos;  /* GENI_IOS */
} CK_TFA_RSP;

typedef struct {
    uint32_t Size;
    uint32_t Version;
    uint32_t Magic;
    uint32_t OpenAcked;
    uint32_t RemoteOpen;
    uint32_t RspCount;
    uint32_t RspLen;
    int32_t  LastRspRetval;
    uint64_t LastRspCtx;
    uint64_t BufPhys;
    uint32_t BufSize;
    uint32_t TxPending;
    uint8_t  LastRspRaw[64];
} CK_FRPC_SNAPSHOT;

typedef struct {
    uint32_t Size;
    uint32_t Version;
    uint32_t Magic;
    uint32_t OpenAcked;
    uint32_t RemoteOpen;
    uint32_t SpfQuerySent;
    uint32_t SpfRspReceived;
    uint32_t SpfRspOpcode;
    uint32_t SpfState;
    uint32_t SpfRspLen;
    uint8_t  SpfRaw[64];
    uint32_t ChanCount;
    char     ChanNames[16][24];
} CK_AUDIO_SNAPSHOT;

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
    CK_TELEMETRY Telemetry;
    /* appended (offsets above unchanged): ADSP USB input telemetry, raw units uV / uA */
    uint32_t UsbVoltNow;
    uint32_t UsbCurrNow;
    uint32_t UsbCurrMax;
    uint32_t UsbInputLimit;
    uint32_t UsbRejectedMask;   /* bit n = USB GET n rejected by the ADSP service */
    /* appended: last physical-gauge (G104) attempt */
    uint32_t GaugeCode, GaugeStage, PreCode, PreReady, PreClock, PrePins;
    uint32_t PreClocks[2][8];   /* QUP SE clock vote/CBCR snapshot before the transfer */
    uint32_t GaugeQueryMask;
    uint32_t GaugeWords[2][10]; /* raw words per gauge: type, fw, hw, temp, mV, flags, rem, full, curr, soc */
} CK_STATUS_SNAPSHOT;

#endif
