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
