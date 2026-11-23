/* SPDX-License-Identifier: MIT
 * Control-device IOCTL ABI for OpenChargerKeeper (\\.\OpenChargerKeeper).
 */
#ifndef OPEN_CK_PROTOCOL_H
#define OPEN_CK_PROTOCOL_H
#include <stdint.h>
#include "keeper_policy.h"

#define CK_MAGIC    0x4B43504Fu /* "OPCK" */
#define CK_ABI_VER  1u

#define IOCTL_CK_STATUS 0x00226000u /* METHOD_BUFFERED, FILE_READ_ACCESS */
#define IOCTL_CK_PAUSE  0x0022A004u /* METHOD_BUFFERED, FILE_WRITE_ACCESS */
#define IOCTL_CK_RESUME 0x0022A008u /* METHOD_BUFFERED, FILE_WRITE_ACCESS */

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
} CK_STATUS_SNAPSHOT;

#endif
