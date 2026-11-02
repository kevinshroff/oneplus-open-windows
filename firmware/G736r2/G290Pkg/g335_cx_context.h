/* SPDX-License-Identifier: MIT -- passive inline context, no runtime pointer. */
#ifndef G335_CX_CONTEXT_H
#define G335_CX_CONTEXT_H
#include "g290_power_report.h"
#pragma pack(push,1)
typedef struct {
 G290_ACPI_HEADER Header;
 uint32_t Version,CapturedMask,ValidMask,PowerStage;
 uint64_t PowerStatus;
 uint64_t Address[4];
 uint32_t ReadMask[2];
 uint32_t Value[2][4];
} G335_CX_CONTEXT;
#pragma pack(pop)
#define G335_CX_SIGNATURE UINT32_C(0x5843474f) /* OGCX */
#define G335_CX_VERSION 1u
#endif
