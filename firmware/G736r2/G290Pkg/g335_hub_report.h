/* SPDX-License-Identifier: MIT -- inline stock-provider outcomes, no pointers. */
#ifndef G335_HUB_REPORT_H
#define G335_HUB_REPORT_H
#include "g290_power_report.h"
#pragma pack(push,1)
typedef struct {
 G290_ACPI_HEADER Header;
 uint32_t Version,Stage;
 uint64_t Status,ProtocolVersion,GetIdStatus,SetHzStatus,EnableStatus,QueryStatus,ClockId;
 uint32_t RequestedHz,ReturnedHz,Enabled,RetainedEnable;
 uint64_t FinalQueryStatus;
 uint32_t FinalEnabled,DirectAttempted,RawBefore,RawAfter;
} G335_HUB_REPORT;
#pragma pack(pop)
#define G335_HUB_SIGNATURE UINT32_C(0x5548474f) /* OGHU */
#endif
