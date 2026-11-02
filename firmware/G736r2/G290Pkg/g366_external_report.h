/* SPDX-License-Identifier: MIT -- external parent outcomes, no pointers. */
#ifndef G366_EXTERNAL_REPORT_H
#define G366_EXTERNAL_REPORT_H
#include "g290_power_report.h"
#pragma pack(push,1)
typedef struct {
 G290_ACPI_HEADER Header;uint32_t Version,Stage;
 uint64_t Status,ProtocolVersion,ClockId,GetIdStatus,EnableStatus,QueryStatus;
 uint64_t VotePa,BcrPa;
 uint32_t VoteBefore,VoteAfter,BcrBefore,BcrAfter,Enabled,RetainedEnable;
} G366_EXTERNAL_REPORT;
#pragma pack(pop)
#define G366_EXTERNAL_SIGNATURE UINT32_C(0x5645474f) /* OGEV */
#endif
