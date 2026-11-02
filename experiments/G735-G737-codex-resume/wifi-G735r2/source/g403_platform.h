/* SPDX-License-Identifier: MIT */
#ifndef G403_PLATFORM_H
#define G403_PLATFORM_H
#include <stdint.h>
#include <stddef.h>
#define G403_SID_TABLE_BASE UINT64_C(0x1c02000)
#define G403_SID_CFG UINT64_C(0x1c02c00)
#define G403_APIC_BYTES 748u
#define G403_IORT_BYTES 3875u
/* Exact current APIC/IORT pair only. Caller owns paired ACPI replacement,
 * rollback/error handling and publication before Windows table consumption. */
int G403BuildTables(const uint8_t*,size_t,const uint8_t*,size_t,uint8_t*,size_t,uint8_t*,size_t);
typedef struct {void*Context;int(*Read32)(void*,uint64_t,uint32_t*);int(*Write32)(void*,uint64_t,uint32_t);} G403_IO;
typedef int(*G403_GATE)(void*); /* zero means current same-boot physical gate passed */
typedef struct {
 uint32_t Attempted,Stage,Code,Uncertain,Writes,Prepared;
 uint32_t BeforeCfg,AfterCfg,SidOffset,Hash,Entry;
 uint32_t Before[256],After[256];
} G403_RESULT;
/* No SMMU/ITS writes, BME changes or publication. Gate must freshly prove
 * same-boot cold-selected/resets-cycled BS/exclusive/noPCIconsumer,
 * no publication, released-phase physical clocks/domain,
 * link, endpoint17cb1107/bus1 and BMEclear before every attempted write. */
int G403PrepareSid(const G403_IO*,G403_GATE,void*,G403_RESULT*);
#endif
