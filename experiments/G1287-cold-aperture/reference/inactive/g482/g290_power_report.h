/* SPDX-License-Identifier: MIT -- exact private pre-EBS report, no runtime pointer */
#ifndef G290_POWER_REPORT_H
#define G290_POWER_REPORT_H
#include <stdint.h>
#pragma pack(push,1)
typedef struct {
    uint32_t Signature,Length;uint8_t Revision,Checksum;uint8_t OemId[6];
    uint64_t OemTableId;uint32_t OemRevision,CreatorId,CreatorRevision;
} G290_ACPI_HEADER;
typedef struct {uint64_t Pa;uint32_t Before,After;} G290_GATE;
typedef struct {
    G290_ACPI_HEADER Header;
    uint32_t Version,Stage;uint64_t Status;
    uint32_t CreatedMask,IssuedMask,ReturnedMask,ObservedMask;
    uint32_t CornerBefore[2],CornerAfter[2];
    uint32_t ReadyBeforeEbs,PostEbsPersistenceProven;
    G290_GATE Gate[7];uint32_t SmmuId[3];
} G290_POWER_REPORT;
#pragma pack(pop)
#define G290_POWER_SIGNATURE UINT32_C(0x5250474f) /* bytes OGPR */
#define G290_POWER_VERSION 3u
#define G290_GPU_CORNER 256u /* exact Open RPMH_REGULATOR_LEVEL_NOM */
#define G290_POWER_STAGE_READY 8u
#define G290_GATES 7u
#endif
