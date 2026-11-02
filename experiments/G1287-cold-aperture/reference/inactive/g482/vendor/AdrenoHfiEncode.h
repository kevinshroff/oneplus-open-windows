/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Configuration/types and two encoder declarations extracted from the pinned
 * AdrenoHfiStartup.h. No transport/startup-run API is provided by this subset. */
#ifndef G190_ADRENO_HFI_ENCODE_H
#define G190_ADRENO_HFI_ENCODE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Modern A6xx/A7xx wire profile. Legacy and A8xx table formats are excluded. */
typedef struct {uint64_t hz;uint32_t vote;} AdrenoHfiPerformanceLevel;
typedef struct {
    unsigned gpu_count,gmu_count;
    AdrenoHfiPerformanceLevel gpu[16],gmu[4];
    unsigned bandwidth_count,cnoc_count,ddr_count;
    uint32_t cnoc_wait_mask,ddr_wait_mask;
    uint32_t cnoc_addresses[6],cnoc_data[2][6];
    uint32_t ddr_addresses[8],ddr_data[16][8];
    uint32_t acd_version,acd_enable_mask,acd_stride,acd_count,acd_data[32];
    unsigned enable_ifpc;
} AdrenoHfiStartupConfig;
typedef enum {
    AdrenoHfiStageNone,AdrenoHfiStagePerformance,AdrenoHfiStageBandwidth,
    AdrenoHfiStageAcdEnable,AdrenoHfiStageAcdTable,AdrenoHfiStageIfpc,
    AdrenoHfiStageCoreStart,AdrenoHfiStageStart,AdrenoHfiStageComplete
} AdrenoHfiStartupStage;
typedef enum {
    AdrenoHfiStartupSuccess,AdrenoHfiStartupInvalid,AdrenoHfiStartupBusy,
    AdrenoHfiStartupPoisoned,AdrenoHfiStartupClockError,AdrenoHfiStartupWaitError,
    AdrenoHfiStartupTimeout,AdrenoHfiStartupPlatformFault,AdrenoHfiStartupTransportError
} AdrenoHfiStartupStatus;
AdrenoHfiStartupStatus AdrenoHfiStartupValidate(const AdrenoHfiStartupConfig *);
AdrenoHfiStartupStatus AdrenoHfiStartupEncode(const AdrenoHfiStartupConfig *,
    AdrenoHfiStartupStage,uint32_t *,uint32_t *,size_t,size_t *);
#ifdef __cplusplus
}
#endif
#endif
