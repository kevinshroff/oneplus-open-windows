/* SPDX-License-Identifier: MIT
 * Generated from G147's hash-bound original-loader writes. Page coverage only:
 * mapping a partially touched page does not permit reading its untouched bytes.
 * No zero-only segment or alignment-hole reads are added by this plan.
 */
#ifndef OPEN_MAIN_ADMISSION_PLAN_H
#define OPEN_MAIN_ADMISSION_PLAN_H
#define MAIN_BASE 0x9ea00000ULL
#define MAIN_BYTES 0x4880000ULL
#define MAIN_CPU_PAGES 15851U
typedef struct {UINT64 Base,End;} OMA_PAGE_RUN;
STATIC CONST OMA_PAGE_RUN mMainPageRuns[2]={
 {0x9ea00000ULL,0xa1050000ULL},
 {0xa109c000ULL,0xa2837000ULL},
};
#endif
