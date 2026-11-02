/* SPDX-License-Identifier: MIT -- exact Open SM8550 read-only route policy. */
#ifndef OPEN_SMMU_HANDOFF_H
#define OPEN_SMMU_HANDOFF_H
#include <stdint.h>
#define OSH_SMRS 24u
#define OSH_BANKS 22u
#define OSH_ROLES 6u
enum osh_status {OSH_OK,OSH_ARGUMENT,OSH_PROFILE,OSH_UNSTABLE,OSH_ALIAS,OSH_ROUTE,OSH_PROTECTED_UNKNOWN,OSH_NOT_CAPTURED,OSH_COLD_FAULT_DEFAULT};
typedef struct {uint32_t Id0,Id1,Id2,Nscr0,Nsacr;uint32_t Smr[OSH_SMRS],S2cr[OSH_SMRS];}OSH_SNAPSHOT;
typedef struct {uint32_t Sid,Found,Index,Bank,Type,Mask,ReadEligible;}OSH_ROUTE_INFO;
typedef struct {
 enum osh_status Status;uint32_t Stable,ProtectedBank,ReadEligibleBankMask;
 uint32_t AliasA,AliasB,ContextReads,OwnershipGranted;
 OSH_ROUTE_INFO Route[OSH_ROLES];
}OSH_REPORT;
/* COLD_FAULT_DEFAULT is a distinct successful observation, not OSH_OK
 * inherited protected-bank classification. It grants ZERO bank eligibility
 * or ownership, and requires exact emptySMR/FAULTS2CR plus USFCFG fault mode. */
/* Pure decoder of two actual bounded snapshots. It grants no ownership and
 * requires disjoint inputs/output and does not read CB registers or assert that any GPU/GMU master is stopped.
 * Exact Open DT roles qualify only SID0(user),1(LPAC),5(GMU) for initial
 * read eligibility. SID2 is protected WHEREVER mapped; SID4 unqualified,
 * SID7 debug-usecase only. IORT outputs and donor VM lists are not authority.
 */
enum osh_status OshAnalyze(const OSH_SNAPSHOT*,const OSH_SNAPSHOT*,OSH_REPORT*);
#endif
